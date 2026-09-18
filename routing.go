package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// RoutingTable 是从 Xray config 派生出的全部分流规则，整体原子替换。
//
// 字段语义与 lib/caddy.sh 路由记录（panel/reality/http/conflict）一一对应：
// 后者是 bash 解析三个语言后端输出的中间协议，这里直接在 Go 里得到同样的结构。
type RoutingTable struct {
	// PanelSNI 是 SECRET_KEY 派生的 SNI。命中它的 TLS 连接转给 node API。
	PanelSNI string
	// Reality 按端口升序，每个端口带一组去重排序后的 SNI。
	Reality []RealityRoute
	// HTTP 是明文 HTTP 的路径路由，按路径长度倒序，长的优先匹配。
	HTTP []HTTPRoute
	// Conflicts 记录同一路径被多个端口认领的情况，这些路径不生成路由。
	Conflicts []Conflict
}

type RealityRoute struct {
	Port int
	SNIs []string
}

type HTTPRoute struct {
	Path    string
	Port    int
	Network string
}

type Conflict struct {
	Path string
	Tags []string
}

// 可被按路径分流的网络类型，以及各类型下承载路径的配置字段名。
var httpNetworkSettings = map[string]string{
	"ws":          "wsSettings",
	"xhttp":       "xhttpSettings",
	"httpupgrade": "httpupgradeSettings",
}

type inboundDoc struct {
	Inbounds []inboundEntry `json:"inbounds"`
}

type inboundEntry struct {
	Tag string `json:"tag"`
	// Port 用 any 而不是 json.Number：json.Number 的底层是 string，encoding/json
	// 会把 JSON 字符串里的合法数字也塞进去，于是 "port": "20002" 会被当成合法
	// 端口。jq 后端的 `type == "number"`、Node 后端的 Number.isInteger 都要求
	// 真正的数字类型，这里必须一致。
	Port           any             `json:"port"`
	StreamSettings *streamSettings `json:"streamSettings"`
}

type streamSettings struct {
	Security            string           `json:"security"`
	Network             string           `json:"network"`
	RealitySettings     *realitySettings `json:"realitySettings"`
	WsSettings          *pathSettings    `json:"wsSettings"`
	XhttpSettings       *pathSettings    `json:"xhttpSettings"`
	HttpupgradeSettings *pathSettings    `json:"httpupgradeSettings"`
}

type realitySettings struct {
	ServerNames []string `json:"serverNames"`
}

type pathSettings struct {
	Path string `json:"path"`
}

// buildRoutingTable 把 /internal/get-config 的原始响应解析成分流路由表。
//
// 容错原则与原先的 jq/Node/Python 三后端一致：任何字段缺失、类型不符或取值
// 越界都只是让该条 inbound 不参与分流，而不是让整份配置解析失败——坏掉一条
// inbound 不该把其它正常路由一起拖下水。
func buildRoutingTable(raw []byte, panelSNI string) (RoutingTable, error) {
	var doc inboundDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return RoutingTable{}, fmt.Errorf("parse config: %w", err)
	}

	table := RoutingTable{PanelSNI: panelSNI}
	realityByPort := map[int]map[string]struct{}{}
	type candidate struct {
		path    string
		port    int
		network string
		tag     string
	}
	var candidates []candidate

	for _, entry := range doc.Inbounds {
		stream := entry.StreamSettings
		if stream == nil {
			continue
		}
		port := parsePort(entry.Port)

		if stream.Security == "reality" {
			if port == 0 || stream.RealitySettings == nil {
				continue
			}
			names := realityByPort[port]
			if names == nil {
				names = map[string]struct{}{}
				realityByPort[port] = names
			}
			for _, name := range stream.RealitySettings.ServerNames {
				if name != "" {
					names[name] = struct{}{}
				}
			}
			continue
		}

		settingsField, ok := httpNetworkSettings[stream.Network]
		if !ok || port == 0 {
			continue
		}
		path := normalizePath(pathFromStream(stream, settingsField))
		if path == "" {
			continue
		}
		tag := entry.Tag
		if tag == "" {
			tag = fmt.Sprintf("port:%d", port)
		}
		candidates = append(candidates, candidate{path: path, port: port, network: stream.Network, tag: tag})
	}

	for port, names := range realityByPort {
		if len(names) == 0 {
			continue
		}
		snis := make([]string, 0, len(names))
		for name := range names {
			snis = append(snis, name)
		}
		sort.Strings(snis)
		table.Reality = append(table.Reality, RealityRoute{Port: port, SNIs: snis})
	}
	sort.Slice(table.Reality, func(i, j int) bool { return table.Reality[i].Port < table.Reality[j].Port })

	// 同一路径只能属于一个端口，否则无法确定转发目标：只报冲突，不生成路由。
	byPath := map[string][]candidate{}
	var pathOrder []string
	for _, c := range candidates {
		if _, seen := byPath[c.path]; !seen {
			pathOrder = append(pathOrder, c.path)
		}
		byPath[c.path] = append(byPath[c.path], c)
	}
	sort.Strings(pathOrder)

	for _, path := range pathOrder {
		entries := byPath[path]
		ports := map[int]struct{}{}
		for _, e := range entries {
			ports[e.port] = struct{}{}
		}
		if len(ports) == 1 {
			table.HTTP = append(table.HTTP, HTTPRoute{
				Path:    path,
				Port:    entries[0].port,
				Network: entries[0].network,
			})
			continue
		}
		tags := make([]string, 0, len(entries))
		for _, e := range entries {
			tags = append(tags, fmt.Sprintf("%s(port:%d)", e.tag, e.port))
		}
		table.Conflicts = append(table.Conflicts, Conflict{Path: path, Tags: tags})
	}

	// 长路径优先，保证 /ws/foo 先于 /ws 命中。
	sort.Slice(table.HTTP, func(i, j int) bool {
		if len(table.HTTP[i].Path) != len(table.HTTP[j].Path) {
			return len(table.HTTP[i].Path) > len(table.HTTP[j].Path)
		}
		return table.HTTP[i].Path < table.HTTP[j].Path
	})

	return table, nil
}

func pathFromStream(stream *streamSettings, field string) string {
	switch field {
	case "wsSettings":
		if stream.WsSettings != nil {
			return stream.WsSettings.Path
		}
	case "xhttpSettings":
		if stream.XhttpSettings != nil {
			return stream.XhttpSettings.Path
		}
	case "httpupgradeSettings":
		if stream.HttpupgradeSettings != nil {
			return stream.HttpupgradeSettings.Path
		}
	}
	return ""
}

// parsePort 只接受 JSON 数字且落在合法端口区间，与 jq 后端的 valid_port
// （type == "number" and . > 0 and . < 65536）以及 Node 后端的 Number.isInteger
// 一致：字符串、小数、布尔都返回 0，表示这条 inbound 不参与分流。
func parsePort(value any) int {
	f, ok := value.(float64)
	if !ok {
		return 0
	}
	if f < 1 || f > 65535 || f != float64(int(f)) {
		return 0
	}
	return int(f)
}

// normalizePath 去掉 query 与 fragment，并保证以 / 开头。
func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if idx := strings.IndexAny(path, "?#"); idx >= 0 {
		path = path[:idx]
	}
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

// MatchReality 返回命中该 SNI 的 REALITY 端口，未命中返回 false。
func (t *RoutingTable) MatchReality(sni string) (int, bool) {
	for _, route := range t.Reality {
		for _, name := range route.SNIs {
			if name == sni {
				return route.Port, true
			}
		}
	}
	return 0, false
}

// MatchHTTP 返回命中最长前缀的 HTTP 路径路由。路径按完整前缀段比较，避免
// /ws 误配到 /wsfoo 这类只共享字符前缀的请求。
func (t *RoutingTable) MatchHTTP(path string) (HTTPRoute, bool) {
	for _, route := range t.HTTP {
		if pathMatchesPrefix(path, route.Path) {
			return route, true
		}
	}
	return HTTPRoute{}, false
}

func pathMatchesPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if len(path) == len(prefix) {
		return true
	}
	// prefix 以 / 结尾时（如 /foo/）允许直接续接；否则必须停在路径段边界上。
	if strings.HasSuffix(prefix, "/") {
		return true
	}
	return path[len(prefix)] == '/'
}
