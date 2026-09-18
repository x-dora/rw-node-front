package main

import (
	"reflect"
	"testing"
)

// 这份 fixture 覆盖真实 Panel 下发配置里的各种形态：多个 REALITY 端口、
// 三种可分流网络类型、带 query 的路径、没有前导斜杠的路径。
const sampleConfig = `{
  "inbounds": [
    {
      "tag": "REALITY_443",
      "port": 443,
      "streamSettings": {
        "security": "reality",
        "network": "tcp",
        "realitySettings": { "serverNames": ["b.example.com", "a.example.com", "a.example.com"] }
      }
    },
    {
      "tag": "REALITY_8443",
      "port": 8443,
      "streamSettings": {
        "security": "reality",
        "realitySettings": { "serverNames": ["c.example.com"] }
      }
    },
    {
      "tag": "VLESS_WS",
      "port": 20001,
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/ws" } }
    },
    {
      "tag": "VLESS_XHTTP",
      "port": 20002,
      "streamSettings": { "network": "xhttp", "xhttpSettings": { "path": "/xh?ed=2048" } }
    },
    {
      "tag": "VLESS_HU",
      "port": 20003,
      "streamSettings": { "network": "httpupgrade", "httpupgradeSettings": { "path": "hu" } }
    }
  ]
}`

func TestBuildRoutingTableFromSampleConfig(t *testing.T) {
	table, err := buildRoutingTable([]byte(sampleConfig), "panel.example")
	if err != nil {
		t.Fatalf("buildRoutingTable: %v", err)
	}

	if table.PanelSNI != "panel.example" {
		t.Fatalf("PanelSNI = %q", table.PanelSNI)
	}

	wantReality := []RealityRoute{
		{Port: 443, SNIs: []string{"a.example.com", "b.example.com"}},
		{Port: 8443, SNIs: []string{"c.example.com"}},
	}
	if !reflect.DeepEqual(table.Reality, wantReality) {
		t.Fatalf("Reality = %#v, want %#v", table.Reality, wantReality)
	}

	// 路径规范化：query 被去掉，缺前导斜杠的被补上。
	wantHTTP := []HTTPRoute{
		{Path: "/hu", Port: 20003, Network: "httpupgrade"},
		{Path: "/ws", Port: 20001, Network: "ws"},
		{Path: "/xh", Port: 20002, Network: "xhttp"},
	}
	if !reflect.DeepEqual(table.HTTP, wantHTTP) {
		t.Fatalf("HTTP = %#v, want %#v", table.HTTP, wantHTTP)
	}

	if len(table.Conflicts) != 0 {
		t.Fatalf("Conflicts = %#v, want none", table.Conflicts)
	}
}

func TestBuildRoutingTableDetectsPathConflicts(t *testing.T) {
	raw := `{"inbounds":[
	  {"tag":"A","port":20001,"streamSettings":{"network":"ws","wsSettings":{"path":"/dup"}}},
	  {"tag":"B","port":20002,"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/dup"}}}
	]}`

	table, err := buildRoutingTable([]byte(raw), "")
	if err != nil {
		t.Fatalf("buildRoutingTable: %v", err)
	}
	if len(table.HTTP) != 0 {
		t.Fatalf("conflicting path must not produce a route, got %#v", table.HTTP)
	}
	if len(table.Conflicts) != 1 {
		t.Fatalf("Conflicts = %#v, want exactly one", table.Conflicts)
	}
	if table.Conflicts[0].Path != "/dup" {
		t.Fatalf("conflict path = %q", table.Conflicts[0].Path)
	}
	// 冲突项应带上端口信息，否则日志里无法定位是哪两个 inbound。
	joined := table.Conflicts[0].Tags
	if len(joined) != 2 {
		t.Fatalf("conflict tags = %#v", joined)
	}
}

// 同一路径落在同一个端口上是合法的（多个 inbound 共用），不该报冲突。
func TestBuildRoutingTableAllowsSamePathSamePort(t *testing.T) {
	raw := `{"inbounds":[
	  {"tag":"A","port":20001,"streamSettings":{"network":"ws","wsSettings":{"path":"/same"}}},
	  {"tag":"B","port":20001,"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/same"}}}
	]}`

	table, err := buildRoutingTable([]byte(raw), "")
	if err != nil {
		t.Fatalf("buildRoutingTable: %v", err)
	}
	if len(table.Conflicts) != 0 {
		t.Fatalf("Conflicts = %#v, want none", table.Conflicts)
	}
	if len(table.HTTP) != 1 || table.HTTP[0].Port != 20001 {
		t.Fatalf("HTTP = %#v", table.HTTP)
	}
}

// 坏掉的 inbound 只应被跳过，不该让整份配置解析失败。
func TestBuildRoutingTableToleratesMalformedInbounds(t *testing.T) {
	raw := `{"inbounds":[
	  {"tag":"NO_STREAM","port":20001},
	  {"tag":"BAD_PORT_STRING","port":"20002","streamSettings":{"network":"ws","wsSettings":{"path":"/a"}}},
	  {"tag":"PORT_TOO_BIG","port":70000,"streamSettings":{"network":"ws","wsSettings":{"path":"/b"}}},
	  {"tag":"PORT_ZERO","port":0,"streamSettings":{"network":"ws","wsSettings":{"path":"/c"}}},
	  {"tag":"NO_PATH","port":20003,"streamSettings":{"network":"ws","wsSettings":{}}},
	  {"tag":"EMPTY_PATH","port":20004,"streamSettings":{"network":"ws","wsSettings":{"path":""}}},
	  {"tag":"UNKNOWN_NETWORK","port":20005,"streamSettings":{"network":"grpc","grpcSettings":{"path":"/d"}}},
	  {"tag":"REALITY_NO_NAMES","port":20006,"streamSettings":{"security":"reality","realitySettings":{"serverNames":[]}}},
	  {"tag":"GOOD","port":20007,"streamSettings":{"network":"ws","wsSettings":{"path":"/good"}}}
	]}`

	table, err := buildRoutingTable([]byte(raw), "")
	if err != nil {
		t.Fatalf("buildRoutingTable must not fail on malformed inbounds: %v", err)
	}
	if len(table.HTTP) != 1 || table.HTTP[0].Path != "/good" || table.HTTP[0].Port != 20007 {
		t.Fatalf("HTTP = %#v, want only the good inbound", table.HTTP)
	}
	if len(table.Reality) != 0 {
		t.Fatalf("Reality = %#v, want none", table.Reality)
	}
}

func TestBuildRoutingTableRejectsNonJSON(t *testing.T) {
	if _, err := buildRoutingTable([]byte("not json"), ""); err == nil {
		t.Fatal("want an error for non-JSON input")
	}
}

// 缺 tag 时用 port:N 补，与 jq 后端的 `(.tag // "port:\(.port)")` 一致。
func TestBuildRoutingTableFallsBackToPortTag(t *testing.T) {
	raw := `{"inbounds":[
	  {"port":20001,"streamSettings":{"network":"ws","wsSettings":{"path":"/a"}}},
	  {"port":20002,"streamSettings":{"network":"ws","wsSettings":{"path":"/a"}}}
	]}`
	table, err := buildRoutingTable([]byte(raw), "")
	if err != nil {
		t.Fatalf("buildRoutingTable: %v", err)
	}
	if len(table.Conflicts) != 1 {
		t.Fatalf("Conflicts = %#v", table.Conflicts)
	}
	joined := table.Conflicts[0].Tags
	if joined[0] != "port:20001(port:20001)" {
		t.Fatalf("tags = %#v", joined)
	}
}

func TestMatchReality(t *testing.T) {
	table, err := buildRoutingTable([]byte(sampleConfig), "")
	if err != nil {
		t.Fatalf("buildRoutingTable: %v", err)
	}

	cases := []struct {
		sni      string
		wantPort int
		wantOK   bool
	}{
		{"a.example.com", 443, true},
		{"c.example.com", 8443, true},
		{"unknown.example.com", 0, false},
		{"", 0, false},
		// 精确匹配，不做后缀或大小写放宽。
		{"A.EXAMPLE.COM", 0, false},
		{"sub.a.example.com", 0, false},
	}
	for _, tc := range cases {
		port, ok := table.MatchReality(tc.sni)
		if ok != tc.wantOK || port != tc.wantPort {
			t.Fatalf("MatchReality(%q) = (%d, %v), want (%d, %v)", tc.sni, port, ok, tc.wantPort, tc.wantOK)
		}
	}
}

// 前缀匹配必须停在路径段边界上：/ws 不能吃掉 /wsfoo 的请求，否则会把别的
// 服务的流量劫持到 inbound 端口。
func TestMatchHTTPStopsAtSegmentBoundary(t *testing.T) {
	table, err := buildRoutingTable([]byte(sampleConfig), "")
	if err != nil {
		t.Fatalf("buildRoutingTable: %v", err)
	}

	cases := []struct {
		path     string
		wantPort int
		wantOK   bool
	}{
		{"/ws", 20001, true},
		{"/ws/", 20001, true},
		{"/ws/sub", 20001, true},
		{"/wsfoo", 0, false},
		{"/w", 0, false},
		{"/", 0, false},
		{"/xh", 20002, true},
		{"/xh/anything", 20002, true},
	}
	for _, tc := range cases {
		route, ok := table.MatchHTTP(tc.path)
		if ok != tc.wantOK {
			t.Fatalf("MatchHTTP(%q) ok = %v, want %v", tc.path, ok, tc.wantOK)
		}
		if ok && route.Port != tc.wantPort {
			t.Fatalf("MatchHTTP(%q).Port = %d, want %d", tc.path, route.Port, tc.wantPort)
		}
	}
}

// 长路径优先：/api/v1 必须先于 /api 命中。
func TestMatchHTTPPrefersLongestPrefix(t *testing.T) {
	raw := `{"inbounds":[
	  {"tag":"SHORT","port":20001,"streamSettings":{"network":"ws","wsSettings":{"path":"/api"}}},
	  {"tag":"LONG","port":20002,"streamSettings":{"network":"ws","wsSettings":{"path":"/api/v1"}}}
	]}`
	table, err := buildRoutingTable([]byte(raw), "")
	if err != nil {
		t.Fatalf("buildRoutingTable: %v", err)
	}

	route, ok := table.MatchHTTP("/api/v1/users")
	if !ok || route.Port != 20002 {
		t.Fatalf("MatchHTTP(/api/v1/users) = %#v, want port 20002", route)
	}
	route, ok = table.MatchHTTP("/api/other")
	if !ok || route.Port != 20001 {
		t.Fatalf("MatchHTTP(/api/other) = %#v, want port 20001", route)
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"/ws":         "/ws",
		"/ws?ed=2048": "/ws",
		"/ws#frag":    "/ws",
		"ws":          "/ws",
		"  /ws  ":     "/ws",
		"":            "",
		"?only=query": "",
		"/a?b#c":      "/a",
	}
	for input, want := range cases {
		if got := normalizePath(input); got != want {
			t.Fatalf("normalizePath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParsePort(t *testing.T) {
	cases := []struct {
		input any
		want  int
	}{
		{float64(443), 443},
		{float64(65535), 65535},
		{float64(0), 0},
		{float64(-1), 0},
		{float64(65536), 0},
		{float64(1.5), 0},
		// JSON 字符串里的合法数字也必须拒绝：json.Number 会把它当成合法值，
		// 而 jq/Node/Python 三后端都要求真正的 number 类型。
		{"20002", 0},
		{nil, 0},
		{true, 0},
	}
	for _, tc := range cases {
		if got := parsePort(tc.input); got != tc.want {
			t.Fatalf("parsePort(%#v) = %d, want %d", tc.input, got, tc.want)
		}
	}
}
