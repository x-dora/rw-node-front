package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// configSource 定期从 rw-node-go 的 internal API 拉取当前 Xray 配置，解析成
// 路由表后原子发布。
//
// 这里刻意用轮询而不是长轮询/推送：那需要在 rw-node-go 里加配置变更通知，
// 而 rw-node-go 的定位是对齐官方 remnawave/node 的 Panel-facing contract，
// 给它塞前端专用的推送机制不合适。轮询的代价在这个进程里也很低——解析只有
// 一份 Go 实现、没有热重载、没有跨进程重载失败要处理。
type configSource struct {
	url      string
	interval time.Duration
	client   *http.Client
	// panelSNI 由本进程从 SECRET_KEY 自行派生，不再依赖 /internal/get-config
	// 注入的 panelSni 字段。
	panelSNI string

	table atomic.Pointer[RoutingTable]
	// lastErr 只用于避免同一个错误反复刷屏。
	lastErr atomic.Pointer[string]
}

func newConfigSource(baseURL string, interval time.Duration, panelSNI string) *configSource {
	return &configSource{
		url:      baseURL + "/internal/get-config",
		interval: interval,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       2,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: true,
			},
		},
		panelSNI: panelSNI,
	}
}

// Table 返回当前生效的路由表。首次成功拉取之前返回空表。
func (s *configSource) Table() *RoutingTable {
	if table := s.table.Load(); table != nil {
		return table
	}
	return &RoutingTable{}
}

// Run 阻塞轮询直到 ctx 结束。启动时立即拉一次，让前置尽早拿到真实路由；
// 失败不清空已有路由表——保留上一份可用配置比退回全默认更安全。
func (s *configSource) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refresh(ctx)
		}
	}
}

func (s *configSource) refresh(ctx context.Context) {
	raw, err := s.fetch(ctx)
	if err != nil {
		s.reportError(fmt.Sprintf("fetch config: %v", err))
		return
	}

	table, err := buildRoutingTable(raw, s.panelSNI)
	if err != nil {
		// buildRoutingTable 的错误已经带上下文，这里不再叠一层前缀。
		s.reportError(err.Error())
		return
	}

	s.lastErr.Store(nil)
	s.publish(table)
}

func (s *configSource) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	// 配置规模受 inbound 数量影响，给一个宽松上限防止异常响应吃满内存。
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// publish 换上新路由表，并把与前一份的差异打出来。
//
// 路由表是整体替换而非增量修改：一次配置下发可能同时改动多个 inbound，
// 增量合并要么需要跟踪来源，要么会在中途暴露半新半旧的路由。
func (s *configSource) publish(next RoutingTable) {
	prev := s.table.Load()
	s.table.Store(&next)

	if prev == nil || routingChanged(prev, &next) {
		logRoutes(&next)
	}
}

func (s *configSource) reportError(msg string) {
	stored := s.lastErr.Load()
	if stored != nil && *stored == msg {
		return
	}
	message := msg
	s.lastErr.Store(&message)
	log.Printf("WARN: %s (保持上一份可用路由)", msg)
}

// routingChanged 做一次粗粒度比较，只用来决定要不要打印路由日志。
func routingChanged(prev, next *RoutingTable) bool {
	if prev.PanelSNI != next.PanelSNI ||
		len(prev.Reality) != len(next.Reality) ||
		len(prev.HTTP) != len(next.HTTP) ||
		len(prev.Conflicts) != len(next.Conflicts) {
		return true
	}
	for i := range prev.Reality {
		a, b := prev.Reality[i], next.Reality[i]
		if a.Port != b.Port || len(a.SNIs) != len(b.SNIs) {
			return true
		}
		for j := range a.SNIs {
			if a.SNIs[j] != b.SNIs[j] {
				return true
			}
		}
	}
	for i := range prev.HTTP {
		if prev.HTTP[i] != next.HTTP[i] {
			return true
		}
	}
	return false
}

func logRoutes(table *RoutingTable) {
	if table.PanelSNI != "" {
		log.Printf("L4 route: PANEL sni=%s", table.PanelSNI)
	}
	for _, route := range table.Reality {
		log.Printf("L4 route: REALITY snis=%v -> 127.0.0.1:%d", route.SNIs, route.Port)
	}
	for _, route := range table.HTTP {
		log.Printf("HTTP route: %s [%s] -> 127.0.0.1:%d", route.Path, route.Network, route.Port)
	}
	for _, conflict := range table.Conflicts {
		log.Printf("WARN: HTTP route conflict: path=%s claimed by [%v], skipped", conflict.Path, conflict.Tags)
	}
	if len(table.HTTP) == 0 {
		log.Printf("no HTTP path inbounds detected, using fallback wildcard routes")
	}
}
