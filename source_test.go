package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// stubNode 模拟 rw-node-go 的 /internal/get-config，响应体可切换。
type stubNode struct {
	mu      sync.Mutex
	status  int
	body    string
	paths   []string
	handler func(w http.ResponseWriter, r *http.Request)
}

func (s *stubNode) set(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
	s.body = body
}

func (s *stubNode) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	status, body, h := s.status, s.body, s.handler
	s.mu.Unlock()

	if h != nil {
		h(w, r)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (s *stubNode) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

func startStub(t *testing.T) (*stubNode, *httptest.Server) {
	t.Helper()
	stub := &stubNode{status: http.StatusOK, body: sampleConfig}
	srv := httptest.NewServer(http.HandlerFunc(stub.serve))
	t.Cleanup(srv.Close)
	return stub, srv
}

func TestConfigSourcePublishesParsedTable(t *testing.T) {
	stub, srv := startStub(t)
	source := newConfigSource(srv.URL, time.Hour, "panel.example")

	source.refresh(context.Background())

	if got := stub.requests(); len(got) != 1 || got[0] != "/internal/get-config" {
		t.Fatalf("requests = %#v", got)
	}

	table := source.Table()
	if table.PanelSNI != "panel.example" {
		t.Fatalf("PanelSNI = %q", table.PanelSNI)
	}
	if len(table.HTTP) != 3 {
		t.Fatalf("HTTP routes = %#v", table.HTTP)
	}
	if port, ok := table.MatchReality("a.example.com"); !ok || port != 443 {
		t.Fatalf("MatchReality = (%d, %v)", port, ok)
	}
}

// 拉取失败必须保留上一份可用路由：退回空表会让所有分流瞬间失效，
// 比继续用一份可能稍旧的配置危险得多。
func TestConfigSourceKeepsLastGoodTableOnFailure(t *testing.T) {
	stub, srv := startStub(t)
	source := newConfigSource(srv.URL, time.Hour, "")

	source.refresh(context.Background())
	before := source.Table()
	if len(before.HTTP) != 3 {
		t.Fatalf("initial table = %#v", before.HTTP)
	}

	stub.set(http.StatusInternalServerError, "boom")
	source.refresh(context.Background())
	if got := source.Table(); got != before {
		t.Fatal("table was replaced after a failed fetch")
	}

	stub.set(http.StatusOK, "not json at all")
	source.refresh(context.Background())
	if got := source.Table(); got != before {
		t.Fatal("table was replaced after an unparseable response")
	}

	stub.set(http.StatusOK, sampleConfig)
	source.refresh(context.Background())
	if got := source.Table(); got == before {
		t.Fatal("table was not replaced after a successful fetch")
	}
}

// 持续失败时只提示一次，避免每轮都刷屏。去重靠「错误文案相同就不换指针」
// 实现，所以第二次 refresh 后 lastErr 必须仍是同一个指针。
func TestConfigSourceDeduplicatesRepeatedErrors(t *testing.T) {
	stub, srv := startStub(t)
	stub.set(http.StatusInternalServerError, "boom")
	source := newConfigSource(srv.URL, time.Hour, "")

	source.refresh(context.Background())
	first := source.lastErr.Load()
	if first == nil {
		t.Fatal("expected an error to be recorded")
	}
	if *first == "" {
		t.Fatal("recorded error message is empty")
	}

	source.refresh(context.Background())
	second := source.lastErr.Load()
	if second != first {
		t.Fatalf("identical errors should be deduplicated onto the same pointer, got %p then %p", first, second)
	}

	// 换成另一种失败时必须重新提示。
	stub.set(http.StatusForbidden, "nope")
	source.refresh(context.Background())
	third := source.lastErr.Load()
	if third == first {
		t.Fatal("a different error must not be deduplicated away")
	}
	if *third == *first {
		t.Fatalf("error message did not change: %q", *third)
	}
}

// 错误状态码下不应把响应体当成配置解析。
func TestConfigSourceRejectsNonOKStatus(t *testing.T) {
	stub, srv := startStub(t)
	stub.set(http.StatusForbidden, sampleConfig)
	source := newConfigSource(srv.URL, time.Hour, "")

	source.refresh(context.Background())
	if len(source.Table().HTTP) != 0 {
		t.Fatal("non-200 response must not be parsed into the routing table")
	}
}

func TestConfigSourceRunPollsUntilCancelled(t *testing.T) {
	stub, srv := startStub(t)
	source := newConfigSource(srv.URL, 20*time.Millisecond, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		source.Run(ctx)
	}()

	time.Sleep(120 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	if got := len(stub.requests()); got < 2 {
		t.Fatalf("expected repeated polling, got %d request(s)", got)
	}
}

func TestRoutingChanged(t *testing.T) {
	base := RoutingTable{
		PanelSNI: "p",
		Reality:  []RealityRoute{{Port: 443, SNIs: []string{"a"}}},
		HTTP:     []HTTPRoute{{Path: "/ws", Port: 20001, Network: "ws"}},
	}
	same := RoutingTable{
		PanelSNI: "p",
		Reality:  []RealityRoute{{Port: 443, SNIs: []string{"a"}}},
		HTTP:     []HTTPRoute{{Path: "/ws", Port: 20001, Network: "ws"}},
	}
	if routingChanged(&base, &same) {
		t.Fatal("identical tables reported as changed")
	}

	changedPort := same
	changedPort.HTTP = []HTTPRoute{{Path: "/ws", Port: 20002, Network: "ws"}}
	if !routingChanged(&base, &changedPort) {
		t.Fatal("port change not detected")
	}

	changedSNI := same
	changedSNI.Reality = []RealityRoute{{Port: 443, SNIs: []string{"b"}}}
	if !routingChanged(&base, &changedSNI) {
		t.Fatal("SNI change not detected")
	}
}
