package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// mockUpstream 记录收到的字节，供断言路由目标与数据完整性。
type mockUpstream struct {
	ln       net.Listener
	port     int
	mu       sync.Mutex
	received []byte
	conns    int
}

func startMockUpstream(t *testing.T) *mockUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	m := &mockUpstream{ln: ln, port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			m.mu.Lock()
			m.conns++
			m.mu.Unlock()
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						m.mu.Lock()
						m.received = append(m.received, buf[:n]...)
						m.mu.Unlock()
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return m
}

func (m *mockUpstream) bytes() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.received...)
}

func (m *mockUpstream) connCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conns
}

// startFront 起一个 frontListener，返回它的监听地址。xhttp/ws 兜底端口固定，
// 需要真实上游时用 startFrontWith。
func startFront(t *testing.T, source *configSource, nodePort, sshPort int, sshEnabled bool, handler http.Handler) string {
	t.Helper()
	return startFrontWith(t, source, nodePort, sshPort, sshEnabled, 18080, 18880, handler)
}

func startFrontWith(t *testing.T, source *configSource, nodePort, sshPort int, sshEnabled bool, xhttpPort, wsPort int, handler http.Handler) string {
	t.Helper()
	fl := newFrontListener(nodePort, sshPort, sshEnabled, xhttpPort, wsPort, source, handler)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = fl.Serve(ln) }()
	return ln.Addr().String()
}

func sourceWith(table RoutingTable) *configSource {
	source := &configSource{panelSNI: table.PanelSNI}
	source.table.Store(&table)
	return source
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("超时等待: %s", what)
}

// TLS 的 SNI 命中 REALITY 时转对应 inbound，未知 SNI 兜底转 node API。
func TestFrontListenerRoutesTLSBySNI(t *testing.T) {
	node := startMockUpstream(t)
	reality := startMockUpstream(t)
	source := sourceWith(RoutingTable{
		Reality: []RealityRoute{{Port: reality.port, SNIs: []string{"r.example.com"}}},
	})
	addr := startFront(t, source, node.port, 0, false, http.NotFoundHandler())

	hello := realClientHello(t, &tls.Config{ServerName: "r.example.com"})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	_ = conn.Close()

	waitFor(t, "REALITY 上游收到 ClientHello", func() bool { return len(reality.bytes()) > 0 })
	if node.connCount() != 0 {
		t.Fatalf("node 上游不应收到连接，实际 %d", node.connCount())
	}
	if got := reality.bytes(); !bytes.Equal(got, hello) {
		t.Fatalf("上游收到的 ClientHello 与发送的不一致: %d vs %d 字节", len(got), len(hello))
	}
}

func TestFrontListenerFallsBackToNodePortForUnknownSNI(t *testing.T) {
	node := startMockUpstream(t)
	reality := startMockUpstream(t)
	source := sourceWith(RoutingTable{
		Reality: []RealityRoute{{Port: reality.port, SNIs: []string{"r.example.com"}}},
	})
	addr := startFront(t, source, node.port, 0, false, http.NotFoundHandler())

	hello := realClientHello(t, &tls.Config{ServerName: "unknown.example.com"})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write(hello)
	_ = conn.Close()

	waitFor(t, "node 上游收到 ClientHello", func() bool { return len(node.bytes()) > 0 })
	if reality.connCount() != 0 {
		t.Fatalf("REALITY 上游不应收到连接，实际 %d", reality.connCount())
	}
}

// 没有 SNI 的 ClientHello 同样兜底到 node API，而不是被丢弃。
func TestFrontListenerRoutesClientHelloWithoutSNIToNode(t *testing.T) {
	node := startMockUpstream(t)
	source := sourceWith(RoutingTable{})
	addr := startFront(t, source, node.port, 0, false, http.NotFoundHandler())

	hello := realClientHello(t, &tls.Config{InsecureSkipVerify: true})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write(hello)
	_ = conn.Close()

	waitFor(t, "node 上游收到无 SNI 的 ClientHello", func() bool { return len(node.bytes()) > 0 })
}

func TestFrontListenerRoutesSSHBanner(t *testing.T) {
	ssh := startMockUpstream(t)
	node := startMockUpstream(t)
	source := sourceWith(RoutingTable{})
	addr := startFront(t, source, node.port, ssh.port, true, http.NotFoundHandler())

	banner := []byte("SSH-2.0-OpenSSH_10.3\r\n")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write(banner)
	_ = conn.Close()

	waitFor(t, "sshd 上游收到 banner", func() bool { return len(ssh.bytes()) > 0 })
	if got := ssh.bytes(); !bytes.Equal(got, banner) {
		t.Fatalf("banner 不一致: %q", got)
	}
	if node.connCount() != 0 {
		t.Fatalf("node 上游不应收到连接，实际 %d", node.connCount())
	}
}

// SSH 关闭时不能直通到不存在的服务：应回落到 HTTP 处理。
func TestFrontListenerRejectsSSHWhenDisabled(t *testing.T) {
	ssh := startMockUpstream(t)
	node := startMockUpstream(t)
	source := sourceWith(RoutingTable{})
	addr := startFront(t, source, node.port, ssh.port, false, http.NotFoundHandler())

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_10.3\r\n"))
	_ = conn.Close()

	// 给它一点时间去错误路由；ssh 上游必须始终为空。
	time.Sleep(200 * time.Millisecond)
	if ssh.connCount() != 0 {
		t.Fatalf("SSH 关闭时不应转发到 sshd 上游，实际 %d 条连接", ssh.connCount())
	}
}

// 明文 HTTP 交给 handler，且请求行不能因为 peek 而丢失。
func TestFrontListenerServesHTTPWithIntactRequestLine(t *testing.T) {
	node := startMockUpstream(t)
	source := sourceWith(RoutingTable{})

	var gotPath, gotMethod string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "served")
	})
	addr := startFront(t, source, node.port, 0, false, handler)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// 这里刻意不在请求后立刻断言：handler 与读取在不同 goroutine。
	waitFor(t, "handler 被调用", func() bool { return gotMethod != "" })
	if gotMethod != "GET" || gotPath != "/health" {
		t.Fatalf("handler 收到 %s %s，请求行可能在 peek 后丢失", gotMethod, gotPath)
	}
	if !bytes.Contains(body, []byte("418")) {
		t.Fatalf("响应异常: %q", body)
	}
}

// 大体积数据在 peek 之后必须一字节不丢地到达上游（补写路径的回归测试）。
func TestFrontListenerRelayPreservesAllBytes(t *testing.T) {
	node := startMockUpstream(t)
	source := sourceWith(RoutingTable{})
	addr := startFront(t, source, node.port, 0, false, http.NotFoundHandler())

	hello := realClientHello(t, &tls.Config{ServerName: "unknown.example.com"})
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB，跨多个 TCP 段

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write(hello)
	_, _ = conn.Write(payload)
	_ = conn.Close()

	want := append(append([]byte(nil), hello...), payload...)
	waitFor(t, "上游收到全部字节", func() bool { return len(node.bytes()) >= len(want) })
	if got := node.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("数据不一致: 收到 %d 字节，期望 %d", len(got), len(want))
	}
}

func TestParseHTTPPath(t *testing.T) {
	cases := []struct {
		request string
		want    string
	}{
		{"GET /health HTTP/1.1\r\nHost: x\r\n\r\n", "/health"},
		{"POST /node/xray/start HTTP/1.1\r\n\r\n", "/node/xray/start"},
		{"GET /ws?ed=2048 HTTP/1.1\r\n\r\n", "/ws"},
		{"GET /ws#frag HTTP/1.1\r\n\r\n", "/ws"},
		{"GET http://example.com/xh HTTP/1.1\r\n\r\n", "/xh"},
		{"GET https://example.com:443/xh HTTP/1.1\r\n\r\n", "/xh"},
		{"PRI * HTTP/2.0\r\n\r\n", ""},
		{"garbage", ""},
	}
	for _, tc := range cases {
		if got := parseHTTPPath([]byte(tc.request)); got != tc.want {
			t.Fatalf("parseHTTPPath(%q) = %q, want %q", tc.request, got, tc.want)
		}
	}
}

func TestClassifyHead(t *testing.T) {
	cases := []struct {
		head string
		want routeKind
	}{
		{"SSH-2.0-OpenSSH_10.3\r\n", routeSSH},
		// 以 S 开头但不是 "SSH-" 前缀的请求必须按 HTTP 处理。
		{"SEARCH /x HTTP/1.1\r\n\r\n", routeHTTP},
		{"SS /x HTTP/1.1\r\n\r\n", routeHTTP},
		{"GET /x HTTP/1.1\r\n\r\n", routeHTTP},
		{"", routeHTTP},
	}
	for _, tc := range cases {
		kind, _, _ := classifyHead([]byte(tc.head))
		if kind != tc.want {
			t.Fatalf("classifyHead(%q) = %v, want %v", tc.head, kind, tc.want)
		}
	}
}

// 回归：判定协议必须「够用即停」，不能等到缓冲区填满。曾经用固定长度的
// Peek 读首部，一个几十字节的 HTTP 请求要白等满 headerTimeout 才被处理。
func TestFrontListenerServesHTTPPromptly(t *testing.T) {
	node := startMockUpstream(t)
	source := sourceWith(RoutingTable{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	addr := startFront(t, source, node.port, 0, false, handler)

	start := time.Now()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(conn, "GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	_, _ = io.ReadAll(conn)

	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("HTTP 连接耗时 %s，判定阶段可能在等缓冲区填满", elapsed.Round(time.Millisecond))
	}
}

func TestTLSUpstreamPrefersRealityThenNode(t *testing.T) {
	source := sourceWith(RoutingTable{
		PanelSNI: "panel.example",
		Reality:  []RealityRoute{{Port: 5000, SNIs: []string{"r.example.com"}}},
	})
	fl := newFrontListener(2222, 0, false, 0, 0, source, http.NotFoundHandler())

	if got := fl.tlsUpstream("r.example.com"); got != 5000 {
		t.Fatalf("REALITY SNI 应转到 5000，得到 %d", got)
	}
	for _, sni := range []string{"panel.example", "unknown", ""} {
		if got := fl.tlsUpstream(sni); got != 2222 {
			t.Fatalf("SNI %q 应兜底到 node 端口 2222，得到 %d", sni, got)
		}
	}
}

// Panel 下发的 inbound 路径必须被裸转发到对应端口，而不是交给 http.Server：
// 这条路径是 ws/xhttp 主流量，走 L4 直通才能吃到 splice。
func TestFrontListenerRelaysInboundPathWithoutHTTPHandler(t *testing.T) {
	inbound := startMockUpstream(t)
	node := startMockUpstream(t)
	source := sourceWith(RoutingTable{
		HTTP: []HTTPRoute{{Path: "/ws", Port: inbound.port, Network: "ws"}},
	})

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})
	addr := startFront(t, source, node.port, 0, false, handler)

	request := "GET /ws/stream HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n"
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write([]byte(request))
	_ = conn.Close()

	waitFor(t, "inbound 上游收到请求", func() bool { return len(inbound.bytes()) > 0 })
	if got := inbound.bytes(); !bytes.Equal(got, []byte(request)) {
		t.Fatalf("上游收到的请求不完整:\n got %q\nwant %q", got, request)
	}
	if handlerCalled {
		t.Fatal("inbound 路径不应进入本进程的 HTTP handler")
	}
	if node.connCount() != 0 {
		t.Fatalf("node 上游不应收到连接，实际 %d", node.connCount())
	}
}

// 路由表里没有该路径时，/xh-* 与 /ws-* 按约定前缀兜底转发。
func TestFrontListenerFallsBackToWildcardPrefixes(t *testing.T) {
	xhttp := startMockUpstream(t)
	ws := startMockUpstream(t)
	node := startMockUpstream(t)
	source := sourceWith(RoutingTable{})
	addr := startFrontWith(t, source, node.port, 0, false, xhttp.port, ws.port, http.NotFoundHandler())

	for _, tc := range []struct {
		path string
		up   *mockUpstream
	}{
		{"/xh-anything", xhttp},
		{"/ws-anything", ws},
	} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_, _ = conn.Write([]byte("GET " + tc.path + " HTTP/1.1\r\nHost: x\r\n\r\n"))
		_ = conn.Close()

		waitFor(t, tc.path+" 被兜底转发", func() bool { return len(tc.up.bytes()) > 0 })
	}
	if node.connCount() != 0 {
		t.Fatalf("node 上游不应收到连接，实际 %d", node.connCount())
	}
}

// /health 与 /node/* 必须由本进程处理，不能被当成 inbound 路径转发出去。
func TestFrontListenerKeepsHealthAndNodeApiLocal(t *testing.T) {
	node := startMockUpstream(t)
	source := sourceWith(RoutingTable{
		// 故意让路由表把 /health 也认领了：本地处理优先，不该被它劫走。
		HTTP: []HTTPRoute{{Path: "/health", Port: node.port, Network: "ws"}},
	})

	var paths []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = io.WriteString(w, "local")
	})
	addr := startFront(t, source, node.port, 0, false, handler)

	for _, path := range []string{"/health", "/node/xray/healthcheck", "/vision/x"} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", path)
		body, _ := io.ReadAll(conn)
		_ = conn.Close()
		if !bytes.Contains(body, []byte("local")) {
			t.Fatalf("%s 未由本进程处理，响应为 %q", path, body)
		}
	}
	if node.connCount() != 0 {
		t.Fatalf("这些路径不该转发到上游，实际 %d 条连接", node.connCount())
	}
}
