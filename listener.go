package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// maxHeadBytes 是愿意为判定协议而缓冲的上限。ClientHello 通常几百字节，
	// 带大量扩展时 2-3KiB；HTTP 请求行通常不到 1KiB。
	maxHeadBytes = 16 << 10

	// headerTimeout 限制等待首部数据的时间，慢连接不该一直占着 goroutine。
	headerTimeout = 10 * time.Second
)

type routeKind int

const (
	routeHTTP routeKind = iota
	routeTLS
	routeSSH
)

// frontListener 在对外端口上做协议分流，取代原先 Caddy 的 layer4
// listener_wrappers：判定一次，然后要么把连接裸转发出去（保住 splice），
// 要么交给 http.Server 按路径处理。
type frontListener struct {
	nodePort   int
	sshPort    int
	sshEnabled bool
	xhttpPort  int
	wsPort     int

	source     *configSource
	httpServer *http.Server
}

func newFrontListener(nodePort, sshPort int, sshEnabled bool, xhttpPort, wsPort int, source *configSource, handler http.Handler) *frontListener {
	return &frontListener{
		nodePort:   nodePort,
		sshPort:    sshPort,
		sshEnabled: sshEnabled,
		xhttpPort:  xhttpPort,
		wsPort:     wsPort,
		source:     source,
		httpServer: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       60 * time.Second,
			ErrorLog:          log.Default(),
		},
	}
}

// Serve 接受连接直到 listener 被关闭。连接各自在 goroutine 里处理，慢客户端
// 不会挡住 Accept。
func (l *frontListener) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go l.handleConn(conn)
	}
}

func (l *frontListener) handleConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(headerTimeout))
	head, err := readHead(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if len(head) == 0 {
		if err != nil {
			log.Printf("front: 读取 %s 的首部失败: %v", remoteAddr(conn), err)
		}
		_ = conn.Close()
		return
	}

	kind, sni, path := classifyHead(head)

	switch kind {
	case routeSSH:
		if !l.sshEnabled {
			// SSH 关闭时不能直通到不存在的服务，直接断开。
			_ = conn.Close()
			return
		}
		defer conn.Close()
		l.relay(conn, head, l.sshPort)

	case routeTLS:
		defer conn.Close()
		l.relay(conn, head, l.tlsUpstream(sni))

	case routeHTTP:
		// 路径分流在 L4 完成、裸转发到 inbound 端口，这样 ws/xhttp 的主流量
		// 也走内核 splice。若改成交给 ReverseProxy，升级后的长连接就会退回
		// 用户态拷贝——那正是原先 Caddy 的形态，等于没解决问题。
		if port, ok := l.httpUpstream(path); ok {
			defer conn.Close()
			l.relay(conn, head, port)
			return
		}
		// 少数需要本进程处理的路径（健康检查、node API、静态伪装页）才进
		// http.Server，连接所有权随之移交，由它负责关闭。
		l.serveHTTP(conn, head)
	}
}

// httpUpstream 决定一条明文 HTTP 该直通到哪个端口；返回 false 表示由本进程
// 处理。判定顺序与原先 Caddyfile 的 handle 顺序一致：node API 与健康检查
// 优先，其次是 Panel 下发的 inbound 路径，最后是 /xh-* /ws-* 兜底，
// 其余落到静态伪装页。
func (l *frontListener) httpUpstream(path string) (int, bool) {
	if path == "/health" || strings.HasPrefix(path, "/node/") || strings.HasPrefix(path, "/vision/") {
		return 0, false
	}
	if route, ok := l.source.Table().MatchHTTP(path); ok {
		return route.Port, true
	}
	switch {
	case strings.HasPrefix(path, "/xh-"):
		return l.xhttpPort, true
	case strings.HasPrefix(path, "/ws-"):
		return l.wsPort, true
	}
	return 0, false
}

// readHead 读到「足够判定协议」为止，而不是读满缓冲区。
//
// 这一点很关键：按固定长度 Peek 会一直等到缓冲填满或读超时，一个几十字节的
// HTTP 请求就会让连接白等满一个 headerTimeout。所以按协议各自的判定条件
// 提前收手——TLS 等整个 ClientHello，SSH 等 4 字节前缀，HTTP 等第一个换行。
//
// 返回的字节已经离开 socket，调用方必须原样交给下游（补写给上游或喂给
// http.Server），否则请求行/ClientHello 就丢了。
func readHead(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 0, 1024)
	chunk := make([]byte, 2048)
	for len(buf) < maxHeadBytes {
		n, err := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if headComplete(buf) {
				return buf, nil
			}
		}
		if err != nil {
			return buf, err
		}
	}
	return buf, nil
}

// headComplete 判断当前缓冲是否已经够判定协议。
func headComplete(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}
	switch buf[0] {
	case recordTypeHandshake:
		if len(buf) < 5 {
			return false
		}
		recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
		if 5+recordLen > maxHeadBytes {
			// 超出上限的 ClientHello 不再等，按不可解析处理。
			return true
		}
		return len(buf) >= 5+recordLen
	case 'S':
		if len(buf) < 4 {
			return false
		}
		if string(buf[:4]) == "SSH-" {
			return true
		}
		return bytes.IndexByte(buf, '\n') >= 0
	default:
		return bytes.IndexByte(buf, '\n') >= 0
	}
}

// classifyHead 只看首部字节判定协议，并取出选路需要的 SNI / 路径。
func classifyHead(head []byte) (routeKind, string, string) {
	if len(head) == 0 {
		return routeHTTP, "", ""
	}

	switch {
	case head[0] == recordTypeHandshake:
		// 解析不出 SNI 不是错误：那条 TLS 连接按无 SNI 处理，兜底走 node API。
		sni, err := sniFromTLSRecords(head)
		if err != nil {
			return routeTLS, "", ""
		}
		return routeTLS, sni, ""

	case bytes.HasPrefix(head, []byte("SSH-")):
		return routeSSH, "", ""

	default:
		return routeHTTP, "", parseHTTPPath(head)
	}
}

// tlsUpstream 决定一条 TLS 连接该转给哪个端口：命中 REALITY SNI 就转对应
// inbound，其余（含 Panel SNI）一律是 node API，与原先 Caddy 的 @reality /
// @panel / @tls 三条规则的相对顺序等价。
func (l *frontListener) tlsUpstream(sni string) int {
	if sni != "" {
		if port, ok := l.source.Table().MatchReality(sni); ok {
			return port
		}
	}
	return l.nodePort
}

// parseHTTPPath 从请求行里取出路径，取不到返回空串。
func parseHTTPPath(head []byte) string {
	line := head
	if idx := bytes.IndexByte(head, '\n'); idx >= 0 {
		line = head[:idx]
	}
	line = bytes.TrimSuffix(line, []byte("\r"))

	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		return ""
	}
	target := fields[1]

	// 绝对形式（代理请求）只取其中的 path 部分。
	if rest, ok := strings.CutPrefix(target, "http://"); ok {
		if idx := strings.IndexByte(rest, '/'); idx >= 0 {
			target = rest[idx:]
		} else {
			return "/"
		}
	} else if rest, ok := strings.CutPrefix(target, "https://"); ok {
		if idx := strings.IndexByte(rest, '/'); idx >= 0 {
			target = rest[idx:]
		} else {
			return "/"
		}
	}

	if idx := strings.IndexAny(target, "?#"); idx >= 0 {
		target = target[:idx]
	}
	if target == "" || target[0] != '/' {
		return ""
	}
	return target
}

// relay 把连接双向转发到 upstream，并先把已经读出来的首部字节补写出去。
//
// 补写这一步决定零拷贝是否成立：首部字节已经离开 socket，必须用用户态写一次；
// 但 down 本身仍是未被包装的 *net.TCPConn，所以随后的 io.Copy 依然命中
// TCPConn.ReadFrom，在 Linux 上由内核 splice 搬运。实测（bench/forward 的
// peek 模式，256MiB）用户态字节数恒为首部大小，与传输总量无关。
func (l *frontListener) relay(down net.Conn, head []byte, port int) {
	upstreamAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	up, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		log.Printf("front: 连接上游 %s 失败: %v", upstreamAddr, err)
		return
	}
	defer up.Close()

	if len(head) > 0 {
		if _, err := up.Write(head); err != nil {
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, down)
		closeWrite(up)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(down, up)
		closeWrite(down)
	}()
	wg.Wait()
}

// serveHTTP 把这条连接交给共享的 http.Server，用于本进程自己处理的路径
// （健康检查、node API、静态伪装页）。
//
// net/http 没有「处理一条已建立的连接」的公开入口，标准做法是喂给它一个只
// 产出这一条连接的 listener。prefixConn 让 server 先读到我们判定协议时已经
// 消费的字节——否则请求行就丢了。
//
// 注意所有权：Serve 返回时连接仍在处理中，由 http.Server 在结束时关闭，
// 调用方不能再 defer Close。
func (l *frontListener) serveHTTP(conn net.Conn, head []byte) {
	pc := &prefixConn{Conn: conn, prefix: bytes.NewReader(head)}
	if err := l.httpServer.Serve(&singleConnListener{conn: pc}); err != nil &&
		!errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("front: 处理 %s 的 HTTP 连接失败: %v", remoteAddr(conn), err)
	}
}

// prefixConn 先吐出判定协议时读到的字节，再回到底层连接。
type prefixConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.Conn.Read(p)
}

// singleConnListener 只产出给定的一条连接。
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, net.ErrClosed
	}
	l.done = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func closeWrite(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

func remoteAddr(c net.Conn) string {
	if addr := c.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return "?"
}
