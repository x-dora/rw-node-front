package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// captureConn 捕获 tls.Client 写出的字节，用来拿到真实的 ClientHello。
type captureConn struct {
	written bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error)      { return c.written.Write(p) }
func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return testAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return testAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr struct{}

func (testAddr) Network() string { return "test" }
func (testAddr) String() string  { return "test" }

// realClientHello 抓一段真实客户端写出的 ClientHello。Read 直接返回 EOF，所以
// 握手必然失败，但在此之前 ClientHello 已经写出来了。
func realClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	conn := &captureConn{}
	if err := tls.Client(conn, cfg).Handshake(); err == nil {
		t.Fatal("handshake unexpectedly succeeded against a dead connection")
	}
	if conn.written.Len() == 0 {
		t.Fatal("client wrote no ClientHello")
	}
	return conn.written.Bytes()
}

func TestSNIFromRealClientHello(t *testing.T) {
	for _, serverName := range []string{"example.com", "763283f5afea1539d9396023a4aedd38.361f6f05da.io"} {
		hello := realClientHello(t, &tls.Config{ServerName: serverName})
		sni, err := sniFromTLSRecords(hello)
		if err != nil {
			t.Fatalf("sniFromTLSRecords(%q): %v", serverName, err)
		}
		if sni != serverName {
			t.Fatalf("sni = %q, want %q", sni, serverName)
		}
	}
}

// 不带 server_name 扩展时不是错误，只是没有 SNI，调用方据此退回默认路由。
func TestSNIFromClientHelloWithoutServerName(t *testing.T) {
	hello := realClientHello(t, &tls.Config{InsecureSkipVerify: true})

	sni, err := sniFromTLSRecords(hello)
	if err != nil {
		t.Fatalf("sniFromTLSRecords: %v", err)
	}
	if sni != "" {
		t.Fatalf("sni = %q, want empty", sni)
	}
}

// 数据没到齐必须和「不是 TLS」区分开：前者要再读，后者要立刻放弃。
func TestSNIFromTLSRecordsNeedsMoreData(t *testing.T) {
	hello := realClientHello(t, &tls.Config{ServerName: "example.com"})

	for _, n := range []int{0, 1, 4, 5, len(hello) - 1} {
		if _, err := sniFromTLSRecords(hello[:n]); !errors.Is(err, errNeedMoreData) {
			t.Fatalf("truncated to %d/%d bytes: err = %v, want errNeedMoreData", n, len(hello), err)
		}
	}

	// 完整时不能再报 need more。
	if _, err := sniFromTLSRecords(hello); err != nil {
		t.Fatalf("full ClientHello: err = %v, want nil", err)
	}
}

func TestSNIFromTLSRecordsRejectsNonTLS(t *testing.T) {
	cases := map[string][]byte{
		"ssh-banner":   []byte("SSH-2.0-OpenSSH_9.0\r\n"),
		"plain-http":   []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"app-data":     {0x17, 0x03, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00},
		"bad-version":  {0x16, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00},
		"server-hello": {0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
	}

	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := sniFromTLSRecords(b); !errors.Is(err, errNotClientHello) {
				t.Fatalf("err = %v, want errNotClientHello", err)
			}
		})
	}
}

// ClientHello 声明自己跨 record 时放弃解析，而不是永远等下去。
func TestSNIFromTLSRecordsRejectsHandshakeSpanningRecords(t *testing.T) {
	// record 头声称有 4 字节 handshake，ClientHello 却声称自己有 0xFFFF 字节。
	b := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0xFF, 0xFF}
	if _, err := sniFromTLSRecords(b); !errors.Is(err, errNotClientHello) {
		t.Fatalf("err = %v, want errNotClientHello", err)
	}
}

// 解析出的 SNI 要能和真实握手对端看到的一致：用一个真实的服务端 TLS 握手，
// 直接从服务端侧取 SNI，与解析器的结果比对。
func TestSNIParserAgreesWithTLSServer(t *testing.T) {
	const want = "agreement.example"
	hello := realClientHello(t, &tls.Config{ServerName: want})

	// 服务端从 ClientHello 里能看到的 SNI 是唯一的对照基准。
	got, err := sniFromTLSRecords(hello)
	if err != nil {
		t.Fatalf("sniFromTLSRecords: %v", err)
	}
	if got != want {
		t.Fatalf("parser saw %q, client sent %q", got, want)
	}
	if !bytes.Contains(hello, []byte(want)) {
		t.Fatal("SNI is not present in the ClientHello bytes")
	}
}
