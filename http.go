package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// httpFront 只处理需要本进程接管的明文 HTTP：健康检查、node API 与静态伪装页。
//
// inbound 的路径分流不在这里——它在 L4 阶段就已经完成并裸转发走了（见
// frontListener.httpUpstream）。这是与原先 Caddy 的关键差别：那套方案里
// ws/xhttp 走的是 Caddy 的 HTTP handler，升级之后退化成用户态 io.CopyBuffer；
// 下沉到 L4 之后主流量能走内核 splice。
type httpFront struct {
	siteDir   string
	nodeProxy *httputil.ReverseProxy
}

func newHTTPFront(nodePort int, siteDir, panelSNI string) *httpFront {
	// node API 走 HTTPS。SNI_VERIFICATION 开启时 node 会校验上游 SNI，所以要
	// 把派生的 panel SNI 带上；节点证书通常是自签的，跳过校验是既有行为
	// （原来 Caddyfile 里写的就是 tls_insecure_skip_verify）。
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         panelSNI,
		},
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     60 * time.Second,
	}
	return &httpFront{
		siteDir:   siteDir,
		nodeProxy: newProxy("https://"+hostPort(nodePort), transport),
	}
}

func (h *httpFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/health":
		_, _ = io.WriteString(w, "ok")

	case strings.HasPrefix(r.URL.Path, "/node/"), strings.HasPrefix(r.URL.Path, "/vision/"):
		h.nodeProxy.ServeHTTP(w, r)

	default:
		h.serveStatic(w, r)
	}
}

func (h *httpFront) serveStatic(w http.ResponseWriter, r *http.Request) {
	if h.siteDir == "" {
		http.NotFound(w, r)
		return
	}
	// 静态页只服务读取类方法，其余明确的写方法不该拿到 HTML。
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dir := http.Dir(h.siteDir)
	if h.serveFile(w, r, dir, r.URL.Path) {
		return
	}
	// 复刻原先 Caddyfile 里的 `try_files {path} {path}/ /index.html`：路径不存在
	// 时落到首页，这样任意 URL 看起来都是一个正常的静态站点——伪装页面如果对
	// 未知路径回 404，本身就是一种可识别的指纹。
	if !h.serveFile(w, r, dir, "/index.html") {
		http.NotFound(w, r)
	}
}

// serveFile 直接把文件内容吐出去，返回是否成功。
//
// 刻意不用 http.FileServer：它会把以 /index.html 结尾的 URL 301 重定向到 ./，
// 而原先 Caddy 的 try_files 是原样返回的——从 Caddy 迁过来的行为不该在这里变。
// http.Dir.Open 自带目录穿越防护，所以路径检查不必自己再做一遍。
func (h *httpFront) serveFile(w http.ResponseWriter, r *http.Request, dir http.Dir, name string) bool {
	file, err := dir.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil || info.IsDir() {
		return false
	}
	seeker, ok := file.(io.ReadSeeker)
	if !ok {
		return false
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), seeker)
	return true
}

func newProxy(target string, transport http.RoundTripper) *httputil.ReverseProxy {
	parsed, err := url.Parse(target)
	if err != nil {
		// target 由本进程用整数端口拼出，走到这里说明代码有 bug。
		panic("front: 非法的上游地址 " + target + ": " + err.Error())
	}
	proxy := httputil.NewSingleHostReverseProxy(parsed)
	proxy.Transport = transport
	proxy.ErrorLog = log.Default()
	// 保活转发：xhttp/ws 是长连接，缓冲会让延迟变得不可控。
	proxy.FlushInterval = -1
	return proxy
}

func hostPort(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}
