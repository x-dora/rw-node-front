// Command frontproxy 是 rw-node 的前置分流进程，取代原先的 Caddy + inbound
// watcher 组合。
//
// 在一个对外端口上按连接首字节分流：
//
//	"SSH-" 前缀              -> sshd-lite
//	TLS (0x16)               -> 按 SNI 转到 REALITY inbound，其余转 node API
//	明文 HTTP                -> 按路径裸转发到 inbound 端口；
//	                            健康检查、node API、静态伪装页由本进程处理
//
// 与 Caddy 方案的关键差别在转发形态：直通路径把两个未被包装的 *net.TCPConn
// 交给 io.Copy，在 Linux 上命中内核 splice，数据不进用户态。Caddy 的 layer4
// 会把连接包装一层，ReadFrom 快路径失效，实测每个字节都要走一遍用户态
// read/write（见 bench/forward 与相关实测记录）。
package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type config struct {
	listenHost   string
	frontPort    int
	nodePort     int
	internalPort int
	xhttpPort    int
	wsPort       int
	sshPort      int
	sshEnabled   bool
	siteDir      string
	secretKey    string
	pollInterval time.Duration
}

// version 由 release 构建通过 -ldflags "-X main.version=..." 注入，本地构建为 dev。
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("[frontproxy] ")

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	log.Printf("rw-node-front %s", version)

	panelSNI, err := derivePanelSNI(cfg.secretKey)
	if err != nil {
		// 派生失败不该阻断启动：它只影响 node API 的上游 SNI 与 Panel 门控，
		// 拿不到时退回「无 SNI」行为即可。
		log.Printf("WARN: 无法从 SECRET_KEY 派生 panel SNI: %v", err)
		panelSNI = ""
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	source := newConfigSource(internalBaseURL(cfg.internalPort), cfg.pollInterval, panelSNI)
	go source.Run(ctx)

	front := newFrontListener(
		cfg.nodePort, cfg.sshPort, cfg.sshEnabled, cfg.xhttpPort, cfg.wsPort,
		source, newHTTPFront(cfg.nodePort, cfg.siteDir, panelSNI),
	)

	addr := net.JoinHostPort(cfg.listenHost, strconv.Itoa(cfg.frontPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", addr, err)
	}

	log.Printf("front proxy 监听 %s", addr)
	log.Printf("node=%d internal=%d xhttp=%d ws=%d ssh=%v(port=%d) 轮询间隔=%s",
		cfg.nodePort, cfg.internalPort, cfg.xhttpPort, cfg.wsPort,
		cfg.sshEnabled, cfg.sshPort, cfg.pollInterval)
	log.Printf("静态伪装页目录: %s", cfg.siteDir)

	go func() {
		if err := front.Serve(ln); err != nil {
			log.Printf("serve 结束: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("收到退出信号，停止监听")
	_ = ln.Close()
}

func loadConfig() (config, error) {
	// HTTP_FRONT_PORT 缺省时跟随 PaaS 下发的 PORT，与原先 lib/core.sh 的
	// `HTTP_FRONT_PORT="${PORT:-3000}"` 保持一致。
	frontPort := envPort("HTTP_FRONT_PORT", 0)
	if frontPort == 0 {
		frontPort = envPort("PORT", 3000)
	}

	siteDir := envString("FRONT_SITE_DIR", "")
	if siteDir == "" {
		// 兼容改造前的变量名，避免老部署升级后静态页凭空消失。
		siteDir = envString("CADDY_SITE_DIR", "")
	}

	cfg := config{
		listenHost:   envString("HTTP_FRONT_HOST", "0.0.0.0"),
		frontPort:    frontPort,
		nodePort:     envPort("NODE_PORT", 2222),
		internalPort: envPort("INTERNAL_REST_PORT", 61001),
		xhttpPort:    envPort("XHTTP_UPSTREAM_PORT", 8080),
		wsPort:       envPort("WS_UPSTREAM_PORT", 8880),
		sshPort:      envPort("SSH_PORT", 22222),
		sshEnabled:   envBool("SSH_ENABLED", false),
		siteDir:      siteDir,
		secretKey:    strings.TrimSpace(os.Getenv("SECRET_KEY")),
		// 复用既有的 INBOUND_WATCHER_INTERVAL：它描述的本来就是「多久拉一次
		// inbound 配置」，与用什么实现无关。
		pollInterval: envDuration("INBOUND_WATCHER_INTERVAL", 15*time.Second),
	}

	if cfg.frontPort == cfg.nodePort {
		log.Printf("WARN: HTTP_FRONT_PORT 与 NODE_PORT 相同(%d)，前置分流会与自己循环", cfg.frontPort)
	}
	if cfg.sshEnabled && cfg.sshPort == cfg.frontPort {
		log.Printf("WARN: SSH_PORT 与 HTTP_FRONT_PORT 相同(%d)，SSH 转发会打回自己", cfg.sshPort)
		cfg.sshEnabled = false
	}
	return cfg, nil
}

func internalBaseURL(port int) string {
	return "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func envString(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envPort(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		log.Printf("WARN: %s=%q 不是合法端口，改用 %d", key, raw, fallback)
		return fallback
	}
	return n
}

func envBool(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "":
		return fallback
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		log.Printf("WARN: %s=%q 不是布尔值，改用 %v", key, os.Getenv(key), fallback)
		return fallback
	}
}

// envDuration 接受纯秒数（沿用 INBOUND_WATCHER_INTERVAL 原有的写法）或 Go
// duration 字符串；非法值退回默认并告警，而不是让进程起不来。
func envDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		if secs <= 0 {
			log.Printf("WARN: %s=%q 必须为正，改用 %s", key, raw, fallback)
			return fallback
		}
		return time.Duration(secs) * time.Second
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d
	}
	log.Printf("WARN: %s=%q 无法解析，改用 %s", key, raw, fallback)
	return fallback
}
