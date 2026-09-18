package main

import (
	"testing"
	"time"
)

var configEnvKeys = []string{
	"HTTP_FRONT_HOST", "HTTP_FRONT_PORT", "PORT", "NODE_PORT", "INTERNAL_REST_PORT",
	"XHTTP_UPSTREAM_PORT", "WS_UPSTREAM_PORT", "SSH_PORT", "SSH_ENABLED",
	"FRONT_SITE_DIR", "CADDY_SITE_DIR", "SECRET_KEY", "INBOUND_WATCHER_INTERVAL",
}

func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range configEnvKeys {
		t.Setenv(key, "")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	clearConfigEnv(t)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.frontPort != 3000 {
		t.Fatalf("frontPort = %d, want 3000", cfg.frontPort)
	}
	if cfg.nodePort != 2222 {
		t.Fatalf("nodePort = %d, want 2222", cfg.nodePort)
	}
	if cfg.internalPort != 61001 {
		t.Fatalf("internalPort = %d, want 61001", cfg.internalPort)
	}
	if cfg.xhttpPort != 8080 || cfg.wsPort != 8880 {
		t.Fatalf("上游端口 = %d/%d, want 8080/8880", cfg.xhttpPort, cfg.wsPort)
	}
	if cfg.sshEnabled {
		t.Fatal("SSH 默认应关闭")
	}
	if cfg.pollInterval != 15*time.Second {
		t.Fatalf("pollInterval = %s, want 15s", cfg.pollInterval)
	}
}

// HTTP_FRONT_PORT 缺省时跟随 PaaS 下发的 PORT，与原先 core.sh 的
// `HTTP_FRONT_PORT="${PORT:-3000}"` 一致。
func TestLoadConfigFrontPortFallsBackToPORT(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("PORT", "8081")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.frontPort != 8081 {
		t.Fatalf("frontPort = %d, want 8081 (来自 PORT)", cfg.frontPort)
	}

	t.Setenv("HTTP_FRONT_PORT", "9999")
	cfg, err = loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.frontPort != 9999 {
		t.Fatalf("frontPort = %d, want 9999 (HTTP_FRONT_PORT 优先)", cfg.frontPort)
	}
}

// 静态页目录兼容改造前的 CADDY_SITE_DIR，避免老部署升级后伪装页消失。
func TestLoadConfigSiteDirFallback(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("CADDY_SITE_DIR", "/opt/rw-node/www")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.siteDir != "/opt/rw-node/www" {
		t.Fatalf("siteDir = %q, want 从 CADDY_SITE_DIR 回退", cfg.siteDir)
	}

	t.Setenv("FRONT_SITE_DIR", "/srv/site")
	cfg, err = loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.siteDir != "/srv/site" {
		t.Fatalf("siteDir = %q, want FRONT_SITE_DIR 优先", cfg.siteDir)
	}
}

// SSH_PORT 与前置端口撞上时必须关掉 SSH：否则转发会打回自己形成环。
func TestLoadConfigDisablesSSHWhenPortCollidesWithFront(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("SSH_ENABLED", "true")
	t.Setenv("HTTP_FRONT_PORT", "3066")
	t.Setenv("SSH_PORT", "3066")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.sshEnabled {
		t.Fatal("SSH_PORT 与 HTTP_FRONT_PORT 相同时应关闭 SSH 转发")
	}

	t.Setenv("SSH_PORT", "22222")
	cfg, err = loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.sshEnabled {
		t.Fatal("端口不冲突时 SSH 应保持开启")
	}
}

func TestEnvPort(t *testing.T) {
	cases := []struct {
		raw      string
		fallback int
		want     int
	}{
		{"", 1234, 1234},
		{"8080", 1234, 8080},
		{"1", 1234, 1},
		{"65535", 1234, 65535},
		{"0", 1234, 1234},
		{"65536", 1234, 1234},
		{"-1", 1234, 1234},
		{"abc", 1234, 1234},
		{"  ", 1234, 1234},
	}
	for _, tc := range cases {
		t.Setenv("TEST_PORT", tc.raw)
		if got := envPort("TEST_PORT", tc.fallback); got != tc.want {
			t.Fatalf("envPort(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestEnvBool(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"true":  true,
		"TRUE":  true,
		"1":     true,
		"yes":   true,
		"on":    true,
		"false": false,
		"0":     false,
		"no":    false,
		"off":   false,
	}
	for raw, want := range cases {
		t.Setenv("TEST_BOOL", raw)
		if got := envBool("TEST_BOOL", false); got != want {
			t.Fatalf("envBool(%q) = %v, want %v", raw, got, want)
		}
	}
	// 无法识别时退回默认值，且默认值本身要生效。
	t.Setenv("TEST_BOOL", "maybe")
	if got := envBool("TEST_BOOL", true); !got {
		t.Fatal("非法布尔值应退回默认值 true")
	}
}

func TestEnvDuration(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", 15 * time.Second},
		{"30", 30 * time.Second},
		{"2m", 2 * time.Minute},
		{"1h30m", 90 * time.Minute},
		{"0", 15 * time.Second},
		{"-5", 15 * time.Second},
		{"abc", 15 * time.Second},
	}
	for _, tc := range cases {
		t.Setenv("TEST_DURATION", tc.raw)
		if got := envDuration("TEST_DURATION", 15*time.Second); got != tc.want {
			t.Fatalf("envDuration(%q) = %s, want %s", tc.raw, got, tc.want)
		}
	}
}
