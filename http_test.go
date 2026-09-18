package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeStaticFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func serveStatic(t *testing.T, dir, path, method string) *httptest.ResponseRecorder {
	t.Helper()
	front := newHTTPFront(2222, dir, "")
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	front.ServeHTTP(rec, req)
	return rec
}

// 复刻原先 Caddyfile 的 `try_files {path} {path}/ /index.html`：真实存在的文件
// 按原样返回，其余一律落到首页。
func TestStaticFallsBackToIndexForUnknownPaths(t *testing.T) {
	dir := t.TempDir()
	writeStaticFile(t, dir, "index.html", "<html>HOME</html>")
	writeStaticFile(t, dir, "asset.txt", "ASSET-CONTENT")

	cases := []struct {
		path string
		want string
	}{
		{"/", "HOME"},
		{"/index.html", "HOME"},
		{"/asset.txt", "ASSET-CONTENT"},
		// 伪装页面如果对未知路径回 404，本身就是个可识别的指纹。
		{"/no-such-path", "HOME"},
		{"/deep/nested/path", "HOME"},
		{"/foobar.html", "HOME"},
	}
	for _, tc := range cases {
		rec := serveStatic(t, dir, tc.path, http.MethodGet)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200", tc.path, rec.Code)
		}
		if body := rec.Body.String(); !contains(body, tc.want) {
			t.Fatalf("GET %s: body = %q, want it to contain %q", tc.path, body, tc.want)
		}
	}
}

// 目录穿越不能读到站点目录之外的内容。
func TestStaticRejectsDirectoryTraversal(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "site")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeStaticFile(t, dir, "index.html", "<html>HOME</html>")
	writeStaticFile(t, parent, "secret.txt", "TOP-SECRET")

	rec := serveStatic(t, dir, "/../secret.txt", http.MethodGet)
	if contains(rec.Body.String(), "TOP-SECRET") {
		t.Fatalf("目录穿越读到了站点外的文件: %q", rec.Body.String())
	}
}

func TestStaticRejectsWriteMethods(t *testing.T) {
	dir := t.TempDir()
	writeStaticFile(t, dir, "index.html", "<html>HOME</html>")

	rec := serveStatic(t, dir, "/", http.MethodPost)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /: status = %d, want 405", rec.Code)
	}
}

// 没有配置静态目录时不该伪造首页。
func TestStaticWithoutSiteDirReturns404(t *testing.T) {
	rec := serveStatic(t, "", "/", http.MethodGet)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	front := newHTTPFront(2222, "", "")
	rec := httptest.NewRecorder()
	front.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("status = %d, body = %q, want 200 ok", rec.Code, rec.Body.String())
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
