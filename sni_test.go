package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

// 这些 golden 值是用 rw-node-go 的 internal/httpapi.DeriveSNI 对同样的
// SECRET_KEY 算出来的。它们是对齐锚点：一旦两边的派生逻辑漂移，SNI 会和节点
// 证书不匹配，SNI_VERIFICATION 开启时的 Panel L4 路由会静默失效。
const (
	goldenSameInputSNI = "ae0c1b1816d00ffe827c5cf934a0d185.321ef5662d.net"
	goldenOtherSNI     = "dc7ff42a9d049d7a5bb8cbedffd50097.9f3b783da0.app"
)

func encodeSecret(t *testing.T, payloadJSON string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString([]byte(payloadJSON))
}

// 同一个载荷用四种 PEM 书写形式表达，SNI 必须完全一致。`literal-backslash-n`
// 这个变体是重点：PEM 里写成字面 `\n` 时整串没有真换行，canonBase64 会把它
// 当成单行 PEM 头整行丢弃、返回空串，SNI 随之变成另一个值——只有先过
// normalizePEM 才会和其他形式对齐。这条测试钉的就是这一步。
func TestDerivePanelSNIIsIndependentOfPEMFormatting(t *testing.T) {
	cases := map[string]string{
		"lf": `{"caCertPem":"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",` +
			`"jwtPublicKey":"-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----",` +
			`"nodeCertPem":"x","nodeKeyPem":"y"}`,

		"crlf": `{"caCertPem":"-----BEGIN CERTIFICATE-----\r\nAAAA\r\n-----END CERTIFICATE-----",` +
			`"jwtPublicKey":"-----BEGIN PUBLIC KEY-----\r\nBBBB\r\n-----END PUBLIC KEY-----",` +
			`"nodeCertPem":"x","nodeKeyPem":"y"}`,

		// JSON 里的 \\n 解码后是字面的反斜杠加 n，正好触发 NormalizePEM 的
		// 字面量替换分支。
		"literal-backslash-n": `{"caCertPem":"-----BEGIN CERTIFICATE-----\\nAAAA\\n-----END CERTIFICATE-----",` +
			`"jwtPublicKey":"-----BEGIN PUBLIC KEY-----\\nBBBB\\n-----END PUBLIC KEY-----",` +
			`"nodeCertPem":"x","nodeKeyPem":"y"}`,

		"blank-lines-and-indent": `{"caCertPem":"  -----BEGIN CERTIFICATE-----\n\n    AAAA   \n\n\n-----END CERTIFICATE-----  ",` +
			`"jwtPublicKey":"\n-----BEGIN PUBLIC KEY-----\n  BBBB\n-----END PUBLIC KEY-----\n",` +
			`"nodeCertPem":"x","nodeKeyPem":"y"}`,
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			sni, err := derivePanelSNI(encodeSecret(t, payload))
			if err != nil {
				t.Fatalf("derivePanelSNI: %v", err)
			}
			if sni != goldenSameInputSNI {
				t.Fatalf("sni = %q, want %q", sni, goldenSameInputSNI)
			}
		})
	}
}

// 对照组：不同的载荷必须产出不同的 SNI，否则上面的测试可能只是恒等函数。
func TestDerivePanelSNIChangesWithPayload(t *testing.T) {
	payload := `{"caCertPem":"-----BEGIN CERTIFICATE-----\nZZZZ\n-----END CERTIFICATE-----",` +
		`"jwtPublicKey":"-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----",` +
		`"nodeCertPem":"x","nodeKeyPem":"y"}`

	sni, err := derivePanelSNI(encodeSecret(t, payload))
	if err != nil {
		t.Fatalf("derivePanelSNI: %v", err)
	}
	if sni != goldenOtherSNI {
		t.Fatalf("sni = %q, want %q", sni, goldenOtherSNI)
	}
	if sni == goldenSameInputSNI {
		t.Fatal("different payloads produced the same SNI")
	}
}

func TestDerivePanelSNIShape(t *testing.T) {
	payload := `{"caCertPem":"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",` +
		`"jwtPublicKey":"-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----",` +
		`"nodeCertPem":"x","nodeKeyPem":"y"}`

	sni, err := derivePanelSNI(encodeSecret(t, payload))
	if err != nil {
		t.Fatalf("derivePanelSNI: %v", err)
	}
	parts := strings.Split(sni, ".")
	if len(parts) != 3 {
		t.Fatalf("sni = %q, want <host>.<label>.<tld>", sni)
	}
	if len(parts[0]) != 32 {
		t.Fatalf("host = %q, want 32 hex chars", parts[0])
	}
	if len(parts[1]) != 10 {
		t.Fatalf("label = %q, want 10 hex chars", parts[1])
	}
	found := false
	for _, tld := range sniTLDs {
		if parts[2] == tld {
			found = true
		}
	}
	if !found {
		t.Fatalf("tld = %q, not in %v", parts[2], sniTLDs)
	}
}

// SECRET_KEY 缺失是正常配置（节点没有证书），必须退化成空 SNI 而不是错误。
func TestDerivePanelSNIEmptySecretKey(t *testing.T) {
	for _, secretKey := range []string{"", "   ", "\n"} {
		sni, err := derivePanelSNI(secretKey)
		if err != nil {
			t.Fatalf("derivePanelSNI(%q) returned error: %v", secretKey, err)
		}
		if sni != "" {
			t.Fatalf("derivePanelSNI(%q) = %q, want empty", secretKey, sni)
		}
	}
}

func TestDerivePanelSNIRejectsMalformedSecretKey(t *testing.T) {
	cases := map[string]string{
		"not-base64":    "!!!not base64!!!",
		"not-json":      base64.StdEncoding.EncodeToString([]byte("plain text")),
		"missing-ca":    base64.StdEncoding.EncodeToString([]byte(`{"jwtPublicKey":"BBBB","nodeCertPem":"x","nodeKeyPem":"y"}`)),
		"missing-jwt":   base64.StdEncoding.EncodeToString([]byte(`{"caCertPem":"AAAA","nodeCertPem":"x","nodeKeyPem":"y"}`)),
		"empty-payload": base64.StdEncoding.EncodeToString([]byte(`{}`)),
	}

	for name, secretKey := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := derivePanelSNI(secretKey); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}
