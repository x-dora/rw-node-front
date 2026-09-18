package main

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// sniTLDs mirrors the official decode-servername.util.ts TLDS list, and must
// stay byte-identical to rw-node-go's internal/httpapi.sniTLDs: the SNI here has
// to match the certificate the node presents, or the Panel-gated L4 route
// silently stops matching after a node upgrade.
var sniTLDs = []string{"com", "net", "org", "io", "dev", "app"}

type nodePayload struct {
	CACertPEM    string `json:"caCertPem"`
	JWTPublicKey string `json:"jwtPublicKey"`
	NodeCertPEM  string `json:"nodeCertPem"`
	NodeKeyPEM   string `json:"nodeKeyPem"`
}

// derivePanelSNI 复刻 rw-node-go 的 internal/httpapi.DeriveSNI，让前置分流不再
// 依赖 /internal/get-config 注入的 panelSni 字段。
//
// 派生链：SECRET_KEY 是 base64(JSON)，取其中的 jwtPublicKey 与 caCertPem，
// 各自经 normalizePEM 与 canonBase64 归一，拼接后做
// HKDF-SHA256(salt 为空, info="rw-v1", 22 字节)，产出
// <16 字节 hex>.<5 字节 hex>.<TLD>。
//
// normalizePEM 不能省。虽然它做的只是空白处理，但 canonBase64 是按「真换行」
// 分行、再把以 ----- 开头的整行当 PEM 头丢掉的：PEM 里写成字面 `\n`（反斜杠
// 加 n）而未经归一的话，整个字符串里没有真换行，会被当成单行 PEM 头整行丢
// 弃，canonBase64 直接返回空串，SNI 随之变成另一个值。
//
// 返回空字符串表示无法派生（SECRET_KEY 未设置或不可解析）。调用方应把空值
// 当作「不做 SNI 门控」而不是错误：SECRET_KEY 缺失时节点本来就没有证书。
func derivePanelSNI(secretKey string) (string, error) {
	secretKey = strings.TrimSpace(secretKey)
	if secretKey == "" {
		return "", nil
	}

	raw, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return "", fmt.Errorf("decode SECRET_KEY: %w", err)
	}

	var payload nodePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("parse SECRET_KEY payload: %w", err)
	}
	if payload.CACertPEM == "" || payload.JWTPublicKey == "" {
		return "", fmt.Errorf("SECRET_KEY payload missing caCertPem or jwtPublicKey")
	}

	ikm := canonBase64(normalizePEM(payload.JWTPublicKey)) + canonBase64(normalizePEM(payload.CACertPEM))
	okm, err := hkdf.Key(sha256.New, []byte(ikm), nil, "rw-v1", 22)
	if err != nil {
		return "", fmt.Errorf("derive sni: %w", err)
	}

	host := hex.EncodeToString(okm[0:16])
	label := hex.EncodeToString(okm[16:21])
	tld := sniTLDs[int(okm[21])%len(sniTLDs)]
	return host + "." + label + "." + tld, nil
}

// normalizePEM 与 rw-node-go 的 config.NormalizePEM 逐字节一致：把字面 `\n`
// 和 CRLF 都转成换行，逐行 trim，连续空行折叠成一个，最后去掉首尾空白。
func normalizePEM(value string) string {
	value = strings.ReplaceAll(value, `\n`, "\n")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.TrimSpace(value)

	lines := strings.Split(value, "\n")
	normalized := make([]string, 0, len(lines))
	lastBlank := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			if !lastBlank {
				normalized = append(normalized, "")
			}
			lastBlank = true
			continue
		}
		normalized = append(normalized, line)
		lastBlank = false
	}
	return strings.TrimSpace(strings.Join(normalized, "\n"))
}

// canonBase64 mirrors the official canon helper (and rw-node-go's): drop PEM
// header/footer markers and keep only base64 characters.
func canonBase64(pemValue string) string {
	var builder strings.Builder
	for _, line := range strings.Split(pemValue, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----") {
			continue
		}
		for _, c := range line {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
				builder.WriteRune(c)
			}
		}
	}
	return builder.String()
}
