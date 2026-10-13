// Command jwksgen 生成 gateway/internal/grpcwire/testdata/jwks/ 下的**合成**一致性夹具
// （第二十轮 O3）。
//
// 安全约束（务必保持）：
//   - 本程序在**内存中**生成 RSA 私钥，只把**公钥部分**（JWK 的 n/e）与**已签名令牌**
//     写入磁盘；私钥在进程退出时随内存丢弃，**永不落盘**；
//   - 令牌是合成样本（issuer/audience 均为 .invalid 域名），不对应任何真实身份提供商；
//   - 生成物中不得出现 PEM 私钥标记（有测试断言）。
//
// 运行方式（在仓库根目录）：
//
//	go run ./gateway/internal/grpcwire/testdata/jwks/gen
//
// 该目录位于 testdata/ 之下，`go build ./...` 与 `go test ./...` 的包匹配不会包含它。
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// 合成样本的固定声明（不对应任何真实 issuer）。
const (
	fixtureIssuer   = "https://fixtures.invalid/issuer"
	fixtureAudience = "agent-ops-gateway"
	fixtureSubject  = "fixture-operator"
	// 固定时间戳：exp 远未来、nbf 过去，保证在任何合理的测试时钟下都有效。
	fixtureExp = 2000000000 // 2033-05-18
	fixtureNbf = 1700000000 // 2023-11-14
)

// outDir 输出目录（相对本文件的执行工作目录 = 仓库根）。
const outDir = "gateway/internal/grpcwire/testdata/jwks"

// keyPair 一对合成密钥。
type keyPair struct {
	kid string
	key *rsa.PrivateKey
}

// newKey 生成一把 RSA 2048 合成密钥。
func newKey(kid string) keyPair {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("生成密钥失败：%v", err)
	}
	return keyPair{kid: kid, key: k}
}

// jwk 把公钥转为 JWK（只含公开参数）。
func jwk(kp keyPair) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": kp.kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(kp.key.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
}

// jwksDoc 构造 JWKS 文档。
func jwksDoc(keys ...map[string]any) []byte {
	doc := map[string]any{"keys": keys}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		log.Fatalf("序列化 JWKS 失败：%v", err)
	}
	return append(b, '\n')
}

// signToken 用给定密钥签发 RS256 令牌（aud 可为字符串或数组）。
func signToken(kp keyPair, aud any) string {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kp.kid}
	claims := map[string]any{
		"iss": fixtureIssuer,
		"sub": fixtureSubject,
		"aud": aud,
		"iat": fixtureNbf,
		"nbf": fixtureNbf,
		"exp": fixtureExp,
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, kp.key, crypto.SHA256, sum[:])
	if err != nil {
		log.Fatalf("签名失败：%v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// write 写文件（0600）。
func write(name string, data []byte) {
	path := filepath.Join(outDir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		log.Fatalf("写 %s 失败：%v", path, err)
	}
	fmt.Printf("已写入 %s（%d 字节）\n", path, len(data))
}

func main() {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatalf("创建目录失败：%v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_ = now

	// —— ① 多密钥（3 个 RSA 公钥，不同 kid）——
	k1, k2, k3 := newKey("mk-1"), newKey("mk-2"), newKey("mk-3")
	write("multi-key.jwks.json", jwksDoc(jwk(k1), jwk(k2), jwk(k3)))
	write("multi-key.token.txt", []byte(signToken(k2, fixtureAudience))) // 由第 2 把密钥签发

	// —— ② kid 轮换（旧 kid 与新 kid 并存）——
	oldK, newK := newKey("rot-old"), newKey("rot-new")
	write("kid-rotation.jwks.json", jwksDoc(jwk(oldK), jwk(newK)))
	write("kid-rotation.old.token.txt", []byte(signToken(oldK, fixtureAudience)))
	write("kid-rotation.new.token.txt", []byte(signToken(newK, fixtureAudience)))

	// —— ③ 带 x5c 字段（解析时忽略 x5c，不影响校验）——
	x5cK := newKey("x5c-1")
	x5cJWK := jwk(x5cK)
	// 合成的 x5c 值：不是真实证书链，只用于验证解析器忽略该字段。
	x5cJWK["x5c"] = []string{"ZmFrZS1jZXJ0aWZpY2F0ZS1ub3QtcmVhbA=="}
	x5cJWK["x5t"] = "ZmFrZS10aHVtYnByaW50"
	write("with-x5c.jwks.json", jwksDoc(x5cJWK))
	write("with-x5c.token.txt", []byte(signToken(x5cK, fixtureAudience)))

	// —— ④ aud 为数组的令牌样本 ——
	audK := newKey("aud-arr-1")
	write("aud-array.jwks.json", jwksDoc(jwk(audK)))
	write("aud-array.token.txt", []byte(signToken(audK, []string{"other-service", fixtureAudience})))

	fmt.Println("完成：所有夹具只含公钥与合成令牌，私钥未落盘。")
}
