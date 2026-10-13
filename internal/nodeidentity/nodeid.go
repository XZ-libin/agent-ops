// Package nodeidentity 承载节点**身份建立**的纯逻辑（第二十一轮 N2/N3/N4）。
//
// 本轮范围（见 ADR-020）：只做设计 + 纯单元部分。本包不依赖数据库、不依赖网络，
// 全部输入（时钟、随机源）可注入，因此可在无 CI 的环境下完整单测。
//
// 三个关注点：
//   - nodeid.go：权威身份 `nod_<ULID>` 的生成与校验（ULID 自实现，无第三方依赖）；
//   - token.go：一次性注册令牌（只保存 SHA-256 哈希、15 分钟有效期、用后即失效）；
//   - ca.go：**测试** CA 的生成、CSR 校验与签发、mTLS 客户端证书校验与身份绑定。
//
// 安全约束：私钥只在内存中生成与持有，**不落盘、不提交**；错误信息不携带令牌明文、
// 私钥或 CSR 原文。
package nodeidentity

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// NodeIDPrefix 权威身份前缀（第二十一轮裁决：nod_<ULID>）。
const NodeIDPrefix = "nod_"

// ulidLen ULID 字符串长度（26 个 Crockford Base32 字符）。
const ulidLen = 26

// ErrBadNodeID 身份格式非法。
var ErrBadNodeID = errors.New("nodeidentity：节点身份格式非法（应为 nod_<26 位 Crockford Base32 ULID>）")

// NewNodeID 用给定时刻与随机源生成权威身份 `nod_<ULID>`。
//
// D5：ULID 生成改用 **github.com/oklog/ulid/v2**（经过广泛使用），
// 不再自研——标识符不值得自研，位序/编码错误代价高。
// randReader 为 nil 时使用 crypto/rand。
func NewNodeID(now time.Time, randReader io.Reader) (string, error) {
	r := randReader
	if r == nil {
		r = rand.Reader
	}
	id, err := ulid.New(ulid.Timestamp(now.UTC()), r)
	if err != nil {
		return "", fmt.Errorf("nodeidentity：生成节点身份失败：%w", err)
	}
	return NodeIDPrefix + id.String(), nil
}

// ValidateNodeID 校验身份格式：
//   - 必须带 `nod_` 前缀；
//   - 后接恰好 26 个字符；
//   - 必须为**大写** Crockford Base32（拒绝小写与大小写混合，避免同一身份多种写法）；
//   - 必须能被 oklog/ulid 解析（拒绝非法字符，含 I/L/O/U）。
func ValidateNodeID(id string) error {
	body, err := splitNodeID(id)
	if err != nil {
		return err
	}
	if body != strings.ToUpper(body) {
		return ErrBadNodeID // 拒绝小写 / 大小写混合
	}
	if _, perr := ulid.Parse(body); perr != nil {
		return ErrBadNodeID
	}
	return nil
}

// NodeIDTime 从身份中解析出生成时刻（毫秒精度）。
func NodeIDTime(id string) (time.Time, error) {
	body, err := splitNodeID(id)
	if err != nil {
		return time.Time{}, err
	}
	parsed, perr := ulid.Parse(body)
	if perr != nil {
		return time.Time{}, ErrBadNodeID
	}
	return time.UnixMilli(int64(parsed.Time())).UTC(), nil
}

// splitNodeID 校验前缀与长度，返回 ULID 主体（不含前缀）。
func splitNodeID(id string) (string, error) {
	if !strings.HasPrefix(id, NodeIDPrefix) {
		return "", ErrBadNodeID
	}
	body := id[len(NodeIDPrefix):]
	if len(body) != ulidLen {
		return "", ErrBadNodeID
	}
	return body, nil
}
