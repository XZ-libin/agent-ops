package nodeidentity

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fixedNow 测试固定时钟（注入，不使用真实时间）。
var fixedNow = time.Unix(1791825000, 0).UTC()

// TestNodeIDFormatAndRoundTrip（N3）身份格式 nod_<ULID>：26 位 Crockford Base32，
// 可回解出生成时刻；非法形态一律拒绝。
func TestNodeIDFormatAndRoundTrip(t *testing.T) {
	id, err := NewNodeID(fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, NodeIDPrefix) {
		t.Fatalf("身份必须带 %q 前缀：%q", NodeIDPrefix, id)
	}
	body := strings.TrimPrefix(id, NodeIDPrefix)
	if len(body) != 26 {
		t.Fatalf("ULID 部分应为 26 字符，实际 %d：%q", len(body), body)
	}
	if err := ValidateNodeID(id); err != nil {
		t.Fatalf("生成的身份应通过校验：%v", err)
	}
	// 时间戳可回解（毫秒精度）。
	got, err := NodeIDTime(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.UnixMilli() != fixedNow.UnixMilli() {
		t.Fatalf("回解时间不符：want=%d got=%d", fixedNow.UnixMilli(), got.UnixMilli())
	}
	// 唯一性（同一毫秒内两次生成也不同：随机部分不同）。
	id2, err := NewNodeID(fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id == id2 {
		t.Fatal("两次生成的身份不得相同")
	}
	// 非法形态（D5 拒绝用例：非法字符 / 长度错误 / 缺前缀 / 大小写混合）。
	// 注意：26 个 '0' 是**结构合法**的 ULID（仅时间戳为纪元 0），故不列入。
	for _, bad := range []string{
		"", "nod_", "nod_0123456789", // 长度不足
		"nod_" + strings.Repeat("0", 27),                                 // 长度过长
		strings.Repeat("0", 26),                                          // 缺少 nod_ 前缀
		"nod_" + strings.Repeat("Z", 26),                                 // 首位超出 ULID 允许范围
		"nod_01I3456789ABCDEFGHJKMNPQR",                                  // 非法字符 'I'（Crockford 剔除）
		"nod_01L3456789ABCDEFGHJKMNPQR",                                  // 非法字符 'L'
		"nod_01O3456789ABCDEFGHJKMNPQR",                                  // 非法字符 'O'
		"nod_01U3456789ABCDEFGHJKMNPQR",                                  // 非法字符 'U'
		id[:len(NodeIDPrefix)] + strings.ToLower(id[len(NodeIDPrefix):]), // ULID 主体全小写
		mixedCaseNodeID(id),                                              // 大小写混合（把主体中第一个**字母**改小写）
	} {
		if err := ValidateNodeID(bad); err == nil {
			t.Errorf("非法身份应被拒绝：%q", bad)
		}
	}
	// 大写 ULID 主体必须通过（回归：前缀保持小写）。
	upper := id[:len(NodeIDPrefix)] + strings.ToUpper(id[len(NodeIDPrefix):])
	if err := ValidateNodeID(upper); err != nil {
		t.Fatalf("大写 ULID 主体应通过：%v", err)
	}
	t.Logf("[N3] 身份格式正确：%s（26 位 Crockford Base32，可回解生成时刻 %s）", id, got.Format(time.RFC3339))
}

// mixedCaseNodeID 把身份主体中第一个**字母**改成小写（ULID 首位多为数字，
// 不能固定取下标 0，否则构造出的"非法值"可能与原值相同）。
func mixedCaseNodeID(id string) string {
	for i := len(NodeIDPrefix); i < len(id); i++ {
		if id[i] >= 'A' && id[i] <= 'Z' {
			return id[:i] + strings.ToLower(id[i:i+1]) + id[i+1:]
		}
	}
	return id
}

// TestEnrollTokenHappyPath（N3 ①）有效令牌注册成功：分配身份、令牌立即失效。
func TestEnrollTokenHappyPath(t *testing.T) {
	store := NewMemoryTokenStore()
	plain, _, err := GenerateToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := NewTokenRecord(plain, fixedNow)
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	// 记录里不得含明文（哈希是定长字节，不可能包含明文）。
	if strings.Contains(string(rec.Hash[:]), plain) {
		t.Fatal("记录不得包含令牌明文")
	}

	used, nodeID, err := Enroll(store, plain, fixedNow.Add(time.Minute), func() (string, error) {
		return NewNodeID(fixedNow, nil)
	})
	if err != nil {
		t.Fatalf("有效令牌应注册成功：%v", err)
	}
	if err := ValidateNodeID(nodeID); err != nil {
		t.Fatalf("分配的身份应合法：%v", err)
	}
	if used.UsedAt.IsZero() || used.UsedByNodeID != nodeID {
		t.Fatalf("令牌应被标记为已用并绑定身份：%+v", used)
	}
	t.Logf("[N3①] 注册成功：node_id=%s，令牌已置为已用（UsedByNodeID 一致）", nodeID)
}

// TestEnrollTokenReuseRejected（N3 ②）令牌重复使用被拒绝。
func TestEnrollTokenReuseRejected(t *testing.T) {
	store := NewMemoryTokenStore()
	plain, _, _ := GenerateToken(nil)
	if err := store.Put(NewTokenRecord(plain, fixedNow)); err != nil {
		t.Fatal(err)
	}
	alloc := func() (string, error) { return NewNodeID(fixedNow, nil) }
	if _, _, err := Enroll(store, plain, fixedNow, alloc); err != nil {
		t.Fatalf("首次注册应成功：%v", err)
	}
	_, _, err := Enroll(store, plain, fixedNow.Add(time.Second), alloc)
	if !errors.Is(err, ErrTokenRejected) {
		t.Fatalf("重复使用必须被拒绝（ErrTokenRejected），实际 %v", err)
	}
	// 内部原因应是 used（供审计），但对外错误同一。
	h := HashTokenOf(plain)
	rec, _ := store.Get(h)
	if oc, _ := CheckToken(rec, true, plain, fixedNow.Add(time.Second)); oc != OutcomeUsed {
		t.Fatalf("内部原因应为 used，实际 %s", oc)
	}
	t.Log("[N3②] 令牌重复使用被拒绝（对外错误统一为 ErrTokenRejected，内部原因 used）")
}

// TestEnrollTokenExpiredRejected（N3 ③）过期令牌被拒绝（15 分钟有效期，注入时钟）。
func TestEnrollTokenExpiredRejected(t *testing.T) {
	store := NewMemoryTokenStore()
	plain, _, _ := GenerateToken(nil)
	if err := store.Put(NewTokenRecord(plain, fixedNow)); err != nil {
		t.Fatal(err)
	}
	if TokenTTL != 15*time.Minute {
		t.Fatalf("令牌有效期应为 15 分钟，实际 %s", TokenTTL)
	}
	alloc := func() (string, error) { return NewNodeID(fixedNow, nil) }
	// 14 分 59 秒仍有效。
	if _, _, err := Enroll(store, plain, fixedNow.Add(14*time.Minute+59*time.Second), alloc); err != nil {
		t.Fatalf("有效期内应通过：%v", err)
	}
	// 另一枚令牌：刚好到期即拒绝。
	plain2, _, _ := GenerateToken(nil)
	if err := store.Put(NewTokenRecord(plain2, fixedNow)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Enroll(store, plain2, fixedNow.Add(TokenTTL), alloc); !errors.Is(err, ErrTokenRejected) {
		t.Fatalf("到期令牌必须被拒绝，实际 %v", err)
	}
	rec, _ := store.Get(HashTokenOf(plain2))
	if oc, _ := CheckToken(rec, true, plain2, fixedNow.Add(TokenTTL)); oc != OutcomeExpired {
		t.Fatalf("内部原因应为 expired，实际 %s", oc)
	}
	t.Log("[N3③] 有效期 15 分钟：14m59s 通过、到期即拒绝（内部原因 expired）")
}

// TestEnrollTokenWrongTokenNoLeak（N3 ④）错误令牌被拒绝且不泄露"哪一部分不匹配"。
func TestEnrollTokenWrongTokenNoLeak(t *testing.T) {
	store := NewMemoryTokenStore()
	good, _, _ := GenerateToken(nil)
	if err := store.Put(NewTokenRecord(good, fixedNow)); err != nil {
		t.Fatal(err)
	}
	// 构造若干"接近但不等于"的错误令牌。
	cases := map[string]string{
		"完全不同":  strings.Repeat("A", 43),
		"前缀相同":  good[:10] + strings.Repeat("B", len(good)-10),
		"少一个字符": good[:len(good)-1],
		"空串":    "",
	}
	alloc := func() (string, error) { return NewNodeID(fixedNow, nil) }
	for name, bad := range cases {
		_, _, err := Enroll(store, bad, fixedNow, alloc)
		if !errors.Is(err, ErrTokenRejected) {
			t.Fatalf("%s：必须被拒绝，实际 %v", name, err)
		}
		// 错误信息不得泄露令牌内容、长度差异或比较位置。
		msg := err.Error()
		for _, leak := range []string{bad, good, "hash", "length", "prefix", "字符"} {
			if leak != "" && strings.Contains(msg, leak) {
				t.Fatalf("%s：错误信息泄露了 %q：%q", name, leak, msg)
			}
		}
	}
	// 所有失败对外是同一个错误值。
	_, _, e1 := Enroll(store, cases["完全不同"], fixedNow, alloc)
	_, _, e2 := Enroll(store, cases["空串"], fixedNow, alloc)
	if e1.Error() != e2.Error() {
		t.Fatalf("不同失败原因的对外错误必须一致：%q vs %q", e1, e2)
	}
	t.Logf("[N3④] 4 类错误令牌均被拒绝，对外错误统一且不含令牌/长度/比较位置信息：%q", e1)
}
