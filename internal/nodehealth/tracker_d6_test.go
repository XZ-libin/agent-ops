package nodehealth

// D6 会话基线测试（第二十三轮 T1）。
//
// 背景：D1 的"sent_at 严格递增"在节点**时钟回拨**后会永久拒绝心跳，直到时钟追平——
// 这是与 D1 修复的"注册锚点"同一类的**永久失联**。D6 的修复方式：
//   - 防重放基线按 **(node_id, boot_session_id)** 维护（会话 = 节点进程启动一次）；
//   - **新会话**的首个心跳不与旧会话比较；
//   - 同一会话内**连续 3 次** replay/duplicate 后，基线重置为当前 sent_at
//     （由服务端写 node.clock_regression_reset 审计）。

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// d6Node D6 用例使用的节点身份。
const (
	d6Node        = "nod_01M4RHFDJ0D6D6D6D6D6D6D6D6"
	d6SessionOld  = "01M4RHFDJ0OLDSESSION00000000"
	d6SessionNew  = "01M4RHFDJ0NEWSESSION00000000"
	d6SessionNext = "01M4RHFDJ0NEXTSESSION0000000"
)

// d6Clock 可控时钟（与 d1Clock 独立，避免共享状态）。
type d6Clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *d6Clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *d6Clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newD6 构建带注入时钟的判定器并注册节点。
func newD6(t *testing.T) (*Tracker, *d6Clock) {
	t.Helper()
	c := &d6Clock{t: base}
	tr, err := NewTracker(Config{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	tr.Register(d6Node)
	return tr, c
}

// TestD6_NewSessionBaselineReset（T1 e-1）新会话且 sent_at 比旧会话早 10 分钟 → 接受。
//
// 这正是"节点时钟回拨 + 重启"的场景：新会话不应与旧基线比较。
func TestD6_NewSessionBaselineReset(t *testing.T) {
	tr, c := newD6(t)

	// 旧会话：以 base 为基线发一次心跳。
	if _, err := tr.Heartbeat(d6Node, d6SessionOld, base); err != nil {
		t.Fatalf("旧会话首个心跳应被接受：%v", err)
	}
	// 旧会话继续前进 10 分钟，基线抬高。
	c.advance(10 * time.Minute)
	if _, err := tr.Heartbeat(d6Node, d6SessionOld, base.Add(10*time.Minute)); err != nil {
		t.Fatalf("旧会话正常心跳应被接受：%v", err)
	}

	// 节点重启（新会话），且系统时钟回拨 10 分钟 → sent_at 比旧基线**早 10 分钟**。
	c.advance(DefaultInterval)
	res, err := tr.Heartbeat(d6Node, d6SessionNew, base.Add(-10*time.Minute))
	if err != nil {
		t.Fatalf("新会话的首个心跳必须被接受（不得与旧会话基线比较）：%v", err)
	}
	if !res.NewSession {
		t.Fatal("应标记 NewSession=true")
	}
	if res.BootSessionID != d6SessionNew {
		t.Fatalf("会话标识应为新会话，实际 %q", res.BootSessionID)
	}
	if res.BaselineReset {
		t.Fatal("新会话的首个心跳不是\"连续 replay 重置\"，BaselineReset 应为 false")
	}
	if st, _, _ := tr.Status(d6Node); st != StatusOnline {
		t.Fatalf("新会话心跳后应保持 online，实际 %s", st)
	}
	t.Logf("[D6①] 新会话 sent_at 比旧基线早 10 分钟 → 接受（NewSession=true，状态 online）")
}

// TestD6_ReplayWithinSessionRejected（T1 e-2）同会话回退 → 拒绝且状态不变。
func TestD6_ReplayWithinSessionRejected(t *testing.T) {
	tr, c := newD6(t)
	session := d6SessionOld

	first := base
	if _, err := tr.Heartbeat(d6Node, session, first); err != nil {
		t.Fatalf("首个心跳应被接受：%v", err)
	}
	_, before, _ := tr.Status(d6Node)
	missesBefore, _ := tr.Misses(d6Node)

	c.advance(DefaultInterval)
	res, err := tr.Heartbeat(d6Node, session, first.Add(-time.Second))
	if !errors.Is(err, ErrHeartbeatReplay) {
		t.Fatalf("同会话回退必须拒绝（ErrHeartbeatReplay），实际 %v", err)
	}
	if res.Transition.Reason != ReasonReplay {
		t.Fatalf("拒绝原因应为 replay，实际 %q", res.Transition.Reason)
	}
	if res.ReplayStreak != 1 {
		t.Fatalf("连续 replay 计数应为 1，实际 %d", res.ReplayStreak)
	}
	// 状态与存活时间**都不得变化**（D1/D6 一致）。
	_, after, _ := tr.Status(d6Node)
	if !after.Equal(before) {
		t.Fatalf("拒绝时不得刷新 last_received_at：前 %v 后 %v", before, after)
	}
	if misses, _ := tr.Misses(d6Node); misses != missesBefore {
		t.Fatalf("拒绝时不得改变 misses：前 %d 后 %d", missesBefore, misses)
	}
	t.Log("[D6②] 同会话回退 → 拒绝 replay，状态与 last_received_at 均未变化")
}

// TestD6_DuplicateWithinSessionRejected（T1 e-3）同会话相同 sent_at → 拒绝且状态不变。
func TestD6_DuplicateWithinSessionRejected(t *testing.T) {
	tr, c := newD6(t)
	session := d6SessionOld

	same := base
	if _, err := tr.Heartbeat(d6Node, session, same); err != nil {
		t.Fatalf("首个心跳应被接受：%v", err)
	}
	_, before, _ := tr.Status(d6Node)

	c.advance(DefaultInterval)
	res, err := tr.Heartbeat(d6Node, session, same)
	if !errors.Is(err, ErrHeartbeatDuplicate) {
		t.Fatalf("同会话相同 sent_at 必须拒绝（ErrHeartbeatDuplicate），实际 %v", err)
	}
	if res.Transition.Reason != ReasonDuplicate {
		t.Fatalf("拒绝原因应为 duplicate，实际 %q", res.Transition.Reason)
	}
	// T3（第二十四轮）加固：**duplicate 不计入连续 replay 计数**
	// （旧断言为 1；新条件要求只有"严格递增的 replay"才可能触发重置，
	//  因此 duplicate 不再参与计数——见 ADR-023 §3）。
	if res.ReplayStreak != 0 {
		t.Fatalf("duplicate 不得计入连续 replay 计数，实际 %d", res.ReplayStreak)
	}
	_, after, _ := tr.Status(d6Node)
	if !after.Equal(before) {
		t.Fatalf("拒绝时不得刷新 last_received_at：前 %v 后 %v", before, after)
	}
	t.Log("[D6③] 同会话相同 sent_at → 拒绝 duplicate，last_received_at 未变化（不计入连续计数）")
}

// TestD6_ConsecutiveReplayResetsBaseline（T1 e-4）同会话第 3 次 replay → 重置基线并接受。
//
// 这是"时钟回拨但进程未重启"的恢复路径：前 2 次拒绝，第 3 次重置基线。
func TestD6_ConsecutiveReplayResetsBaseline(t *testing.T) {
	tr, c := newD6(t)
	if tr.ReplayResetThreshold() != DefaultReplayResetThreshold {
		t.Fatalf("默认连续阈值应为 %d，实际 %d",
			DefaultReplayResetThreshold, tr.ReplayResetThreshold())
	}
	session := d6SessionOld
	high := base.Add(time.Hour) // 旧基线（时钟"未来"）
	if _, err := tr.Heartbeat(d6Node, session, high); err != nil {
		t.Fatalf("首个心跳应被接受：%v", err)
	}
	// 时钟回拨：此后 sent_at 都远低于基线，但**在前进**（真实回拨的形态）。
	//
	// T3（第二十四轮）加固：重置需要"被拒的 sent_at 之间严格递增 + 接收跨度 ≥20s"。
	// 旧版本用同一个 rolledBack 值（不递增），在新条件下**不应**触发重置——
	// 那正是"随机低值"的形态。因此本用例改为每次前进 5 秒（3 次跨度 10 秒 <
	// sent_at 的前进幅度无关），并配合 c.advance(DefaultInterval) 满足跨度要求。
	rolledBack := base.Add(-10 * time.Minute)

	var resets int
	for i := 1; i <= DefaultReplayResetThreshold; i++ {
		c.advance(DefaultInterval)
		sent := rolledBack.Add(time.Duration(i) * 5 * time.Second)
		res, err := tr.Heartbeat(d6Node, session, sent)
		switch {
		case i < DefaultReplayResetThreshold:
			if !errors.Is(err, ErrHeartbeatReplay) {
				t.Fatalf("第 %d 次 replay 应被拒绝，实际 err=%v", i, err)
			}
			if res.ReplayStreak != i {
				t.Fatalf("第 %d 次 replay 的连续计数应为 %d，实际 %d", i, i, res.ReplayStreak)
			}
			if res.BaselineReset {
				t.Fatalf("第 %d 次不应重置基线", i)
			}
		default:
			// 第 3 次：重置基线并按正常心跳**接受**（否则永久失联）。
			if err != nil {
				t.Fatalf("第 %d 次必须重置基线并接受，实际 err=%v", i, err)
			}
			if !res.BaselineReset {
				t.Fatalf("第 %d 次应标记 BaselineReset=true", i)
			}
			if res.ReplayStreak != DefaultReplayResetThreshold {
				t.Fatalf("重置时连续次数应为 %d，实际 %d",
					DefaultReplayResetThreshold, res.ReplayStreak)
			}
			resets++
		}
	}
	if resets != 1 {
		t.Fatalf("应恰好重置 1 次，实际 %d", resets)
	}
	// 重置后同一 sent_at 再次提交 → 是 duplicate（证明基线确实已重置为该值）。
	// 重置用的 sent_at 是第 3 次的值：rolledBack + 15s。
	resetValue := rolledBack.Add(time.Duration(DefaultReplayResetThreshold) * 5 * time.Second)
	c.advance(DefaultInterval)
	if _, err := tr.Heartbeat(d6Node, session, resetValue); !errors.Is(err, ErrHeartbeatDuplicate) {
		t.Fatalf("重置后同一 sent_at 应为 duplicate，实际 %v", err)
	}
	// 重置后正常前进 → 接受。
	c.advance(DefaultInterval)
	if _, err := tr.Heartbeat(d6Node, session, resetValue.Add(time.Second)); err != nil {
		t.Fatalf("重置后正常心跳应被接受：%v", err)
	}
	if st, _, _ := tr.Status(d6Node); st != StatusOnline {
		t.Fatalf("重置后应保持 online，实际 %s", st)
	}
	t.Logf("[D6④] 同会话第 %d 次**递增** replay（接收跨度 ≥%s）→ 基线重置并接受"+
		"（Reset 后同值=duplicate、前进=接受）",
		DefaultReplayResetThreshold, DefaultReplayResetMinSpan)
}

// TestD6_ResetAuditNoSecrets（T1 e-5）重置事件对外暴露的字段只有
// node_id / boot_session_id / 连续次数——**不含**证书或令牌内容。
//
// 这里是纯逻辑层的取证：断言 HeartbeatResult 的公开字段集合恰好够写审计，
// 且会话标识是 ULID 形态（不含任何证书/令牌材料）。
func TestD6_ResetAuditNoSecrets(t *testing.T) {
	tr, c := newD6(t)
	session := d6SessionOld
	high := base.Add(time.Hour)
	if _, err := tr.Heartbeat(d6Node, session, high); err != nil {
		t.Fatal(err)
	}
	rolledBack := base.Add(-10 * time.Minute)
	var res HeartbeatResult
	for i := 0; i < DefaultReplayResetThreshold; i++ {
		c.advance(DefaultInterval)
		// T3：sent_at 必须**严格递增**（真实回拨的形态）。
		res, _ = tr.Heartbeat(d6Node, session,
			rolledBack.Add(time.Duration(i+1)*5*time.Second))
	}
	if !res.BaselineReset {
		t.Fatal("应已触发基线重置")
	}
	// 审计三要素齐备。
	if res.Transition.NodeID != d6Node {
		t.Fatalf("审计需含 node_id，实际 %q", res.Transition.NodeID)
	}
	if res.BootSessionID != session {
		t.Fatalf("审计需含 boot_session_id，实际 %q", res.BootSessionID)
	}
	if res.ReplayStreak != DefaultReplayResetThreshold {
		t.Fatalf("审计需含连续次数，实际 %d", res.ReplayStreak)
	}
	// 会话标识不得含任何 PEM/令牌形态的字样。
	for _, bad := range []string{"BEGIN ", "PRIVATE KEY", "CERTIFICATE", "-----"} {
		if contains(res.BootSessionID, bad) {
			t.Fatalf("会话标识不得含敏感材料字样 %q：%q", bad, res.BootSessionID)
		}
	}
	t.Logf("[D6⑤] 重置审计三要素齐备（node_id/%s/连续=%d），会话标识为 ULID 形态、无敏感材料",
		res.BootSessionID, res.ReplayStreak)
}

// TestD6_NewSessionDoesNotTouchOldBaseline（D6 边界）新会话不改变旧会话的历史记录语义：
// 连续 replay 计数在新会话开始时清零。
func TestD6_NewSessionDoesNotTouchOldBaseline(t *testing.T) {
	tr, c := newD6(t)
	high := base.Add(time.Hour)
	if _, err := tr.Heartbeat(d6Node, d6SessionOld, high); err != nil {
		t.Fatal(err)
	}
	// 旧会话累积 2 次 replay（未达阈值）。
	low := base.Add(-time.Minute)
	for i := 0; i < 2; i++ {
		c.advance(DefaultInterval)
		if _, err := tr.Heartbeat(d6Node, d6SessionOld, low); !errors.Is(err, ErrHeartbeatReplay) {
			t.Fatalf("第 %d 次应为 replay，实际 %v", i+1, err)
		}
	}
	// 切到新会话：计数清零，且不与旧基线比较。
	c.advance(DefaultInterval)
	res, err := tr.Heartbeat(d6Node, d6SessionNext, low.Add(-time.Hour))
	if err != nil {
		t.Fatalf("新会话首个心跳应被接受：%v", err)
	}
	if res.NewSession != true || res.ReplayStreak != 0 {
		t.Fatalf("新会话应清零连续计数：NewSession=%v ReplayStreak=%d",
			res.NewSession, res.ReplayStreak)
	}
	t.Log("[D6 边界] 新会话清零连续异常计数，且不与旧会话基线比较")
}

// contains 简易子串判断（避免为测试引入 strings 依赖歧义）。
func contains(s, sub string) bool {
	if sub == "" {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
