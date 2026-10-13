package nodehealth

// D1 心跳语义测试（第二十二轮）。
//
// 新语义（取代 ADR-020 §5 的注册时刻锚点）：
//   - **存活以控制面接收时间 received_at 为准**，不使用节点自报时间；
//   - sent_at 仅用于**防重放**：同一节点内必须**严格递增**
//     （小于 → replay；等于 → duplicate；两者都拒绝且**不刷新任何状态**）；
//   - 时钟偏差 skew = received_at − sent_at 只**记录与告警**，不拒绝、不离线；
//   - 偏差级别变化时才写一条 clock_skew 告警（不逐条刷屏）；
//   - **删除注册时刻锚点**：首个心跳的 sent_at 可以早于注册时刻，只要单调。

import (
	"errors"
	"testing"
	"time"
)

// testSession D1/N5 既有用例使用的固定会话标识。
//
// 这些用例验证的是"**同一会话内**严格递增"的 D1 语义；
// D6 引入会话维度后，显式传入同一会话即可保持原断言完全等价。
const testSession = "01M4RHFDJ0TESTSESSION0000000"

// base 固定注入时钟（测试不使用真实时间，也不 sleep）。
var base = time.Unix(1791825000, 0).UTC()

// clock 可推进的注入时钟。
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

// newTracker 构建注入了可控时钟的判定器。
func newTracker(t *testing.T) (*Tracker, *clock) {
	t.Helper()
	c := &clock{t: base}
	tr, err := NewTracker(Config{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	return tr, c
}

const d1Node = "nod_01M4RHFDJ0D1D1D1D1D1D1D1D1"

// TestD1ClockSlowNodeStaysOnline（D1 ①）节点时钟慢 60 秒的完整心跳序列：
// 保持 online、skew 被记录、产生一条 clock_skew 告警、且**不被拒绝**。
func TestD1ClockSlowNodeStaysOnline(t *testing.T) {
	tr, c := newTracker(t)
	tr.Register(d1Node)

	// 节点时钟比控制面慢 60 秒：sent_at = received_at - 60s。
	// 但 sent_at 必须严格递增，所以每轮在节点侧推进 10 秒。
	nodeClock := base.Add(-60 * time.Second)
	warnCount := 0
	for i := 0; i < 5; i++ {
		res, err := tr.Heartbeat(d1Node, testSession, nodeClock)
		if err != nil {
			t.Fatalf("第 %d 次心跳不得因时钟偏差被拒绝：%v", i+1, err)
		}
		if res.Transition.To != StatusOnline {
			t.Fatalf("第 %d 次心跳后应为 online，实际 %s", i+1, res.Transition.To)
		}
		if res.Skew != 60*time.Second {
			t.Fatalf("第 %d 次心跳 skew 应为 60s，实际 %s", i+1, res.Skew)
		}
		if res.SkewLevel != SkewAlert {
			t.Fatalf("第 %d 次心跳偏差级别应为 alert（>30s），实际 %q", i+1, res.SkewLevel)
		}
		if res.SkewReported {
			warnCount++
		}
		// 控制面推进 10 秒；节点侧同步推进 10 秒（保持 60 秒偏差）。
		c.advance(DefaultInterval)
		nodeClock = nodeClock.Add(DefaultInterval)
	}
	if warnCount != 1 {
		t.Fatalf("偏差级别未变化时只应写 1 条告警，实际 %d 条", warnCount)
	}
	st, _, err := tr.Status(d1Node)
	if err != nil {
		t.Fatal(err)
	}
	if st != StatusOnline {
		t.Fatalf("时钟慢 60 秒不得导致离线，实际 %s", st)
	}
	// 偏差被记录（最后一次 skew 落在 60s）。
	skew, err := tr.LastSkew(d1Node)
	if err != nil {
		t.Fatal(err)
	}
	if skew != 60*time.Second {
		t.Fatalf("应记录最后一次 skew=60s，实际 %s", skew)
	}
	t.Logf("[D1①] 节点时钟慢 60 秒：5 次心跳全部接受、保持 online、skew=60s（alert），仅 1 条告警")
}

// TestD1ReplayRejected（D1 ②）sent_at 回退 → 拒绝（reason=replay），last_seen 不变。
func TestD1ReplayRejected(t *testing.T) {
	tr, c := newTracker(t)
	tr.Register(d1Node)

	first := base.Add(-time.Minute)
	if _, err := tr.Heartbeat(d1Node, testSession, first); err != nil {
		t.Fatalf("首个心跳应被接受：%v", err)
	}
	_, lastSeenBefore, _ := tr.Status(d1Node)

	// 控制面前进 5 秒，但节点上报一个**更早**的 sent_at。
	c.advance(5 * time.Second)
	res, err := tr.Heartbeat(d1Node, testSession, first.Add(-time.Second))
	if !errors.Is(err, ErrHeartbeatReplay) {
		t.Fatalf("sent_at 回退必须被拒绝（ErrHeartbeatReplay），实际 %v", err)
	}
	if res.Transition.Reason != ReasonReplay {
		t.Fatalf("reason 应为 %q，实际 %q", ReasonReplay, res.Transition.Reason)
	}
	if res.Transition.Changed() {
		t.Fatalf("拒绝时不得产生状态变化：%+v", res.Transition)
	}
	_, lastSeenAfter, _ := tr.Status(d1Node)
	if !lastSeenAfter.Equal(lastSeenBefore) {
		t.Fatalf("拒绝时 last_seen 不得刷新：before=%s after=%s", lastSeenBefore, lastSeenAfter)
	}
	t.Log("[D1②] sent_at 回退 → 拒绝（reason=replay），last_seen 未刷新")
}

// TestD1DuplicateRejected（D1 ③）sent_at 相同 → 拒绝（reason=duplicate），last_seen 不变。
func TestD1DuplicateRejected(t *testing.T) {
	tr, c := newTracker(t)
	tr.Register(d1Node)

	same := base.Add(-time.Minute)
	if _, err := tr.Heartbeat(d1Node, testSession, same); err != nil {
		t.Fatalf("首个心跳应被接受：%v", err)
	}
	_, lastSeenBefore, _ := tr.Status(d1Node)

	c.advance(5 * time.Second)
	res, err := tr.Heartbeat(d1Node, testSession, same) // 完全相同的 sent_at
	if !errors.Is(err, ErrHeartbeatDuplicate) {
		t.Fatalf("sent_at 相同必须被拒绝（ErrHeartbeatDuplicate），实际 %v", err)
	}
	if res.Transition.Reason != ReasonDuplicate {
		t.Fatalf("reason 应为 %q，实际 %q", ReasonDuplicate, res.Transition.Reason)
	}
	_, lastSeenAfter, _ := tr.Status(d1Node)
	if !lastSeenAfter.Equal(lastSeenBefore) {
		t.Fatalf("拒绝时 last_seen 不得刷新：before=%s after=%s", lastSeenBefore, lastSeenAfter)
	}
	t.Log("[D1③] sent_at 相同 → 拒绝（reason=duplicate），last_seen 未刷新")
}

// TestD1OfflineByReceivedTime（D1 ④）控制面时钟前进 30 秒无心跳接收 → offline（基于 received_at）。
func TestD1OfflineByReceivedTime(t *testing.T) {
	tr, c := newTracker(t)
	tr.Register(d1Node)
	if _, err := tr.Heartbeat(d1Node, testSession, base.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	// 节点侧时间戳完全不前进（甚至更慢），但控制面 30 秒没收到心跳 → offline。
	c.advance(3 * DefaultInterval)
	trans := tr.EvaluateAll()
	if len(trans) != 1 {
		t.Fatalf("应产生 1 条 offline 迁移，实际 %d：%v", len(trans), trans)
	}
	if trans[0].To != StatusOffline || trans[0].Reason != "missed_heartbeats" {
		t.Fatalf("迁移不符：%+v", trans[0])
	}
	if st, _, _ := tr.Status(d1Node); st != StatusOffline {
		t.Fatalf("应为 offline，实际 %s", st)
	}
	t.Logf("[D1④] 控制面 30 秒无接收 → offline（基于 received_at）：%s", trans[0])
}

// TestD1FirstHeartbeatBeforeEnrollmentAccepted（D1 ⑤）首个心跳的 sent_at 早于注册时刻
// 但单调递增 → 接受（证明注册时刻锚点已删除）。
func TestD1FirstHeartbeatBeforeEnrollmentAccepted(t *testing.T) {
	tr, _ := newTracker(t)
	tr.Register(d1Node) // 注册时刻 = base

	// sent_at 远早于注册时刻（例如节点时钟严重落后）。
	early := base.Add(-24 * time.Hour)
	if _, err := tr.Heartbeat(d1Node, testSession, early); err != nil {
		t.Fatalf("首个心跳的 sent_at 早于注册时刻不得被拒绝（锚点应已移除）：%v", err)
	}
	// 单调递增即继续接受。
	if _, err := tr.Heartbeat(d1Node, testSession, early.Add(time.Second)); err != nil {
		t.Fatalf("单调递增的心跳应被接受：%v", err)
	}
	t.Log("[D1⑤] 首个心跳 sent_at 早于注册时刻但单调 → 接受（注册时刻锚点已删除）")
}

// TestD1SkewThresholds（D1 偏差阈值）warn=5s / alert=30s，只告警不拒绝；级别变化才告警。
//
// 构造方式：控制面每轮推进 15 秒，节点侧 sent_at 每轮只推进 1 秒
// （保证 sent_at **严格递增**，同时让 skew 逐轮变大）。
func TestD1SkewThresholds(t *testing.T) {
	tr, c := newTracker(t)
	tr.Register(d1Node)

	if tr.SkewWarn() != 5*time.Second || tr.SkewAlert() != 30*time.Second {
		t.Fatalf("默认阈值应为 warn=5s / alert=30s，实际 %s / %s", tr.SkewWarn(), tr.SkewAlert())
	}

	// R0：received=t0，sent=t0-3s → skew 3s → 无告警。
	sent := base.Add(-3 * time.Second)
	res, err := tr.Heartbeat(d1Node, testSession, sent)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skew != 3*time.Second || res.SkewLevel != SkewNone || res.SkewReported {
		t.Fatalf("R0 偏差 3 秒不应告警：skew=%s level=%q reported=%v", res.Skew, res.SkewLevel, res.SkewReported)
	}

	// R1：控制面 +15s，sent +1s → skew 17s → warn（级别变化 → 告警一次）。
	c.advance(15 * time.Second)
	sent = sent.Add(time.Second)
	res, err = tr.Heartbeat(d1Node, testSession, sent)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skew != 17*time.Second || res.SkewLevel != SkewWarn || !res.SkewReported {
		t.Fatalf("R1 偏差 17 秒应告警 warn：skew=%s level=%q reported=%v", res.Skew, res.SkewLevel, res.SkewReported)
	}

	// R2：控制面 +15s，sent +1s → skew 31s → alert（级别变化 → 告警一次）。
	c.advance(15 * time.Second)
	sent = sent.Add(time.Second)
	res, err = tr.Heartbeat(d1Node, testSession, sent)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skew != 31*time.Second || res.SkewLevel != SkewAlert || !res.SkewReported {
		t.Fatalf("R2 偏差 31 秒应告警 alert：skew=%s level=%q reported=%v", res.Skew, res.SkewLevel, res.SkewReported)
	}

	// R3：控制面 +15s，sent +1s → skew 45s → 仍是 alert（同级别 → 不重复告警）。
	c.advance(15 * time.Second)
	sent = sent.Add(time.Second)
	res, err = tr.Heartbeat(d1Node, testSession, sent)
	if err != nil {
		t.Fatal(err)
	}
	if res.SkewLevel != SkewAlert || res.SkewReported {
		t.Fatalf("R3 同级别偏差不应重复告警：level=%q reported=%v", res.SkewLevel, res.SkewReported)
	}

	// R4：节点追上时钟（sent 大幅推进）→ skew 2s → 回到 none（级别变化 → 记录一次）。
	c.advance(15 * time.Second)
	sent = c.now().Add(-2 * time.Second)
	res, err = tr.Heartbeat(d1Node, testSession, sent)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skew != 2*time.Second || res.SkewLevel != SkewNone || !res.SkewReported {
		t.Fatalf("R4 偏差恢复应记录一次级别变化：skew=%s level=%q reported=%v", res.Skew, res.SkewLevel, res.SkewReported)
	}

	// 全程 online：偏差只记录/告警，不影响存活。
	if st, _, _ := tr.Status(d1Node); st != StatusOnline {
		t.Fatalf("任何偏差级别都不得导致离线，实际 %s", st)
	}
	t.Log("[D1 阈值] 3s→无告警；17s→warn(1)；31s→alert(1)；45s→同级不重复；2s→恢复记录一次；全程 online")
}

// TestD1SkewNeverCausesOfflineOrRejection（D1 约束）偏差再大也不拒绝、不离线。
func TestD1SkewNeverCausesOfflineOrRejection(t *testing.T) {
	tr, c := newTracker(t)
	tr.Register(d1Node)
	// 偏差 10 分钟（远超 alert 阈值）。
	if _, err := tr.Heartbeat(d1Node, testSession, base.Add(-10*time.Minute)); err != nil {
		t.Fatalf("巨大偏差不得被拒绝：%v", err)
	}
	c.advance(time.Second)
	if st, _, _ := tr.Status(d1Node); st != StatusOnline {
		t.Fatalf("巨大偏差不得导致离线，实际 %s", st)
	}
	t.Log("[D1 约束] 偏差 10 分钟：接受且保持 online（只记录/告警）")
}
