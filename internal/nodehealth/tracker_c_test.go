package nodehealth

// T3 时钟回退重置加固测试（第二十四轮，缺口 3）。
//
// 背景：第二十三轮的规则是"同一会话内连续 3 次 replay 即重置基线"——条件过宽。
// 攻击者（或一次短时抖动）能用 3 个**随机低值**触发重置，使 replay 检测在 3 个
// 心跳窗口内失效。
//
// 加固后，重置必须**同时满足**三条件：
//  ① 连续 3 次 replay（工程默认，待确认）；
//  ② 这 3 个被拒的 sent_at 之间**严格递增**（是一条正在前进的新时钟）；
//  ③ 这 3 次的 received_at 跨度 ≥ 20 秒（工程默认，待确认）。
//
//	TestC1_MonotonicReplayTriggersReset
//	TestC2_NonMonotonicReplayDoesNotReset
//	TestC3_TightSpanDoesNotReset
//	TestC4_DuplicateDoesNotCount
//	TestC5_AcceptedHeartbeatResetsCounter

import (
	"errors"
	"testing"
	"time"
)

// cNode / cSession T3 用例使用的固定节点与会话。
const (
	cNode    = "nod_01M4RHFDJ0C0C0C0C0C0C0C0C0"
	cSession = "01M4RHFDJ0CSESSION000000000"
)

// newC 构建注入时钟的判定器并注册节点。
func newC(t *testing.T) (*Tracker, *d6Clock) {
	t.Helper()
	c := &d6Clock{t: base}
	tr, err := NewTracker(Config{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	tr.Register(cNode)
	return tr, c
}

// armBaseline 建立一个"时钟在未来"的基线（后续低值都是 replay）。
func armBaseline(t *testing.T, tr *Tracker, session string) time.Time {
	t.Helper()
	high := base.Add(time.Hour)
	if _, err := tr.Heartbeat(cNode, session, high); err != nil {
		t.Fatalf("建立基线失败：%v", err)
	}
	return high
}

// TestC1_MonotonicReplayTriggersReset（C1）单调递增 + 跨度足够 → 第 3 次触发重置。
func TestC1_MonotonicReplayTriggersReset(t *testing.T) {
	tr, c := newC(t)
	armBaseline(t, tr, cSession)
	if tr.ReplayResetMinSpan() != DefaultReplayResetMinSpan {
		t.Fatalf("默认最小跨度应为 %s，实际 %s", DefaultReplayResetMinSpan, tr.ReplayResetMinSpan())
	}
	low := base.Add(-10 * time.Minute)

	var finals []HeartbeatResult
	for i := 1; i <= DefaultReplayResetThreshold; i++ {
		// 接收跨度：每次间隔 10 秒 → 3 次共 20 秒（恰好满足 ≥20s）。
		c.advance(10 * time.Second)
		res, err := tr.Heartbeat(cNode, cSession, low.Add(time.Duration(i)*time.Second))
		finals = append(finals, res)
		if i < DefaultReplayResetThreshold {
			if !errors.Is(err, ErrHeartbeatReplay) {
				t.Fatalf("第 %d 次应被拒绝，实际 %v", i, err)
			}
			if res.BaselineReset {
				t.Fatalf("第 %d 次不应重置", i)
			}
			continue
		}
		if err != nil {
			t.Fatalf("第 %d 次应重置并接受，实际 %v", i, err)
		}
		if !res.BaselineReset {
			t.Fatal("第 3 次应标记 BaselineReset")
		}
		if res.ResetSpan < DefaultReplayResetMinSpan {
			t.Fatalf("ResetSpan 应 ≥%s，实际 %s", DefaultReplayResetMinSpan, res.ResetSpan)
		}
		if res.ReplayStreak != DefaultReplayResetThreshold {
			t.Fatalf("连续次数应为 %d，实际 %d", DefaultReplayResetThreshold, res.ReplayStreak)
		}
	}
	if st, _, _ := tr.Status(cNode); st != StatusOnline {
		t.Fatalf("重置后应保持 online，实际 %s", st)
	}
	t.Logf("[C1] 单调递增 + 接收跨度 %s（≥%s）→ 第 %d 次重置基线并接受",
		finals[len(finals)-1].ResetSpan, DefaultReplayResetMinSpan, DefaultReplayResetThreshold)
}

// TestC2_NonMonotonicReplayDoesNotReset（C2）低值**乱序**（非严格递增）→ **不**重置。
//
// 构造要点：判定只看**最近 threshold 个** replay 候选的单调性与跨度。
// 因此要构造"最近 3 个里含非递增对"的窗口，并验证它确实拦住重置。
func TestC2_NonMonotonicReplayDoesNotReset(t *testing.T) {
	tr, c := newC(t)
	bLine := base
	if _, err := tr.Heartbeat(cNode, cSession, bLine); err != nil {
		t.Fatalf("建立基线失败：%v", err)
	}
	// 基线之后的所有值都取 bLine-10m+δ（δ 远小于 10m → 恒低于基线 → 都是 replay）。
	lowOf := func(d time.Duration) time.Time {
		return bLine.Add(-10 * time.Minute).Add(d)
	}

	// ① 乱序：10s → 8s → 9s。第 3 个时窗口为 [10s,8s,9s]，含递减对 → 不得重置。
	for i, d := range []time.Duration{10 * time.Second, 8 * time.Second, 9 * time.Second} {
		c.advance(10 * time.Second)
		res, err := tr.Heartbeat(cNode, cSession, lowOf(d))
		if !errors.Is(err, ErrHeartbeatReplay) {
			t.Fatalf("乱序第 %d 次应为 replay，实际 %v", i+1, err)
		}
		if res.BaselineReset {
			t.Fatalf("乱序第 %d 次**不得**触发重置（窗口含递减对）", i+1)
		}
	}
	// ② 再发一个更低的 1s：窗口变成 [8s,9s,1s]，末对仍递减 → 仍不得重置。
	c.advance(10 * time.Second)
	res, err := tr.Heartbeat(cNode, cSession, lowOf(1*time.Second))
	if !errors.Is(err, ErrHeartbeatReplay) {
		t.Fatalf("更低值应为 replay，实际 %v", err)
	}
	if res.BaselineReset {
		t.Fatalf("窗口 [8s,9s,1s] 含递减对，不得重置（streak=%d）", res.ReplayStreak)
	}
	if st, _, _ := tr.Status(cNode); st != StatusOnline {
		t.Fatalf("拒绝期间节点应保持 online（拒绝不改变状态），实际 %s", st)
	}

	// ③ 先清场：发一个**高于基线**的心跳（被接受）→ 计数与候选清零（C5 语义）。
	//    否则之前的乱序候选会与新序列混在同一个滑动窗口里，使对照组的语义不清晰。
	c.advance(10 * time.Second)
	if _, err := tr.Heartbeat(cNode, cSession, bLine.Add(time.Minute)); err != nil {
		t.Fatalf("清场心跳应被接受：%v", err)
	}

	// ④ 对照组：紧随的 3 个**严格递增**值（30s→31s→32s）应触发重置
	//    （末次窗口 [30s,31s,32s]，严格递增且接收跨度 20s）。
	//    这证明判定看的是单调性，而不是"乱序后永不重置"。
	var reset bool
	for i, d := range []time.Duration{30 * time.Second, 31 * time.Second, 32 * time.Second} {
		c.advance(10 * time.Second)
		res, err := tr.Heartbeat(cNode, cSession, lowOf(d))
		if i < 2 {
			if !errors.Is(err, ErrHeartbeatReplay) {
				t.Fatalf("递增序列第 %d 次应为 replay（等待累积），实际 %v", i+1, err)
			}
			if res.BaselineReset {
				t.Fatalf("递增序列第 %d 次不应提前重置（窗口仍含递减对）", i+1)
			}
			continue
		}
		if err != nil || !res.BaselineReset {
			t.Fatalf("递增序列末次应触发重置，实际 err=%v reset=%v", err, res.BaselineReset)
		}
		reset = true
	}
	if !reset {
		t.Fatal("对照组（严格递增）应触发重置")
	}
	t.Log("[C2] 乱序窗口（[10s,8s,9s] 与 [8s,9s,1s]）→ 不重置；" +
		"对照组（[30s,31s,32s] 严格递增）→ 如期重置（判定看的是单调性）")
}

// TestC3_TightSpanDoesNotReset（C3）3 次在 1 秒内完成 → **不**重置（跨度不足）。
func TestC3_TightSpanDoesNotReset(t *testing.T) {
	tr, c := newC(t)
	armBaseline(t, tr, cSession)
	low := base.Add(-10 * time.Minute)

	// 严格递增，但接收跨度只有 ~0.6 秒（远小于 20 秒）→ 一次抖动里的廉价伪造。
	for i := 1; i <= DefaultReplayResetThreshold+2; i++ {
		c.advance(200 * time.Millisecond)
		res, err := tr.Heartbeat(cNode, cSession, low.Add(time.Duration(i)*time.Millisecond))
		if !errors.Is(err, ErrHeartbeatReplay) {
			t.Fatalf("第 %d 次应为 replay（跨度不足不重置），实际 %v", i, err)
		}
		if res.BaselineReset {
			t.Fatalf("接收跨度不足 %s 时**不得**重置（第 %d 次）",
				DefaultReplayResetMinSpan, i)
		}
	}
	// 补足跨度后（推进 20 秒）再发一次严格递增的低值 → 此时才允许重置。
	c.advance(DefaultReplayResetMinSpan)
	res, err := tr.Heartbeat(cNode, cSession, low.Add(time.Second))
	if err != nil {
		t.Fatalf("跨度补足后应重置并接受，实际 %v", err)
	}
	if !res.BaselineReset {
		t.Fatal("跨度补足后应触发重置")
	}
	t.Logf("[C3] 3 次在 0.6s 内完成 → 不重置；补足 %s 跨度后 → 重置",
		DefaultReplayResetMinSpan)
}

// TestC4_DuplicateDoesNotCount（C4）duplicate **不计入**连续 replay 计数。
//
// 构造要点：`duplicate` 的定义是"与**当前基线**相同"。因此本用例先用一次接受
// 把基线降到 base，再用同一值制造 duplicate（与基线相同 → duplicate），
// 然后用**低于基线**的递增值制造 replay。
func TestC4_DuplicateDoesNotCount(t *testing.T) {
	tr, c := newC(t)
	// 直接以 base 建立基线（被接受）——duplicate 的定义是"与当前基线相同"。
	if _, err := tr.Heartbeat(cNode, cSession, base); err != nil {
		t.Fatalf("建立基线失败：%v", err)
	}
	// duplicate：与基线（base）相同。
	c.advance(10 * time.Second)
	res, err := tr.Heartbeat(cNode, cSession, base)
	if !errors.Is(err, ErrHeartbeatDuplicate) {
		t.Fatalf("与基线相同应为 duplicate，实际 %v", err)
	}
	if res.ReplayStreak != 0 {
		t.Fatalf("duplicate 不得计入连续计数：应为 0，实际 %d", res.ReplayStreak)
	}
	// replay 1：低于基线。
	c.advance(10 * time.Second)
	res, err = tr.Heartbeat(cNode, cSession, base.Add(-time.Minute))
	if !errors.Is(err, ErrHeartbeatReplay) || res.ReplayStreak != 1 {
		t.Fatalf("应为 replay 且计数 1，实际 err=%v streak=%d", err, res.ReplayStreak)
	}
	// duplicate 夹在中间：再来一次与基线相同的值 → 计数仍为 1。
	c.advance(10 * time.Second)
	res, err = tr.Heartbeat(cNode, cSession, base)
	if !errors.Is(err, ErrHeartbeatDuplicate) {
		t.Fatalf("应仍为 duplicate，实际 %v", err)
	}
	if res.ReplayStreak != 1 {
		t.Fatalf("duplicate 不得推进计数：应仍为 1，实际 %d", res.ReplayStreak)
	}
	// replay 2。
	c.advance(10 * time.Second)
	res, err = tr.Heartbeat(cNode, cSession, base.Add(-time.Minute+time.Second))
	if !errors.Is(err, ErrHeartbeatReplay) || res.ReplayStreak != 2 {
		t.Fatalf("应为 replay 且计数 2，实际 err=%v streak=%d", err, res.ReplayStreak)
	}
	// replay 3 → 触发重置（递增 + 跨度满足）。
	c.advance(10 * time.Second)
	res, err = tr.Heartbeat(cNode, cSession, base.Add(-time.Minute+2*time.Second))
	if err != nil || !res.BaselineReset {
		t.Fatalf("第 3 次递增 replay 应重置并接受，实际 err=%v reset=%v", err, res.BaselineReset)
	}
	t.Log("[C4] duplicate 不计入连续计数（序列：duplicate=0、replay=1、duplicate=1、replay=2、replay=3→重置）")
}

// TestC5_AcceptedHeartbeatResetsCounter（C5）任一被接受的心跳清零计数与候选。
func TestC5_AcceptedHeartbeatResetsCounter(t *testing.T) {
	tr, c := newC(t)
	high := armBaseline(t, tr, cSession)
	low := base.Add(-10 * time.Minute)

	// 累积 2 次 replay（未达阈值）。
	for i := 1; i <= 2; i++ {
		c.advance(10 * time.Second)
		if _, err := tr.Heartbeat(cNode, cSession, low.Add(time.Duration(i)*time.Second)); !errors.Is(err, ErrHeartbeatReplay) {
			t.Fatalf("第 %d 次应为 replay，实际 %v", i, err)
		}
	}
	// 一次**被接受**的心跳（高于基线）→ 清零计数与候选。
	c.advance(10 * time.Second)
	accepted := high.Add(time.Minute)
	if _, err := tr.Heartbeat(cNode, cSession, accepted); err != nil {
		t.Fatalf("高于基线的心跳应被接受：%v", err)
	}
	// 之后再来 2 次递增 replay → 不应重置（计数已清零，只到 2）。
	for i := 1; i <= 2; i++ {
		c.advance(10 * time.Second)
		res, err := tr.Heartbeat(cNode, cSession,
			low.Add(time.Duration(i)*time.Second))
		if !errors.Is(err, ErrHeartbeatReplay) {
			t.Fatalf("清零后第 %d 次应为 replay，实际 %v", i, err)
		}
		if res.ReplayStreak != i {
			t.Fatalf("清零后计数应从 1 重新开始：第 %d 次应为 %d，实际 %d",
				i, i, res.ReplayStreak)
		}
		if res.BaselineReset {
			t.Fatalf("计数未达阈值不得重置（第 %d 次）", i)
		}
	}
	t.Log("[C5] 被接受的心跳清零计数与候选（之后需重新累积 3 次才可能重置）")
}
