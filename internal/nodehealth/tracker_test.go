package nodehealth

// N5 心跳与离线判定测试（第二十一轮；第二十二轮 D1 修订后同步更新）。
//
// 与 D1 的差异：存活判定基于控制面**接收时间**；sent_at 只用于防重放且必须严格递增；
// 不再有"注册时刻锚点"。

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestHeartbeatKeepsOnline（N5 ①）正常心跳保持 online。
func TestHeartbeatKeepsOnline(t *testing.T) {
	tr, c := newTracker(t)
	const node = "nod_01M4RHFDJ0AAAAAAAAAAAAAAAA"
	tr.Register(node)

	// 节点侧与控制面同步推进（无偏差）。
	nodeClock := base
	for i := 0; i < 5; i++ {
		if i > 0 {
			c.advance(DefaultInterval)
			nodeClock = nodeClock.Add(DefaultInterval)
		}
		if _, err := tr.Heartbeat(node, testSession, nodeClock); err != nil {
			t.Fatalf("第 %d 次心跳应成功：%v", i+1, err)
		}
		if st, _, _ := tr.Status(node); st != StatusOnline {
			t.Fatalf("第 %d 次心跳后应为 online，实际 %s", i+1, st)
		}
	}
	t.Logf("[N5①] 连续 5 次心跳（间隔 %s）保持 online", DefaultInterval)
}

// TestOfflineAfterThreshold（N5 ②③）缺失 1、2 次仍 online；第 3 次（30 秒）转 offline。
func TestOfflineAfterThreshold(t *testing.T) {
	tr, c := newTracker(t)
	const node = "nod_01M4RHFDJ0BBBBBBBBBBBBBBBB"
	tr.Register(node)

	if tr.Interval() != 10*time.Second || tr.MissThreshold() != 3 {
		t.Fatalf("默认参数应为 10s/3 次，实际 %s/%d", tr.Interval(), tr.MissThreshold())
	}

	// 缺失 1 次（10 秒）：仍 online。
	c.advance(DefaultInterval)
	tr1, _ := tr.Evaluate(node)
	if tr1.To != StatusOnline || tr1.Changed() {
		t.Fatalf("缺失 1 次应保持 online 且无变化：%+v", tr1)
	}
	// 缺失 2 次（20 秒）：仍 online。
	c.advance(DefaultInterval)
	tr2, _ := tr.Evaluate(node)
	if tr2.To != StatusOnline || tr2.Changed() {
		t.Fatalf("缺失 2 次应保持 online 且无变化：%+v", tr2)
	}
	// 缺失 3 次（30 秒）：转 offline。
	c.advance(DefaultInterval)
	tr3, _ := tr.Evaluate(node)
	if tr3.To != StatusOffline || !tr3.Changed() {
		t.Fatalf("缺失 3 次应转 offline 且标记为变化：%+v", tr3)
	}
	if tr3.From != StatusOnline || tr3.Misses != 3 || tr3.Reason != ReasonMissedHeartbeats {
		t.Fatalf("迁移记录不符：%+v", tr3)
	}
	// 继续判定不重复产生变化。
	c.advance(DefaultInterval)
	tr4, _ := tr.Evaluate(node)
	if tr4.Changed() {
		t.Fatalf("已 offline 后重复判定不应产生变化：%+v", tr4)
	}
	t.Logf("[N5②③] 缺失 1/2 次→online；第 3 次（30s）→offline（%s）", tr3)
}

// TestRecoverAfterHeartbeat（N5 ④）恢复心跳后回到 online。
func TestRecoverAfterHeartbeat(t *testing.T) {
	tr, c := newTracker(t)
	const node = "nod_01M4RHFDJ0CCCCCCCCCCCCCCCC"
	tr.Register(node)
	nodeClock := base

	// 掉线。
	c.advance(3 * DefaultInterval)
	if trr, _ := tr.Evaluate(node); trr.To != StatusOffline {
		t.Fatalf("应先转 offline：%+v", trr)
	}
	// 恢复心跳（sent_at 严格递增）。
	nodeClock = nodeClock.Add(time.Second)
	c.advance(time.Second)
	res, err := tr.Heartbeat(node, testSession, nodeClock)
	if err != nil {
		t.Fatalf("恢复心跳应成功：%v", err)
	}
	if res.Transition.From != StatusOffline || res.Transition.To != StatusOnline || !res.Transition.Changed() {
		t.Fatalf("恢复心跳应产生 offline→online 迁移：%+v", res.Transition)
	}
	if res.Transition.Reason != ReasonHeartbeatRecovered {
		t.Fatalf("恢复原因应为 %s：%+v", ReasonHeartbeatRecovered, res.Transition)
	}
	if misses, _ := tr.Misses(node); misses != 0 {
		t.Fatalf("恢复后缺失计数应清零，实际 %d", misses)
	}
	t.Logf("[N5④] 恢复心跳：offline→online（%s），缺失计数清零", res.Transition)
}

// TestEvaluateAllOnlyReturnsChanges（N5）批量判定只返回发生状态变化的迁移。
func TestEvaluateAllOnlyReturnsChanges(t *testing.T) {
	tr, c := newTracker(t)
	nodes := []string{
		"nod_01M4RHFDJ0EEEEEEEEEEEEEEEE",
		"nod_01M4RHFDJ0FFFFFFFFFFFFFFFF",
		"nod_01M4RHFDJ0GGGGGGGGGGGGGGGG",
	}
	for _, n := range nodes {
		tr.Register(n)
	}
	// 让第 1 个节点保持心跳，其余掉线。
	c.advance(2 * DefaultInterval)
	if _, err := tr.Heartbeat(nodes[0], testSession, base.Add(2*DefaultInterval)); err != nil {
		t.Fatal(err)
	}
	c.advance(DefaultInterval)
	trans := tr.EvaluateAll()
	if len(trans) != 2 {
		t.Fatalf("应只有 2 个节点发生 offline 迁移，实际 %d：%v", len(trans), trans)
	}
	for _, tr2 := range trans {
		if tr2.To != StatusOffline || !tr2.Changed() {
			t.Fatalf("迁移记录不符：%+v", tr2)
		}
	}
	if again := tr.EvaluateAll(); len(again) != 0 {
		t.Fatalf("重复判定不应返回变化：%v", again)
	}
	t.Logf("[N5] 批量判定只返回变化项：首次 %d 条 offline 迁移，重复判定 0 条", len(trans))
}

// TestTrackerRequiresInjectedClock（N5 约束）未注入时钟必须拒绝构建。
func TestTrackerRequiresInjectedClock(t *testing.T) {
	if _, err := NewTracker(Config{}); err == nil {
		t.Fatal("未注入时钟必须拒绝构建")
	} else if !strings.Contains(err.Error(), "时钟") {
		t.Fatalf("错误应说明缺少注入时钟：%v", err)
	}
	// 阈值配置校验：alert 不得小于 warn。
	if _, err := NewTracker(Config{Now: time.Now, SkewWarn: time.Minute, SkewAlert: time.Second}); err == nil {
		t.Fatal("SkewAlert < SkewWarn 必须拒绝")
	}
	t.Log("[N5] 未注入时钟 / 阈值倒置 → NewTracker 拒绝（fail-closed）")
}

// TestUnknownNodeRejected（N5）未知节点一律拒绝。
func TestUnknownNodeRejected(t *testing.T) {
	tr, _ := newTracker(t)
	if _, err := tr.Heartbeat("nod_unknown", testSession, base); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("未知节点心跳应拒绝：%v", err)
	}
	if _, err := tr.Evaluate("nod_unknown"); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("未知节点判定应拒绝：%v", err)
	}
	if _, err := tr.Snapshot("nod_unknown"); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("未知节点快照应拒绝：%v", err)
	}
	t.Log("[N5] 未知节点：心跳/判定/快照一律拒绝")
}
