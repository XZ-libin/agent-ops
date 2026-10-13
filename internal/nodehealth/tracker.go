// Package nodehealth 承载心跳与**离线判定**的纯逻辑
// （第二十一轮 N5；第二十二轮 D1 修订；**第二十三轮 D6 会话基线**）。
//
// D1 语义（取代 ADR-020 §5 的"注册时刻锚点"）：
//   - **存活以控制面接收时间 `received_at` 为准**（即本包的注入时钟），
//     不使用节点自报时间；
//   - `sent_at` **只用于防重放**：同一**会话**内必须**严格递增**
//     （小于 → `replay`；等于 → `duplicate`；两者都**拒绝且不刷新任何状态**）；
//
// D6 语义（第二十三轮，修复"时钟回拨后永久失联"）：
//
//   - 防重放基线按 **(node_id, boot_session_id)** 维护；`boot_session_id` 由节点
//     **进程启动**时生成（ULID）；
//
//   - **新会话**的首个心跳**不与旧会话基线比较**（时钟回拨/重启后不会永久被拒）；
//
//   - 同一会话内**连续 3 次** replay（工程默认，待确认），**且同时满足**
//     ①被拒的 `sent_at` 之间严格递增（说明是一条正在前进的新时钟，而非随机低值）、
//     ②这几次的 `received_at` 跨度 ≥ 20 秒（工程默认，待确认）——服务端才把基线
//     **重置为当前 `sent_at`** 并返回 `BaselineReset=true`（由调用方写
//     `node.clock_regression_reset` 审计）。
//
//     **为什么加这两个条件**：最初的实现只数"连续 3 次 replay"，攻击者（或一次
//     短时抖动）能用 3 个随机低值触发重置，使 replay 检测在 3 个心跳窗口内失效。
//     加上"单调 + 时间跨度"后，只有**真实的时钟回拨**（新时钟稳定前进、且跨越了
//     足够的观测时间）才会触发重置。
//
//   - `duplicate` **不计入**连续 replay 计数，也不参与重置判定；
//
//   - **任一被接受的心跳清零计数与候选序列**。
//
//   - 时钟偏差 `skew = received_at − sent_at` 只**记录与告警**，
//     **不拒绝、不离线**（阈值 warn=5s / alert=30s，工程默认，待运维确认）；
//
//   - 偏差**级别变化**时才需要写一条 `clock_skew` 审计（不逐条刷屏）；
//
//   - **删除注册时刻锚点**：首个心跳的 `sent_at` 可以早于注册时刻，只要单调递增。
//
// 本包不依赖数据库与网络：状态保存在内存，落库与审计由调用方负责（N6）。
package nodehealth

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// 默认参数。
const (
	// DefaultInterval 心跳间隔：10 秒。
	DefaultInterval = 10 * time.Second
	// DefaultMissThreshold 连续缺失次数阈值：3 次（= 30 秒）。
	DefaultMissThreshold = 3
	// DefaultSkewWarn 时钟偏差告警阈值：5 秒（工程默认，待运维确认）。
	DefaultSkewWarn = 5 * time.Second
	// DefaultSkewAlert 时钟偏差强告警阈值：30 秒（工程默认，待运维确认）。
	DefaultSkewAlert = 30 * time.Second
	// DefaultReplayResetThreshold 同一会话内**连续 replay** 达到该次数后重置基线
	// （D6；工程默认，待确认）。重置避免节点在时钟回拨后永久失联。
	DefaultReplayResetThreshold = 3
	// DefaultReplayResetMinSpan 触发重置所需的**最小观测跨度**（C3；工程默认，待确认）。
	//
	// 语义：从"第一次被拒的 replay"到"触发重置的那次"之间，控制面**接收时间**
	// 的跨度必须 ≥ 该值。取 20 秒 ≈ 2 个心跳周期，足以排除"一次网络抖动里
	// 连发 3 个伪造低值"的廉价攻击，同时远小于节点时钟追平所需的时间。
	DefaultReplayResetMinSpan = 20 * time.Second
)

// Status 节点状态。
type Status string

const (
	// StatusOnline 心跳正常。
	StatusOnline Status = "online"
	// StatusOffline 连续缺失达到阈值。
	StatusOffline Status = "offline"
	// StatusRevoked 证书被吊销（D3；**不可恢复为 online**，只能重新注册）。
	StatusRevoked Status = "revoked"
)

// 心跳拒绝/迁移原因（机器可读短语，不含任何敏感值）。
const (
	// ReasonEnrolled 注册登记。
	ReasonEnrolled = "enrolled"
	// ReasonHeartbeat 正常心跳。
	ReasonHeartbeat = "heartbeat"
	// ReasonHeartbeatRecovered 掉线后恢复。
	ReasonHeartbeatRecovered = "heartbeat_recovered"
	// ReasonMissedHeartbeats 连续缺失导致离线。
	ReasonMissedHeartbeats = "missed_heartbeats"
	// ReasonReplay sent_at 回退（重放）。
	ReasonReplay = "replay"
	// ReasonDuplicate sent_at 相同（重复）。
	ReasonDuplicate = "duplicate"
	// ReasonNoChange 判定后无状态变化。
	ReasonNoChange = "no_change"
	// ReasonRevoked 证书已吊销。
	ReasonRevoked = "revoked"
	// ReasonClockRegressionReset 连续 replay 后重置防重放基线（D6）。
	ReasonClockRegressionReset = "clock_regression_reset"
)

// 错误。
var (
	// ErrUnknownNode 未注册的节点（无状态记录）。
	ErrUnknownNode = errors.New("nodehealth：未知节点（未注册）")
	// ErrHeartbeatReplay sent_at 早于上一次被接受的 sent_at（重放）。
	ErrHeartbeatReplay = errors.New("nodehealth：心跳 sent_at 回退（replay），已拒绝且未刷新状态")
	// ErrHeartbeatDuplicate sent_at 与上一次相同（重复）。
	ErrHeartbeatDuplicate = errors.New("nodehealth：心跳 sent_at 重复（duplicate），已拒绝且未刷新状态")
	// ErrTimestampMissing 心跳缺少 sent_at。
	ErrTimestampMissing = errors.New("nodehealth：心跳缺少 sent_at")
	// ErrNodeRevoked 节点已被吊销（证书吊销后不可恢复）。
	ErrNodeRevoked = errors.New("nodehealth：节点已被吊销（revoked），拒绝心跳")
)

// SkewLevel 时钟偏差级别。
type SkewLevel string

const (
	// SkewNone 偏差在 warn 阈值内。
	SkewNone SkewLevel = ""
	// SkewWarn 偏差超过 warn 阈值。
	SkewWarn SkewLevel = "warn"
	// SkewAlert 偏差超过 alert 阈值。
	SkewAlert SkewLevel = "alert"
)

// Transition 一次状态变化（供审计写入；From==To 时表示无变化）。
type Transition struct {
	// NodeID 节点身份。
	NodeID string
	// From 变化前状态；空串表示首次记录。
	From Status
	// To 变化后状态。
	To Status
	// Reason 变化原因（机器可读短语）。
	Reason string
	// Misses 判定时的连续缺失次数。
	Misses int
	// At 判定时刻（= 控制面接收时间）。
	At time.Time
}

// Changed 是否发生了状态变化（true 才需要写状态迁移审计）。
func (t Transition) Changed() bool { return t.From != t.To }

// String 便于日志与测试输出。
func (t Transition) String() string {
	return fmt.Sprintf("node=%s %s→%s misses=%d reason=%s",
		t.NodeID, orNone(string(t.From)), t.To, t.Misses, t.Reason)
}

// HeartbeatResult 一次心跳的处理结果。
type HeartbeatResult struct {
	// Transition 状态迁移（可能无变化）。
	Transition Transition
	// ReceivedAt 控制面接收时间（存活判定依据）。
	ReceivedAt time.Time
	// SentAt 节点自报时间（仅用于防重放与偏差观测）。
	SentAt time.Time
	// Skew 本次偏差（received_at − sent_at，带符号）。
	Skew time.Duration
	// SkewLevel 本次偏差级别（按 |skew| 判定）。
	SkewLevel SkewLevel
	// SkewReported 是否需要写一条 clock_skew 审计（**级别变化**时为 true）。
	SkewReported bool

	// —— D6 ——
	// BootSessionID 本次心跳所属会话。
	BootSessionID string
	// NewSession true 表示这是**新会话**的首个心跳（基线已切换，不与旧会话比较）。
	NewSession bool
	// BaselineReset true 表示因连续 replay 达到阈值而**重置了基线**
	// （调用方需写 node.clock_regression_reset 审计）。
	BaselineReset bool
	// ReplayStreak 重置时的连续 replay 次数（审计用）。
	ReplayStreak int
	// ResetSpan 触发重置时的接收时间跨度（审计用；未触发时为 0）。
	ResetSpan time.Duration
}

// NodeSnapshot 单个节点的可持久化状态快照（N6 落库/恢复用）。
type NodeSnapshot struct {
	NodeID         string
	Status         Status
	LastReceivedAt time.Time
	LastSentAt     time.Time
	LastSkew       time.Duration
	Misses         int
	// BootSessionID / SessionSentAt（D6）当前会话与基线，重启恢复后继续沿用。
	BootSessionID string
	SessionSentAt time.Time
}

// Config 判定参数。
type Config struct {
	// Interval 心跳间隔（<=0 用 DefaultInterval）。
	Interval time.Duration
	// MissThreshold 连续缺失阈值（<=0 用 DefaultMissThreshold）。
	MissThreshold int
	// SkewWarn 偏差告警阈值（<=0 用 DefaultSkewWarn）。
	SkewWarn time.Duration
	// SkewAlert 偏差强告警阈值（<=0 用 DefaultSkewAlert）。
	SkewAlert time.Duration
	// ReplayResetThreshold 同会话连续 replay 重置阈值
	// （<=0 用 DefaultReplayResetThreshold=3）。
	ReplayResetThreshold int
	// ReplayResetMinSpan 触发重置所需的最小接收时间跨度
	// （<=0 用 DefaultReplayResetMinSpan=20s）。
	ReplayResetMinSpan time.Duration
	// Now 注入时钟（必填；= 控制面接收时间来源）。
	Now func() time.Time
}

// nodeState 单个节点的判定状态。
type nodeState struct {
	status         Status
	lastReceivedAt time.Time // 最近一次**接收**心跳的控制面时刻（存活判定依据）
	lastSkew       time.Duration
	lastSkewLevel  SkewLevel
	misses         int

	// —— D6：防重放基线按会话维护 ——
	bootSessionID string    // 当前会话标识（节点进程启动时生成）
	sessionSentAt time.Time // **当前会话内**最近一次被接受的 sent_at（基线）
	lastSentAt    time.Time // 最近一次被接受的 sent_at（跨会话观测用，D1 兼容）

	// replayStreak 当前会话内**连续** replay 次数（duplicate 不计入）。
	replayStreak int
	// replayCandidates 连续 replay 的候选序列（**只记 replay，不记 duplicate**）：
	// 用于 C1/C2/C3 的三条件判定——严格递增 + 接收时间跨度。
	replayCandidates []replayCandidate
}

// replayCandidate 一次被拒的 replay（用于重置条件的判定）。
type replayCandidate struct {
	// sentAt 被拒的节点自报时间。
	sentAt time.Time
	// receivedAt 控制面接收时间（跨度判定的依据）。
	receivedAt time.Time
}

// Tracker 心跳与离线判定器（并发安全）。
type Tracker struct {
	cfg   Config
	mu    sync.Mutex
	nodes map[string]*nodeState
}

// NewTracker 构建判定器；Now 必填（fail-closed，避免误用真实时钟）。
func NewTracker(cfg Config) (*Tracker, error) {
	if cfg.Now == nil {
		return nil, errors.New("nodehealth：必须注入时钟（Config.Now）")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.MissThreshold <= 0 {
		cfg.MissThreshold = DefaultMissThreshold
	}
	if cfg.SkewWarn <= 0 {
		cfg.SkewWarn = DefaultSkewWarn
	}
	if cfg.SkewAlert <= 0 {
		cfg.SkewAlert = DefaultSkewAlert
	}
	if cfg.SkewAlert < cfg.SkewWarn {
		return nil, errors.New("nodehealth：SkewAlert 不得小于 SkewWarn")
	}
	if cfg.ReplayResetThreshold <= 0 {
		cfg.ReplayResetThreshold = DefaultReplayResetThreshold
	}
	if cfg.ReplayResetMinSpan <= 0 {
		cfg.ReplayResetMinSpan = DefaultReplayResetMinSpan
	}
	return &Tracker{cfg: cfg, nodes: map[string]*nodeState{}}, nil
}

// Register 登记一个已注册节点（注册成功后调用），初始状态为 online。
//
// **不锚定 sent_at**（D1：删除注册时刻锚点）——首个心跳的 sent_at 可以早于注册时刻。
func (t *Tracker) Register(nodeID string) Transition {
	now := t.cfg.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodes[nodeID] = &nodeState{status: StatusOnline, lastReceivedAt: now}
	return Transition{NodeID: nodeID, From: "", To: StatusOnline, Reason: ReasonEnrolled, At: now}
}

// Restore 用快照恢复节点状态（N6：控制面重启后恢复）。
func (t *Tracker) Restore(snap NodeSnapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodes[snap.NodeID] = &nodeState{
		status:         snap.Status,
		lastReceivedAt: snap.LastReceivedAt,
		lastSentAt:     snap.LastSentAt,
		lastSkew:       snap.LastSkew,
		misses:         snap.Misses,
		bootSessionID:  snap.BootSessionID,
		sessionSentAt:  snap.SessionSentAt,
	}
}

// Snapshot 返回节点状态快照（N6 落库用）。
func (t *Tracker) Snapshot(nodeID string) (NodeSnapshot, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.nodes[nodeID]
	if !ok {
		return NodeSnapshot{}, ErrUnknownNode
	}
	return NodeSnapshot{
		NodeID: nodeID, Status: st.status,
		LastReceivedAt: st.lastReceivedAt, LastSentAt: st.lastSentAt,
		LastSkew: st.lastSkew, Misses: st.misses,
		BootSessionID: st.bootSessionID, SessionSentAt: st.sessionSentAt,
	}, nil
}

// Revoke 把节点标记为 revoked（D3：不可恢复为 online）。
func (t *Tracker) Revoke(nodeID string) (Transition, error) {
	now := t.cfg.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.nodes[nodeID]
	if !ok {
		return Transition{}, ErrUnknownNode
	}
	from := st.status
	st.status = StatusRevoked
	return Transition{NodeID: nodeID, From: from, To: StatusRevoked,
		Reason: ReasonRevoked, Misses: st.misses, At: now}, nil
}

// Heartbeat 处理一次心跳（D6：基线按会话维护）。
//
// 参数 bootSessionID 由节点**进程启动**时生成；为空时视为"无会话信息"，
// 退回 D1 的"跨会话单调"语义（仅用于兼容旧节点，**会**在时钟回拨后失联）。
//
// 顺序：
//  1. 未知节点 → ErrUnknownNode；
//  2. 已吊销 → ErrNodeRevoked（不刷新任何状态）；
//  3. sent_at 缺失 → ErrTimestampMissing；
//  4. **会话切换**（bootSessionID 非空且与当前会话不同）：
//     基线切换到本次 sent_at，**不与旧会话比较**（`NewSession=true`）；
//  5. **同会话**严格递增：小于 → replay；等于 → duplicate
//     （**都不刷新任何状态**）；
//  6. **连续 replay 达到阈值**（默认 3）→ 基线重置为当前 sent_at，
//     返回 `BaselineReset=true`（调用方写 node.clock_regression_reset 审计），
//     并**按正常心跳接受**（否则节点会一直失联）；
//  7. 接受：刷新 last_received_at / 基线 / 清零 misses；offline → online；
//  8. 计算偏差并判定级别（只记录与告警，**不影响接受与在线状态**）。
func (t *Tracker) Heartbeat(nodeID, bootSessionID string, sentAt time.Time) (HeartbeatResult, error) {
	receivedAt := t.cfg.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.nodes[nodeID]
	if !ok {
		return HeartbeatResult{BootSessionID: bootSessionID, ReceivedAt: receivedAt, SentAt: sentAt,
				Transition: Transition{NodeID: nodeID, Reason: ReasonNoChange, At: receivedAt}},
			ErrUnknownNode
	}
	if st.status == StatusRevoked {
		return HeartbeatResult{BootSessionID: bootSessionID, ReceivedAt: receivedAt, SentAt: sentAt,
			Transition: Transition{NodeID: nodeID, From: StatusRevoked, To: StatusRevoked,
				Reason: ReasonRevoked, At: receivedAt}}, ErrNodeRevoked
	}
	if sentAt.IsZero() {
		return HeartbeatResult{BootSessionID: bootSessionID, ReceivedAt: receivedAt},
			ErrTimestampMissing
	}
	sent := sentAt.UTC()

	session := strings.TrimSpace(bootSessionID)
	newSession := false

	switch {
	case session != "" && session != st.bootSessionID:
		// ④ 会话切换（含首个心跳）：建立新基线，**不与旧会话比较**。
		//    D6 的核心：节点重启或时钟回拨后不会被旧基线永久拒绝。
		newSession = true
		st.bootSessionID = session
		st.sessionSentAt = time.Time{}
		st.replayStreak = 0
		st.replayCandidates = nil
	case session == "" && st.bootSessionID != "":
		// 节点未提供会话信息（旧版本）：沿用当前会话继续比较，不切换。
		session = st.bootSessionID
	}

	// ⑤ 同会话严格递增（基线为空时直接建立）。
	if !st.sessionSentAt.IsZero() {
		switch {
		case sent.Before(st.sessionSentAt):
			// replay：计数 + 记候选（C1/C2/C3 用）。
			st.replayStreak++
			st.replayCandidates = append(st.replayCandidates, replayCandidate{
				sentAt: sent, receivedAt: receivedAt,
			})
			res := HeartbeatResult{
				BootSessionID: firstNonEmpty(session, st.bootSessionID),
				ReceivedAt:    receivedAt, SentAt: sent, ReplayStreak: st.replayStreak,
				Transition: Transition{NodeID: nodeID, From: st.status, To: st.status,
					Reason: ReasonReplay, Misses: st.misses, At: receivedAt},
			}
			if eligible, streak, span := st.resetEligible(t.cfg.ReplayResetThreshold,
				t.cfg.ReplayResetMinSpan); eligible {
				st.sessionSentAt = sent
				st.replayStreak = 0
				st.replayCandidates = nil
				res.BaselineReset = true
				res.ReplayStreak = streak
				res.ResetSpan = span
				return t.accept(nodeID, st, sent, receivedAt, res), nil
			}
			return res, ErrHeartbeatReplay
		case sent.Equal(st.sessionSentAt):
			// duplicate：**不计入**连续 replay 计数（C4），也不改变候选序列。
			res := HeartbeatResult{
				BootSessionID: firstNonEmpty(session, st.bootSessionID),
				ReceivedAt:    receivedAt, SentAt: sent, ReplayStreak: st.replayStreak,
				Transition: Transition{NodeID: nodeID, From: st.status, To: st.status,
					Reason: ReasonDuplicate, Misses: st.misses, At: receivedAt},
			}
			return res, ErrHeartbeatDuplicate
		}
	}

	res := HeartbeatResult{
		BootSessionID: firstNonEmpty(session, st.bootSessionID),
		NewSession:    newSession, ReceivedAt: receivedAt, SentAt: sent,
	}
	return t.accept(nodeID, st, sent, receivedAt, res), nil
}

// accept 接受一次心跳：刷新基线、存活时间与在线状态，并计算偏差级别。
//
// 调用方必须已持有 t.mu。
func (t *Tracker) accept(nodeID string, st *nodeState, sent, receivedAt time.Time,
	res HeartbeatResult) HeartbeatResult {
	from := st.status
	st.sessionSentAt = sent
	st.lastSentAt = sent
	st.lastReceivedAt = receivedAt
	st.misses = 0
	st.replayStreak = 0
	st.replayCandidates = nil
	st.status = StatusOnline
	reason := ReasonHeartbeat
	if from != StatusOnline {
		reason = ReasonHeartbeatRecovered
	}
	skew := receivedAt.Sub(sent)
	st.lastSkew = skew
	level := t.skewLevel(skew)
	reported := level != st.lastSkewLevel
	st.lastSkewLevel = level

	res.Transition = Transition{NodeID: nodeID, From: from, To: StatusOnline,
		Reason: reason, Misses: 0, At: receivedAt}
	res.ReceivedAt = receivedAt
	res.SentAt = sent
	res.Skew = skew
	res.SkewLevel = level
	res.SkewReported = reported
	return res
}

// resetEligible 判定是否满足**重置基线的三个条件**（T3 加固）。
//
// 条件（**必须同时满足**）：
//
//	① 连续 replay 次数达到阈值；
//	② 这些被拒的 `sent_at` 之间**严格递增**（说明是一条正在前进的新时钟，
//	   而不是随机低值——C2）；
//	③ 首个候选到当前的**接收时间跨度** ≥ minSpan（排除一次抖动里连发 3 个
//	   伪造低值的廉价攻击——C3）。
//
// 返回（是否可重置, 连续次数, 跨度）。调用方负责清零计数与候选。
func (st *nodeState) resetEligible(threshold int, minSpan time.Duration) (bool, int, time.Duration) {
	if len(st.replayCandidates) < threshold || st.replayStreak < threshold {
		return false, st.replayStreak, 0
	}
	// 只看最近 threshold 个候选。
	recent := st.replayCandidates[len(st.replayCandidates)-threshold:]
	// ② 严格递增。
	for i := 1; i < len(recent); i++ {
		if !recent[i].sentAt.After(recent[i-1].sentAt) {
			return false, st.replayStreak, 0
		}
	}
	// ③ 接收时间跨度。
	span := recent[len(recent)-1].receivedAt.Sub(recent[0].receivedAt)
	if span < minSpan {
		return false, st.replayStreak, span
	}
	return true, st.replayStreak, span
}

// firstNonEmpty 返回第一个非空字符串（会话标识回填用）。
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// skewLevel 按 |skew| 判定偏差级别（节点快/慢都告警）。
func (t *Tracker) skewLevel(skew time.Duration) SkewLevel {
	abs := skew
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs > t.cfg.SkewAlert:
		return SkewAlert
	case abs > t.cfg.SkewWarn:
		return SkewWarn
	}
	return SkewNone
}

// Evaluate 按控制面时钟判定某节点是否应转为 offline。
func (t *Tracker) Evaluate(nodeID string) (Transition, error) {
	now := t.cfg.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.nodes[nodeID]
	if !ok {
		return Transition{}, ErrUnknownNode
	}
	return t.evaluateLocked(nodeID, st, now), nil
}

// EvaluateAll 对所有已登记节点判定，返回**发生了状态变化**的迁移（供写审计）。
func (t *Tracker) EvaluateAll() []Transition {
	now := t.cfg.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Transition
	for id, st := range t.nodes {
		if tr := t.evaluateLocked(id, st, now); tr.Changed() {
			out = append(out, tr)
		}
	}
	return out
}

// evaluateLocked 判定单个节点（需持有锁）。
//
// 缺失次数基于 **received_at**（控制面接收时间）计算；revoked 节点不参与判定。
func (t *Tracker) evaluateLocked(nodeID string, st *nodeState, now time.Time) Transition {
	if st.status == StatusRevoked {
		return Transition{NodeID: nodeID, From: StatusRevoked, To: StatusRevoked,
			Reason: ReasonRevoked, At: now}
	}
	elapsed := now.Sub(st.lastReceivedAt)
	misses := 0
	if elapsed > 0 {
		misses = int(elapsed / t.cfg.Interval)
	}
	st.misses = misses
	if misses >= t.cfg.MissThreshold && st.status != StatusOffline {
		from := st.status
		st.status = StatusOffline
		return Transition{NodeID: nodeID, From: from, To: StatusOffline,
			Reason: ReasonMissedHeartbeats, Misses: misses, At: now}
	}
	return Transition{NodeID: nodeID, From: st.status, To: st.status,
		Reason: ReasonNoChange, Misses: misses, At: now}
}

// Status 返回节点当前状态与最近一次**接收**心跳的控制面时刻。
func (t *Tracker) Status(nodeID string) (Status, time.Time, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.nodes[nodeID]
	if !ok {
		return "", time.Time{}, ErrUnknownNode
	}
	return st.status, st.lastReceivedAt, nil
}

// Misses 返回当前连续缺失次数。
func (t *Tracker) Misses(nodeID string) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.nodes[nodeID]
	if !ok {
		return 0, ErrUnknownNode
	}
	return st.misses, nil
}

// LastSkew 返回最近一次记录的时钟偏差（带符号）。
func (t *Tracker) LastSkew(nodeID string) (time.Duration, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.nodes[nodeID]
	if !ok {
		return 0, ErrUnknownNode
	}
	return st.lastSkew, nil
}

// Interval 返回生效的心跳间隔。
func (t *Tracker) Interval() time.Duration { return t.cfg.Interval }

// MissThreshold 返回生效的缺失阈值。
func (t *Tracker) MissThreshold() int { return t.cfg.MissThreshold }

// SkewWarn 返回生效的偏差告警阈值。
func (t *Tracker) SkewWarn() time.Duration { return t.cfg.SkewWarn }

// SkewAlert 返回生效的偏差强告警阈值。
func (t *Tracker) SkewAlert() time.Duration { return t.cfg.SkewAlert }

// orNone 空串显示为 "(new)"。
func orNone(s string) string {
	if s == "" {
		return "(new)"
	}
	return s
}

// ReplayResetThreshold 返回生效的"连续 replay 重置"阈值（D6）。
func (t *Tracker) ReplayResetThreshold() int { return t.cfg.ReplayResetThreshold }

// ReplayResetMinSpan 返回生效的"重置所需最小接收跨度"（T3）。
func (t *Tracker) ReplayResetMinSpan() time.Duration { return t.cfg.ReplayResetMinSpan }
