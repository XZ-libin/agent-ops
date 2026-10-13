// Package nodesweep 是控制面的**周期到期扫描器**（第二十四轮 T2）。
//
// 解决的问题（缺口 2）：第二十三轮的到期提醒只在**心跳到达时**判定。
// 而"续期失败"的典型症状恰恰是节点沉默——心跳不再到达，于是提醒**永远不会触发**，
// 直到证书过期、节点彻底失联才发现。本包把判定搬到服务端的**周期扫描**：
// 无论节点是否说话，只要它的 active 证书临近到期就会被标记。
//
// 本包只做两件事，都**只写审计**：
//
//	① active 证书剩余 < 48h（工程默认，待确认）→ node.cert_expiry_risk
//	   条件：自上次成功续期以来没有新签发（即没有更新的 issued/active 证书）。
//	   节流：同一节点每 6 小时最多一条（**上次写入时刻持久化**，跨重启有效）。
//	② issued 状态超过 24 小时仍未确认 → node.cert_unconfirmed（信息级）
//
// **不改变节点状态，也不改变证书状态**（扫描器是纯观察者）。
//
// # 单实例约束
//
// 扫描器**必须单实例运行**：本实现没有 lease 协调，多实例会各自扫描并重复写审计
// （节流靠数据库仍能挡住重复告警，但 `node.cert_unconfirmed` 等非节流事件会重复）。
// 多实例部署前必须先实现 lease 协调（见 docs/ops/node-cert-lifecycle.md）。
package nodesweep

import (
	"context"
	"errors"
	"regexp"
	"time"
)

// 默认参数（**工程默认，待确认**）。
const (
	// DefaultInterval 扫描周期：5 分钟。
	DefaultInterval = 5 * time.Minute
	// DefaultExpiryThreshold 剩余有效期告警阈值：48 小时。
	DefaultExpiryThreshold = 48 * time.Hour
	// DefaultThrottleGap 同一节点同一事件的告警最小间隔：6 小时。
	DefaultThrottleGap = 6 * time.Hour
	// DefaultUnconfirmedAge issued 超过该时长仍未确认 → 标记：24 小时。
	DefaultUnconfirmedAge = 24 * time.Hour
)

// 扫描事件名（写入节流状态表；与审计动作同名以便对照）。
const (
	// EventExpiryRisk 到期风险。
	EventExpiryRisk = "node.cert_expiry_risk"
	// EventUnconfirmed issued 超期未确认。
	EventUnconfirmed = "node.cert_unconfirmed"
)

// tablePattern 表名必须是 test_ 前缀的小写标识符（DDL 拼装，杜绝注入）。
var tablePattern = regexp.MustCompile(`^test_[a-z0-9_]+$`)

// ErrBadTable 表名不合法。
var ErrBadTable = errors.New("nodesweep：表名必须以 test_ 开头且为合法标识符")

// Config 配置。
type Config struct {
	// Interval 扫描周期（<=0 用 DefaultInterval）。
	Interval time.Duration
	// ExpiryThreshold 剩余有效期告警阈值（<=0 用 DefaultExpiryThreshold）。
	ExpiryThreshold time.Duration
	// ThrottleGap 同节点同事件最小间隔（<=0 用 DefaultThrottleGap）。
	ThrottleGap time.Duration
	// UnconfirmedAge issued 超期未确认阈值（<=0 用 DefaultUnconfirmedAge）。
	UnconfirmedAge time.Duration
	// SweepStateTable 节流状态表（默认 test_node_sweep_state）。
	SweepStateTable string
}

// classifyConfig 只用于构建时校验（把默认值填齐）。
func (c Config) withDefaults() Config {
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.ExpiryThreshold <= 0 {
		c.ExpiryThreshold = DefaultExpiryThreshold
	}
	if c.ThrottleGap <= 0 {
		c.ThrottleGap = DefaultThrottleGap
	}
	if c.UnconfirmedAge <= 0 {
		c.UnconfirmedAge = DefaultUnconfirmedAge
	}
	if c.SweepStateTable == "" {
		c.SweepStateTable = "test_node_sweep_state"
	}
	return c
}

// ExpiryFinding 一条到期风险发现。
type ExpiryFinding struct {
	// NodeID 节点。
	NodeID string
	// Serial 当前 active 证书序列号。
	Serial string
	// NotAfter 到期时刻。
	NotAfter time.Time
	// Remaining 剩余有效期。
	Remaining time.Duration
	// Reported 本次是否真的写了审计（受 6 小时节流控制）。
	Reported bool
}

// UnconfirmedFinding 一条"未确认超期"发现。
type UnconfirmedFinding struct {
	// NodeID 节点。
	NodeID string
	// Serial 未确认的序列号。
	Serial string
	// IssuedAt 签发时刻。
	IssuedAt time.Time
	// Age 已签发时长。
	Age time.Duration
	// Reported 本次是否真的写了审计（受节流控制）。
	Reported bool
}

// Result 一次扫描的结果。
type Result struct {
	// Expiry 到期风险发现。
	Expiry []ExpiryFinding
	// Unconfirmed 未确认超期发现。
	Unconfirmed []UnconfirmedFinding
	// Audited 本次写入的审计条数（= Reported 的数量之和）。
	Audited int
}

// Dependencies 扫描器依赖（接口化便于测试注入与解耦）。
type Dependencies struct {
	// NodeIDs 列出全部节点 ID。
	NodeIDs func(ctx context.Context) ([]string, error)
	// ActiveCerts 列出某节点的 active 证书（通常 0 或 1 张）。
	ActiveCerts func(ctx context.Context, nodeID string) ([]Cert, error)
	// HasNewerThan 判定"自 at 之后是否有更新的证书被签发或确认"
	// （有更新的证书 ⇒ 说明续期在进行中，不告警）。
	HasNewerThan func(ctx context.Context, nodeID string, at time.Time) (bool, error)
	// StaleIssued 列出某节点签发早于 before 仍未确认的 issued 证书。
	StaleIssued func(ctx context.Context, nodeID string, before time.Time) ([]Cert, error)
	// LastEmit 读取上次告警时刻（零值表示从未写过）。
	LastEmit func(ctx context.Context, nodeID, event string) (time.Time, error)
	// RecordEmit 记录本次告警时刻。
	RecordEmit func(ctx context.Context, nodeID, event string, at time.Time) error
	// Audit 写一条审计（action 为 EventExpiryRisk / EventUnconfirmed）。
	Audit func(ctx context.Context, nodeID, action string, payload map[string]any)
	// Now 注入时钟（必填）。
	Now func() time.Time
}

// Cert 扫描器视角的一张证书（只读快照）。
type Cert struct {
	// Serial 序列号。
	Serial string
	// NodeID 所属节点。
	NodeID string
	// IssuedAt 签发时刻。
	IssuedAt time.Time
	// NotAfter 到期时刻。
	NotAfter time.Time
}

// Sweeper 周期扫描器。
type Sweeper struct {
	cfg   Config
	dep   Dependencies
	OnRan func(Result) // 可选回调（测试/指标用）
}

// New 构建扫描器（校验依赖，fail-closed）。
func New(cfg Config, dep Dependencies) (*Sweeper, error) {
	if dep.NodeIDs == nil || dep.ActiveCerts == nil || dep.HasNewerThan == nil ||
		dep.StaleIssued == nil || dep.LastEmit == nil || dep.RecordEmit == nil ||
		dep.Audit == nil {
		return nil, errors.New("nodesweep：依赖不完整（NodeIDs/ActiveCerts/HasNewerThan/" +
			"StaleIssued/LastEmit/RecordEmit/Audit 均必填）")
	}
	if dep.Now == nil {
		return nil, errors.New("nodesweep：必须注入时钟（Dependencies.Now）")
	}
	return &Sweeper{cfg: cfg.withDefaults(), dep: dep}, nil
}

// Interval 返回生效的扫描周期。
func (s *Sweeper) Interval() time.Duration { return s.cfg.Interval }

// ExpiryThreshold 返回生效的到期阈值。
func (s *Sweeper) ExpiryThreshold() time.Duration { return s.cfg.ExpiryThreshold }

// ThrottleGap 返回生效的节流间隔。
func (s *Sweeper) ThrottleGap() time.Duration { return s.cfg.ThrottleGap }

// UnconfirmedAge 返回生效的未确认阈值。
func (s *Sweeper) UnconfirmedAge() time.Duration { return s.cfg.UnconfirmedAge }

// RunOnce 执行一次扫描（**只写审计，不改状态**）。
func (s *Sweeper) RunOnce(ctx context.Context) (Result, error) {
	now := s.dep.Now().UTC()
	var res Result

	nodes, err := s.dep.NodeIDs(ctx)
	if err != nil {
		return res, err
	}
	for _, nodeID := range nodes {
		actives, aerr := s.dep.ActiveCerts(ctx, nodeID)
		if aerr != nil {
			return res, aerr
		}
		for _, cert := range actives {
			remaining := cert.NotAfter.Sub(now)
			if remaining > s.cfg.ExpiryThreshold {
				continue
			}
			// 条件：**自上次成功续期以来没有新签发**。
			// 以"该 active 证书的确认时刻"为参照点：若之后有更新的证书签发/确认，
			// 说明续期正在进行（节点不是沉默的），本次不告警。
			newer, herr := s.dep.HasNewerThan(ctx, nodeID, cert.IssuedAt)
			if herr != nil {
				return res, herr
			}
			if newer {
				continue
			}
			finding := ExpiryFinding{NodeID: nodeID, Serial: cert.Serial,
				NotAfter: cert.NotAfter, Remaining: remaining}
			reported, rerr := s.emit(ctx, nodeID, EventExpiryRisk, now, map[string]any{
				"node_id":      nodeID,
				"cert_serial":  cert.Serial,
				"remaining_ms": remaining.Milliseconds(),
				"threshold":    s.cfg.ExpiryThreshold.String(),
				"not_after":    cert.NotAfter.UTC().Format(time.RFC3339),
			})
			if rerr != nil {
				return res, rerr
			}
			finding.Reported = reported
			if reported {
				res.Audited++
			}
			res.Expiry = append(res.Expiry, finding)
		}

		// 未确认超期（信息级）。
		stale, serr := s.dep.StaleIssued(ctx, nodeID, now.Add(-s.cfg.UnconfirmedAge))
		if serr != nil {
			return res, serr
		}
		for _, cert := range stale {
			age := now.Sub(cert.IssuedAt)
			finding := UnconfirmedFinding{NodeID: nodeID, Serial: cert.Serial,
				IssuedAt: cert.IssuedAt, Age: age}
			reported, rerr := s.emit(ctx, nodeID, EventUnconfirmed, now, map[string]any{
				"node_id":     nodeID,
				"cert_serial": cert.Serial,
				"age_ms":      age.Milliseconds(),
				"threshold":   s.cfg.UnconfirmedAge.String(),
				"issued_at":   cert.IssuedAt.UTC().Format(time.RFC3339),
			})
			if rerr != nil {
				return res, rerr
			}
			finding.Reported = reported
			if reported {
				res.Audited++
			}
			res.Unconfirmed = append(res.Unconfirmed, finding)
		}
	}

	if s.OnRan != nil {
		s.OnRan(res)
	}
	return res, nil
}

// emit 按节流规则写审计：同节点同事件在 ThrottleGap 内只写一次。
//
// 节流状态**持久化**（LastEmit/RecordEmit），跨控制面重启有效。
func (s *Sweeper) emit(ctx context.Context, nodeID, event string, now time.Time,
	payload map[string]any) (bool, error) {
	last, err := s.dep.LastEmit(ctx, nodeID, event)
	if err != nil {
		return false, err
	}
	if !last.IsZero() && now.Sub(last) < s.cfg.ThrottleGap {
		return false, nil // 节流窗口内：不写
	}
	if err := s.dep.RecordEmit(ctx, nodeID, event, now); err != nil {
		return false, err
	}
	s.dep.Audit(ctx, nodeID, event, payload)
	return true, nil
}

// Run 按 Interval 周期执行扫描，直到 ctx 取消（优雅停机）。
//
// 时钟注入：等待用 Sleep（由调用方注入，测试中替换为受控实现），
// **不接受真实 sleep**（硬性约束 11）。
func (s *Sweeper) Run(ctx context.Context, sleep func(context.Context, time.Duration) bool) error {
	if sleep == nil {
		return errors.New("nodesweep：必须注入 Sleep（禁止真实 sleep）")
	}
	for {
		if _, err := s.RunOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !sleep(ctx, s.cfg.Interval) {
			return nil // ctx 取消：优雅停机
		}
	}
}
