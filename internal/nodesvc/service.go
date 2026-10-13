// Package nodesvc 编排节点身份与健康的完整流程（第二十二轮 N6）。
//
// 职责（只做编排，不复制任何判定逻辑）：
//
//	Enroll        校验令牌 → 原子消费 → 校验 CSR 持有性证明 → 分配 node_id
//	              → 签发证书（7 天）→ 落库 → 写审计
//	Heartbeat     校验证书吊销 → **会话基线**防重放（D6）→ 刷新存活（received_at）
//	              → 待确认旧证书 supersede（T3）→ 偏差记录/告警 → 落库 → 写审计
//	Renew         7 步校验 → 换钥签发新证书 → 状态机记 issued（含未确认上限）→ 写审计（T3/T1）
//	              → **不吊销旧证书**；旧证书在"新序列号被心跳确认"时统一 supersede
//	RevokeCert    写吊销表 → 节点置 revoked → 写审计（D3，终态）
//	IssueReissue  为 revoked 节点补发一次性令牌（T4，仅 test 模式）
//	EvaluateOffline / ExpiryRisks / Restore
//
// 审计约定（N6）：
//   - 节点事件 actor = `node:<node_id>`；
//   - **拒绝事件** actor = `system`；
//   - payload **不含**令牌明文、令牌哈希、CSR 原文、证书 PEM、私钥。
package nodesvc

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/XZ-libin/agent-ops/internal/audit"
	"github.com/XZ-libin/agent-ops/internal/nodecerts"
	"github.com/XZ-libin/agent-ops/internal/nodehealth"
	"github.com/XZ-libin/agent-ops/internal/nodeidentity"
	"github.com/XZ-libin/agent-ops/internal/nodemigrate"
	"github.com/XZ-libin/agent-ops/internal/nodestore"
	"github.com/XZ-libin/agent-ops/internal/nodesweep"
)

// 审计动作（N6）。
const (
	// ActionEnrolled 注册成功。
	ActionEnrolled = "node.enrolled"
	// ActionOnline 节点转为 online。
	ActionOnline = "node.online"
	// ActionOffline 节点转为 offline。
	ActionOffline = "node.offline"
	// ActionClockSkewWarning 时钟偏差级别变化告警。
	ActionClockSkewWarning = "node.clock_skew_warning"
	// ActionCertRevoked 证书被吊销。
	ActionCertRevoked = "node.cert_revoked"
	// ActionEnrollRejected 注册被拒绝（内部 reason 仅供审计，对外统一）。
	ActionEnrollRejected = "node.enroll_rejected"
	// ActionHeartbeatRejected 心跳被拒绝（reason: replay / duplicate / revoked）。
	ActionHeartbeatRejected = "node.heartbeat_rejected"
	// ActionClockRegressionReset 同会话连续 replay 达阈值后重置基线（D6）。
	ActionClockRegressionReset = "node.clock_regression_reset"
	// ActionCertRenewed 证书续期成功（T3）。
	ActionCertRenewed = "node.cert_renewed"
	// ActionCertSuperseded 旧证书被新证书取代，已写入吊销表（T3）。
	ActionCertSuperseded = "node.cert_superseded"
	// ActionRenewRejected 续期被拒绝（内部 reason 仅入审计）。
	ActionRenewRejected = "node.renew_rejected"
	// ActionCertExpiryRisk 剩余有效期不足阈值仍未续期（T3 告警）。
	ActionCertExpiryRisk = "node.cert_expiry_risk"
	// ActionReissueTokenIssued 为 revoked 节点补发一次性令牌（T4）。
	ActionReissueTokenIssued = "node.reissue_token_issued"
	// ActionCertUnconfirmed 扫描器发现 issued 超期未确认（T2，信息级）。
	ActionCertUnconfirmed = "node.cert_unconfirmed"
)

// SupersedeReason 旧证书被取代时写入吊销表的 reason（T3）。
const SupersedeReason = "superseded"

// RevokeReason 主动吊销时写入吊销表的 reason（D3）。
const RevokeReason = "revoked"

// 过期风险阈值与告警节流（T3；工程默认，待确认）。
const (
	// DefaultExpiryRiskThreshold 剩余有效期低于该值仍未续期 → 告警。
	DefaultExpiryRiskThreshold = 48 * time.Hour
	// DefaultExpiryRiskInterval 同一节点告警最小间隔。
	DefaultExpiryRiskInterval = 6 * time.Hour
)

// EnrollMode 运行模式（T4：补发只在 test 模式可用）。
type EnrollMode string

const (
	// ModeTest 测试模式。
	ModeTest EnrollMode = "test"
	// ModeProd 生产模式（补发流程未设计，拒绝）。
	ModeProd EnrollMode = "prod"
)

// ActorSystem 拒绝事件的审计 actor。
const ActorSystem = "system"

// NodeActor 节点事件的审计 actor。
func NodeActor(nodeID string) string { return "node:" + nodeID }

// 错误（对外统一，不泄露"哪一部分不匹配"）。
var (
	// ErrEnrollRejected 注册被拒绝（令牌无效/CSR 不合法等，对外统一）。
	ErrEnrollRejected = errors.New("nodesvc：注册被拒绝")
	// ErrHeartbeatRejected 心跳被拒绝。
	ErrHeartbeatRejected = errors.New("nodesvc：心跳被拒绝")
	// ErrCertRevoked 证书已吊销。
	ErrCertRevoked = errors.New("nodesvc：证书已被吊销")
	// ErrCertSuperseded 证书已被更新的证书取代（心跳必须被拒绝）。
	ErrCertSuperseded = errors.New("nodesvc：证书已被取代（superseded），拒绝心跳")
	// ErrRenewRejected 续期被拒绝（对外统一，不说明具体校验项）。
	ErrRenewRejected = errors.New("nodesvc：证书续期被拒绝")
	// ErrReissueNotAllowed 补发不被允许（非 revoked 节点 / 生产模式）。
	ErrReissueNotAllowed = errors.New("nodesvc：补发不被允许")
	// ErrNodeNotRevoked 目标节点不是 revoked 状态（补发仅面向 revoked）。
	ErrNodeNotRevoked = errors.New("nodesvc：目标节点不是 revoked 状态")
	// ErrProdReissueUnimplemented 生产模式的补发流程未设计。
	ErrProdReissueUnimplemented = errors.New("nodesvc：生产模式的补发流程未设计（拒绝执行）")
)

// Config 配置。
type Config struct {
	// Store 持久化（必填）。
	Store *nodestore.Store
	// CA 证书颁发机构（必填）。
	CA *nodeidentity.TestCA
	// Tracker 心跳判定器（必填）。
	Tracker *nodehealth.Tracker
	// Audit 审计存储（必填）。
	Audit *audit.Store
	// HeartbeatInterval 心跳间隔（<=0 用 nodehealth.DefaultInterval）。
	HeartbeatInterval time.Duration
	// Now 注入时钟（必填）。
	Now func() time.Time
	// Mode 运行模式（空 = test；T4 决定补发是否可用）。
	Mode EnrollMode
	// ExpiryRiskThreshold 剩余有效期告警阈值
	// （<=0 用 DefaultExpiryRiskThreshold=48h；工程默认，待确认）。
	ExpiryRiskThreshold time.Duration
	// ExpiryRiskInterval 同节点告警最小间隔
	// （<=0 用 DefaultExpiryRiskInterval=6h；工程默认，待确认）。
	ExpiryRiskInterval time.Duration
	// CertNotAfter 计算某节点的证书到期时刻
	// （nil 用 CA 有效期 + 节点创建时刻的估算实现）。
	CertNotAfter func(rec nodestore.NodeRecord) time.Time
	// Certs 证书状态机（必填；第二十四轮 T1）。
	// 为空时按 Store.Tables() 的表名自动构建（测试与生产同构）。
	Certs *nodecerts.Store
}

// Service 节点身份与健康服务。
type Service struct {
	store        *nodestore.Store
	ca           *nodeidentity.TestCA
	tracker      *nodehealth.Tracker
	audit        *audit.Store
	interval     time.Duration
	now          func() time.Time
	mode         EnrollMode
	riskTTL      time.Duration
	riskGap      time.Duration
	certNotAfter func(rec nodestore.NodeRecord) time.Time
	certs        *nodecerts.Store

	// riskMu / lastRiskAt 过期风险告警节流（每节点每 riskGap 最多一条）。
	riskMu     sync.Mutex
	lastRiskAt map[string]time.Time
}

// New 构建服务。
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.CA == nil || cfg.Tracker == nil || cfg.Audit == nil {
		return nil, errors.New("nodesvc：Store/CA/Tracker/Audit 必填")
	}
	if cfg.Now == nil {
		return nil, errors.New("nodesvc：必须注入时钟（Config.Now）")
	}
	interval := cfg.HeartbeatInterval
	if interval <= 0 {
		interval = nodehealth.DefaultInterval
	}
	mode := cfg.Mode
	if mode == "" {
		mode = ModeTest
	}
	riskTTL := cfg.ExpiryRiskThreshold
	if riskTTL <= 0 {
		riskTTL = DefaultExpiryRiskThreshold
	}
	riskGap := cfg.ExpiryRiskInterval
	if riskGap <= 0 {
		riskGap = DefaultExpiryRiskInterval
	}
	certs := cfg.Certs
	if certs == nil {
		_, _, revocations := cfg.Store.Tables()
		built, cerr := nodecerts.New(nodecerts.Config{
			Pool:             cfg.Store.Pool(),
			CertsTable:       cfg.Store.CertsTable(),
			RevocationsTable: revocations,
		})
		if cerr != nil {
			return nil, cerr
		}
		certs = built
	}
	notAfterFn := cfg.CertNotAfter
	if notAfterFn == nil {
		// 默认估算：节点创建时刻 + CA 配置的证书有效期。
		validity := caValidity(cfg.CA)
		notAfterFn = func(rec nodestore.NodeRecord) time.Time {
			if rec.CreatedAt.IsZero() || validity <= 0 {
				return time.Time{}
			}
			return rec.CreatedAt.UTC().Add(validity)
		}
	}
	return &Service{
		store: cfg.Store, ca: cfg.CA, tracker: cfg.Tracker, audit: cfg.Audit,
		interval: interval, now: cfg.Now,
		mode: mode, riskTTL: riskTTL, riskGap: riskGap,
		certNotAfter: notAfterFn, certs: certs,
		lastRiskAt: map[string]time.Time{},
	}, nil
}

// Mode 返回生效的运行模式。
func (s *Service) Mode() EnrollMode { return s.mode }

// Certs 返回证书状态机（供周期扫描器与测试使用）。
func (s *Service) Certs() *nodecerts.Store { return s.certs }

// Tracker 返回心跳判定器（供扫描器与测试使用）。
func (s *Service) Tracker() *nodehealth.Tracker { return s.tracker }

// AuditStore 返回审计存储（供扫描器与测试使用）。
func (s *Service) AuditStore() *audit.Store { return s.audit }

// Now 返回注入时钟（供扫描器使用）。
func (s *Service) Now() time.Time { return s.now().UTC() }

// SweeperDeps 构建**周期扫描器**的依赖（T2）。
//
// 扫描器与 Service 共用同一份存储与时钟，但**只读证书状态并只写审计**：
// 不改变节点状态、不改变证书状态。
func (s *Service) SweeperDeps() nodesweep.Dependencies {
	return nodesweep.Dependencies{
		NodeIDs: func(ctx context.Context) ([]string, error) {
			recs, err := s.store.ListNodes(ctx)
			if err != nil {
				return nil, err
			}
			ids := make([]string, 0, len(recs))
			for _, rec := range recs {
				ids = append(ids, rec.NodeID)
			}
			return ids, nil
		},
		ActiveCerts: func(ctx context.Context, nodeID string) ([]nodesweep.Cert, error) {
			recs, err := s.certs.ListByNode(ctx, nodeID)
			if err != nil {
				return nil, err
			}
			var out []nodesweep.Cert
			for _, rec := range recs {
				if rec.State != nodecerts.StateActive {
					continue
				}
				out = append(out, nodesweep.Cert{
					Serial: rec.Serial, NodeID: rec.NodeID,
					IssuedAt: rec.IssuedAt, NotAfter: rec.NotAfter,
				})
			}
			return out, nil
		},
		HasNewerThan: func(ctx context.Context, nodeID string, at time.Time) (bool, error) {
			recs, err := s.certs.ListByNode(ctx, nodeID)
			if err != nil {
				return false, err
			}
			for _, rec := range recs {
				if rec.IssuedAt.After(at) {
					return true, nil
				}
			}
			return false, nil
		},
		StaleIssued: func(ctx context.Context, nodeID string, before time.Time) ([]nodesweep.Cert, error) {
			recs, err := s.certs.ListByNode(ctx, nodeID)
			if err != nil {
				return nil, err
			}
			var out []nodesweep.Cert
			for _, rec := range recs {
				if rec.State != nodecerts.StateIssued || !rec.IssuedAt.Before(before) {
					continue
				}
				out = append(out, nodesweep.Cert{
					Serial: rec.Serial, NodeID: rec.NodeID,
					IssuedAt: rec.IssuedAt, NotAfter: rec.NotAfter,
				})
			}
			return out, nil
		},
		LastEmit:   s.lastEmit,
		RecordEmit: s.recordEmit,
		Audit: func(ctx context.Context, nodeID, action string, payload map[string]any) {
			s.appendAudit(ctx, NodeActor(nodeID), action, nodeID, payload)
		},
		Now: s.now,
	}
}

// lastEmit 读取节流状态（table 由迁移 005 创建）。
func (s *Service) lastEmit(ctx context.Context, nodeID, event string) (time.Time, error) {
	return s.sweepStateLast(ctx, nodeID, event)
}

// recordEmit 写入节流状态。
func (s *Service) recordEmit(ctx context.Context, nodeID, event string, at time.Time) error {
	return s.sweepStateRecord(ctx, nodeID, event, at)
}

// SweepStateTable 返回节流状态表名（测试断言用）。
//
// R2b：表名一律取自 Store（与 nodestore.DefaultSweepStateTable 同源），
// 不再在此硬编码默认值——否则测试环境自定义表名时迁移会收到空名而被拒绝。
func (s *Service) SweepStateTable() string { return s.store.SweepStateTable() }

// EnsureSchema 建表 + 执行**可回滚的迁移**（第二十三/二十四轮新增列与表）。
//
// 顺序不可颠倒：先 EnsureSchema（创建初始形态），再 migrate.Up（补列与约束）。
// 迁移是幂等的，可重复调用。
func (s *Service) EnsureSchema(ctx context.Context) error {
	if err := s.store.EnsureSchema(ctx); err != nil {
		return err
	}
	nodes, tokens, revocations := s.store.Tables()
	mig, err := nodemigrate.New(s.store.Pool(), nodemigrate.Tables{
		Nodes: nodes, Tokens: tokens, Revocations: revocations,
		Certs:      s.store.CertsTable(),
		SweepState: s.store.SweepStateTable(),
	})
	if err != nil {
		return err
	}
	if _, err := mig.Up(ctx); err != nil {
		return err
	}
	return nil
}

// EnrollOutcome 注册结果。
type EnrollOutcome struct {
	NodeID            string
	CertificateDER    []byte
	CACertificateDER  []byte
	NotAfter          time.Time
	HeartbeatInterval time.Duration
	// CertSerial 证书序列号（心跳与吊销都按它查表）。
	CertSerial string
}

// Enroll 完成一次注册。
//
// 步骤：令牌哈希校验（未找到/已用/过期 → 统一拒绝）→ **原子消费** →
// CSR 持有性证明校验（含 CN/SAN/扩展即拒绝）→ 分配 node_id → 签发证书 → 落库 → 审计。
func (s *Service) Enroll(ctx context.Context, token string, csrDER []byte,
	displayLabel, agentVersion string) (*EnrollOutcome, error) {
	now := s.now().UTC()

	// 1. CSR 持有性证明（D2）：失败一律统一拒绝，不说明具体字段。
	if _, err := nodeidentity.ParseCSRProofOfPossession(csrDER); err != nil {
		s.auditRejected(ctx, ActionEnrollRejected, "system", "csr_invalid", "")
		return nil, ErrEnrollRejected
	}

	// 2. 令牌存在性 / 已用 / 过期（先读状态给出内部 reason，再原子消费）。
	hash := nodeidentity.HashTokenOf(token)
	state, err := s.store.GetTokenState(ctx, hash)
	if err != nil {
		return nil, err
	}
	switch {
	case !state.Found:
		s.auditRejected(ctx, ActionEnrollRejected, "system", "token_not_found", "")
		return nil, ErrEnrollRejected
	case !state.UsedAt.IsZero():
		s.auditRejected(ctx, ActionEnrollRejected, "system", "token_used", state.UsedByNodeID)
		return nil, ErrEnrollRejected
	case !now.Before(state.ExpiresAt):
		s.auditRejected(ctx, ActionEnrollRejected, "system", "token_expired", "")
		return nil, ErrEnrollRejected
	}

	// 3. 分配权威身份（**只由控制面分配**）。
	nodeID, err := nodeidentity.NewNodeID(now, nil)
	if err != nil {
		return nil, err
	}

	// 3.5 补发令牌关联的旧节点（T4）：注册时写入 previous_node_id，旧节点保持 revoked。
	prev := state.ReissuedForNodeID

	// 4. **原子**消费令牌：并发提交时只有一个成功。
	ok, err := s.store.ConsumeToken(ctx, hash, nodeID, now)
	if err != nil {
		return nil, err
	}
	if !ok {
		s.auditRejected(ctx, ActionEnrollRejected, "system", "token_race_lost", "")
		return nil, ErrEnrollRejected
	}

	// 5. 签发证书（CN/SAN = 分配的 node_id；有效期由 CA 配置指定）。
	certDER, notAfter, err := s.ca.SignCSR(csrDER, nodeID, now, nil)
	if err != nil {
		s.auditRejected(ctx, ActionEnrollRejected, "system", "sign_failed", nodeID)
		return nil, ErrEnrollRejected
	}
	leaf, err := s.ca.VerifyClientCert(certDER, now)
	if err != nil {
		s.auditRejected(ctx, ActionEnrollRejected, "system", "verify_failed", nodeID)
		return nil, ErrEnrollRejected
	}

	// 6. 落库 + 登记到判定器。
	rec := nodestore.NodeRecord{
		NodeID: nodeID, Status: nodestore.StatusOnline,
		DisplayLabel: displayLabel, CertSerial: leaf.SerialNumber.String(),
		LastReceivedAt: now, CreatedAt: now,
	}
	if err := s.store.UpsertNode(ctx, rec); err != nil {
		return nil, err
	}
	// T1：注册得到的证书**立即**被使用（没有"待确认"窗口），因此直接登记为 active
	// 并写 confirmed_at；同时把可能存在的历史记录收敛（重复注册同一序列号不会发生，
	// 因为序列号由 CA 随机生成）。
	serial := leaf.SerialNumber.String()
	if err := s.certs.Issue(ctx, nodecerts.Record{
		Serial: serial, NodeID: nodeID, State: nodecerts.StateIssued,
		IssuedAt: now, NotAfter: notAfter,
	}); err != nil {
		return nil, err
	}
	if _, err := s.certs.Confirm(ctx, nodeID, serial, now); err != nil {
		return nil, err
	}
	s.tracker.Register(nodeID)

	// 7. 审计（actor = node:<node_id>；payload 不含令牌/CSR/证书内容）。
	//    T4：若本次消费的是**补发**令牌，记录 previous_node_id（旧节点保持 revoked）。
	payload := map[string]any{
		"node_id":       nodeID,
		"display_label": displayLabel,
		"agent_version": agentVersion,
		"cert_serial":   serial,
		"not_after":     notAfter.UTC().Format(time.RFC3339),
	}
	if prev != "" {
		payload["previous_node_id"] = prev
	}
	s.appendAudit(ctx, NodeActor(nodeID), ActionEnrolled, nodeID, payload)

	return &EnrollOutcome{
		NodeID:            nodeID,
		CertificateDER:    certDER,
		CACertificateDER:  s.ca.CertificateDER(),
		NotAfter:          notAfter,
		HeartbeatInterval: s.interval,
		CertSerial:        leaf.SerialNumber.String(),
	}, nil
}

// HeartbeatOutcome 心跳结果。
type HeartbeatOutcome struct {
	Status     nodehealth.Status
	Skew       time.Duration
	SkewLevel  nodehealth.SkewLevel
	Transition nodehealth.Transition
	// BootSessionID 本次心跳的会话（D6）。
	BootSessionID string
	// NewSession 是否为新会话的首个心跳（D6）。
	NewSession bool
	// BaselineReset 是否因连续 replay 重置了基线（D6；调用方据此写审计）。
	BaselineReset bool
}

// Heartbeat 处理一次心跳。
//
// 证书吊销 → 拒绝（revoked）；防重放（replay/duplicate）→ 拒绝且不刷新状态；
// 存活以 **received_at** 为准；偏差只记录与告警。
func (s *Service) Heartbeat(ctx context.Context, nodeID, bootSessionID string, sentAt time.Time,
	certSerial string) (*HeartbeatOutcome, error) {
	// 1. 证书状态机确认（T1）——**先于**吊销表检查：
	//    状态机能区分"被更新的证书取代（superseded）"与"被人工吊销（revoked）"，
	//    两者的运维处置不同，因此先由它给出精确原因，再由吊销表兜底。
	//    - S 为 issued → 提升 active，并把**同节点更早的 issued/active 全部** supersede
	//      （含因响应丢失而从未确认的**孤儿证书**）→ 写吊销表 reason=superseded；
	//    - S 已 active → 无变化；
	//    - S 为 superseded / revoked → 拒绝（不改任何状态）；
	//    **不改变节点状态**。
	confirm, cerr := s.certs.Confirm(ctx, nodeID, certSerial, s.now().UTC())
	switch {
	case cerr == nil:
		// 正常：记录本次新确认的孤儿证书（若有）用于审计。
		if len(confirm.Superseded) > 0 {
			s.appendAudit(ctx, NodeActor(nodeID), ActionCertSuperseded, nodeID, map[string]any{
				"node_id":    nodeID,
				"superseded": confirm.Superseded,
				"new_serial": certSerial,
				"reason":     SupersedeReason,
			})
		}
	case errors.Is(cerr, nodecerts.ErrNotUsable):
		// 心跳携带已失效的序列号 → 拒绝且不改任何状态。
		// 状态为 revoked（人工吊销）时仍走下面的吊销表分支，以保留"revoked"的既有语义
		// （终止节点 + 写 cert_revoked 之上的一致性）。
		if confirm.State == nodecerts.StateRevoked {
			break
		}
		s.auditRejected(ctx, ActionHeartbeatRejected, ActorSystem, "serial_superseded", nodeID)
		return nil, ErrCertSuperseded
	case errors.Is(cerr, nodecerts.ErrUnknownSerial):
		// 不在状态机中（例如早于本表引入的证书）：放行，交由吊销表检查兜底。
	default:
		return nil, cerr
	}

	// 2. 证书吊销检查（每次心跳都查；对状态机未知的序列号是唯一防线）。
	if certSerial != "" {
		revoked, err := s.store.IsRevokedSerial(ctx, certSerial)
		if err != nil {
			return nil, err
		}
		if revoked {
			reason, found, rerr := s.store.RevocationReason(ctx, certSerial)
			if rerr != nil {
				return nil, rerr
			}
			// superseded 是"证书被取代"，不是"节点被撤销"：**不改节点状态**。
			// 只有 revoked 才是终态（终止节点）。
			if found && reason == SupersedeReason {
				s.auditRejected(ctx, ActionHeartbeatRejected, ActorSystem, "serial_superseded", nodeID)
				return nil, ErrCertSuperseded
			}
			s.auditRejected(ctx, ActionHeartbeatRejected, ActorSystem, "revoked", nodeID)
			_, _ = s.tracker.Revoke(nodeID)
			_ = s.store.SetNodeStatus(ctx, nodeID, nodestore.StatusRevoked)
			return nil, ErrCertRevoked
		}
	}

	// 3. 状态机处理（防重放 / 偏差 / 存活；D6 基线按会话维护）。
	res, err := s.tracker.Heartbeat(nodeID, bootSessionID, sentAt)
	if err != nil {
		reason := "unknown"
		switch {
		case errors.Is(err, nodehealth.ErrHeartbeatReplay):
			reason = "replay"
		case errors.Is(err, nodehealth.ErrHeartbeatDuplicate):
			reason = "duplicate"
		case errors.Is(err, nodehealth.ErrNodeRevoked):
			reason = "revoked"
		}
		s.auditRejected(ctx, ActionHeartbeatRejected, ActorSystem, reason, nodeID)
		return nil, fmt.Errorf("%w：%s", ErrHeartbeatRejected, reason)
	}

	// 4. 落库（存活字段 + 偏差 + D6 会话基线）。
	if err := s.store.UpdateNodeState(ctx, nodeID, string(res.Transition.To),
		res.ReceivedAt, res.SentAt, res.Skew); err != nil {
		return nil, err
	}
	if res.BootSessionID != "" {
		if err := s.store.UpdateNodeSession(ctx, nodeID, res.BootSessionID, res.SentAt); err != nil {
			return nil, err
		}
	}

	// 5. 审计：状态迁移（恰好一条）+ 偏差级别变化（恰好一条）+ 基线重置（恰好一条）。
	if res.Transition.Changed() {
		action := ActionOnline
		if res.Transition.To == nodehealth.StatusOffline {
			action = ActionOffline
		}
		s.appendAudit(ctx, NodeActor(nodeID), action, nodeID, map[string]any{
			"node_id": nodeID, "from": string(res.Transition.From),
			"to": string(res.Transition.To), "reason": res.Transition.Reason,
			"misses": res.Transition.Misses,
		})
	}
	if res.SkewReported {
		s.appendAudit(ctx, NodeActor(nodeID), ActionClockSkewWarning, nodeID, map[string]any{
			"node_id":   nodeID,
			"skew_ms":   res.Skew.Milliseconds(),
			"level":     string(res.SkewLevel),
			"threshold": "warn=5s alert=30s（工程默认，待运维确认）",
		})
	}
	// D6：连续 replay 达阈值 → 基线已重置（payload 只含三要素，无任何证书/令牌材料）。
	if res.BaselineReset {
		s.appendAudit(ctx, NodeActor(nodeID), ActionClockRegressionReset, nodeID, map[string]any{
			"node_id":         nodeID,
			"boot_session_id": res.BootSessionID,
			"replay_streak":   res.ReplayStreak,
		})
	}

	// 6. 过期风险（T3）：剩余有效期不足阈值且未续期 → 节流写告警（每节点每 6h 最多一条）。
	if _, err := s.ExpiryRisks(ctx); err != nil {
		return nil, err
	}

	return &HeartbeatOutcome{
		Status: res.Transition.To, Skew: res.Skew,
		SkewLevel: res.SkewLevel, Transition: res.Transition,
		BootSessionID: res.BootSessionID, NewSession: res.NewSession,
		BaselineReset: res.BaselineReset,
	}, nil
}

// ExpiryRisks 扫描剩余有效期不足阈值的节点（**未续期**），并为其中应告警者
// 写一条 node.cert_expiry_risk 审计（每节点每 6 小时最多一条；工程默认，待确认）。
//
// 到期时刻由 Config.CertNotAfter 提供（默认：节点创建时刻 + CA 配置的有效期；
// 调用方可注入更精确的实现，例如从证书本身读取）；本方法**不接触证书材料**。
func (s *Service) ExpiryRisks(ctx context.Context) ([]ExpiryRisk, error) {
	recs, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	var out []ExpiryRisk
	for _, rec := range recs {
		if rec.Status == nodestore.StatusRevoked {
			continue
		}
		exp := s.certNotAfter(rec)
		if exp.IsZero() {
			continue
		}
		remaining := exp.Sub(now)
		if remaining > s.riskTTL {
			continue
		}
		risk := ExpiryRisk{NodeID: rec.NodeID, CertSerial: rec.CertSerial,
			NotAfter: exp, Remaining: remaining}
		// 节流：每节点每 riskGap 最多一条。
		s.riskMu.Lock()
		last, seen := s.lastRiskAt[rec.NodeID]
		if !seen || now.Sub(last) >= s.riskGap {
			s.lastRiskAt[rec.NodeID] = now
			risk.Reported = true
		}
		s.riskMu.Unlock()
		if risk.Reported {
			s.appendAudit(ctx, NodeActor(rec.NodeID), ActionCertExpiryRisk, rec.NodeID,
				map[string]any{
					"node_id":      rec.NodeID,
					"cert_serial":  rec.CertSerial,
					"remaining_ms": remaining.Milliseconds(),
					"threshold":    s.riskTTL.String(),
					"not_after":    exp.Format(time.RFC3339),
					"throttle_gap": s.riskGap.String(),
				})
		}
		out = append(out, risk)
	}
	return out, nil
}

// ExpiryRisk 一条到期风险记录。
type ExpiryRisk struct {
	// NodeID 节点身份。
	NodeID string
	// CertSerial 当前证书序列号。
	CertSerial string
	// NotAfter 证书到期时刻。
	NotAfter time.Time
	// Remaining 剩余有效期。
	Remaining time.Duration
	// Reported 本次是否写入了审计（受节流控制）。
	Reported bool
}

// RenewOutcome 续期结果。
type RenewOutcome struct {
	// NodeID 节点身份（**不变**：续期不改变身份）。
	NodeID string
	// CertificateDER 新证书。
	CertificateDER []byte
	// CACertificateDER CA 证书。
	CACertificateDER []byte
	// NotAfter 新证书到期时刻。
	NotAfter time.Time
	// NewSerial 新序列号。
	NewSerial string
	// OldSerial 被取代的旧序列号（**尚未**写入吊销表，待新序列号首次心跳确认）。
	OldSerial string
}

// Renew 处理一次证书续期（T3）。
//
// 校验顺序（**任一步失败即统一拒绝**，不改变状态，写 node.renew_rejected）：
//  1. mTLS 证书由本 CA 签发且有效（由调用方在 gRPC 层完成；这里再次自校验）；
//  2. 序列号未被吊销；
//  3. 证书 CN 与 SAN 与 node_id 绑定；
//  4. 节点状态不是 revoked；
//  5. CSR 签名有效（纯持有性证明）；
//  6. CSR 公钥**必须不等于**当前证书公钥（必须换钥）；
//  7. 签发新证书：同一 node_id、新序列号。
//
// 成功：**同一事务**写入新序列号 + 待确认旧序列号；状态不变；写 node.cert_renewed。
// 旧证书**不立即吊销**（理由见 ADR-022：否则续期响应丢失会让节点卡在已吊销证书上）。
func (s *Service) Renew(ctx context.Context, nodeID, clientSerial string,
	clientCertDER, csrPEM []byte) (*RenewOutcome, error) {
	now := s.now().UTC()
	reject := func(reason string) (*RenewOutcome, error) {
		s.auditRejected(ctx, ActionRenewRejected, ActorSystem, reason, nodeID)
		return nil, ErrRenewRejected
	}

	// ② 序列号未被吊销。
	if strings.TrimSpace(clientSerial) == "" {
		return reject("serial_missing")
	}
	revoked, err := s.store.IsRevokedSerial(ctx, clientSerial)
	if err != nil {
		return nil, err
	}
	if revoked {
		return reject("serial_revoked")
	}

	// ④ 节点状态不是 revoked。
	rec, found, err := s.store.GetNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if !found {
		return reject("unknown_node")
	}
	if rec.Status == nodestore.StatusRevoked {
		return reject("node_revoked")
	}

	// ①③ 证书有效且身份绑定（再次自校验，不信任传输层结论）。
	leaf, verr := s.ca.VerifyClientCert(clientCertDER, now)
	if verr != nil {
		// 区分"过期"与其它原因，便于运维；对外仍统一拒绝。
		if errors.Is(verr, nodeidentity.ErrCertExpired) {
			return reject("cert_expired")
		}
		return reject("cert_invalid")
	}
	if berr := nodeidentity.CheckCertBindsNodeID(leaf, nodeID); berr != nil {
		return reject("cert_identity_mismatch")
	}
	// 证书序列号必须与调用方声明一致（防止"用 A 的证书续 B 的期"）。
	if leaf.SerialNumber.String() != clientSerial {
		return reject("serial_mismatch")
	}
	// ⑤ CSR 持有性证明。
	csr, cerr := nodeidentity.ParseCSRProofOfPossessionPEM(csrPEM)
	if cerr != nil {
		return reject("csr_invalid")
	}
	// ⑥ 必须换钥：CSR 公钥**不得**等于当前证书公钥。
	if pubKeyEqual(csr.PublicKey, leaf.PublicKey) {
		return reject("same_key")
	}

	// ⑦ 签发新证书（同一 node_id、新序列号）。
	newDER, notAfter, err := s.ca.SignCSRFromPEM(csrPEM, nodeID, now, nil)
	if err != nil {
		return reject("sign_failed")
	}
	newLeaf, lerr := s.ca.VerifyClientCert(newDER, now)
	if lerr != nil {
		return reject("verify_failed")
	}
	oldSerial := rec.CertSerial
	newSerial := newLeaf.SerialNumber.String()

	// T1：登记为 **issued**（不是 active）——它要等节点真正用这张证书发心跳才被确认。
	// 未确认上限在此判定（同一事务内 count + insert，防止并发绕过）。
	if err := s.certs.Issue(ctx, nodecerts.Record{
		Serial: newSerial, NodeID: nodeID, State: nodecerts.StateIssued,
		IssuedAt: now, NotAfter: notAfter,
	}); err != nil {
		if errors.Is(err, nodecerts.ErrPendingLimit) {
			// 未确认上限：拒绝本次续期（reason=pending_limit 只入审计）。
			return reject("pending_limit")
		}
		return nil, err
	}
	// 同一事务更新节点表的当前序列号（pending_superseded_serial 已停止写入）。
	if err := s.store.RotateCert(ctx, nodeID, newSerial); err != nil {
		return nil, err
	}

	s.appendAudit(ctx, NodeActor(nodeID), ActionCertRenewed, nodeID, map[string]any{
		"node_id":    nodeID,
		"old_serial": oldSerial,
		"new_serial": newSerial,
		"not_after":  notAfter.UTC().Format(time.RFC3339),
	})
	return &RenewOutcome{
		NodeID:           nodeID,
		CertificateDER:   newDER,
		CACertificateDER: s.ca.CertificateDER(),
		NotAfter:         notAfter,
		NewSerial:        newSerial,
		OldSerial:        oldSerial,
	}, nil
}

// pubKeyEqual 判定两个公钥是否相同（续期必须换钥）。
func pubKeyEqual(a, b any) bool {
	pa, ok1 := a.(*ecdsa.PublicKey)
	pb, ok2 := b.(*ecdsa.PublicKey)
	if !ok1 || !ok2 {
		// 类型不支持时 fail-closed：视为相同 → 拒绝续期。
		return true
	}
	return pa.Equal(pb)
}

// ReissueOutcome 补发结果（**不含**令牌明文：明文只由调用方一次性返回给运维）。
type ReissueOutcome struct {
	// NodeID 旧节点（保持 revoked）。
	NodeID string
	// Token 一次性令牌明文（**调用方负责一次性交付**；不落库、不入审计）。
	Token string
	// ExpiresAt 令牌到期时刻。
	ExpiresAt time.Time
}

// IssueReissueToken 为 **revoked** 节点补发一次性令牌（T4，仅测试模式）。
//
// 约束：
//   - 仅 ModeTest 可用；生产模式返回 ErrProdReissueUnimplemented（流程未设计）；
//   - 目标节点必须为 revoked；
//   - 令牌沿用 N6 规则（32 字节随机、只存 SHA-256、15 分钟、单次消费）；
//   - 令牌记录关联 reissued_for_node_id；
//   - 写 node.reissue_token_issued 审计（operator / old_node_id / reason），
//     **不含令牌明文或哈希**。
func (s *Service) IssueReissueToken(ctx context.Context, oldNodeID, operator, reason string,
	confirm bool) (*ReissueOutcome, error) {
	if s.mode != ModeTest {
		return nil, ErrProdReissueUnimplemented
	}
	if !confirm {
		return nil, fmt.Errorf("%w：调用方未显式确认（confirm=true）", ErrReissueNotAllowed)
	}
	if strings.TrimSpace(oldNodeID) == "" || strings.TrimSpace(operator) == "" {
		return nil, fmt.Errorf("%w：old_node_id 与 operator 必填", ErrReissueNotAllowed)
	}
	rec, found, err := s.store.GetNode(ctx, oldNodeID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w：节点不存在", ErrReissueNotAllowed)
	}
	if rec.Status != nodestore.StatusRevoked {
		return nil, ErrNodeNotRevoked
	}

	now := s.now().UTC()
	plain, hash, err := nodeidentity.GenerateToken(nil)
	if err != nil {
		return nil, err
	}
	expiresAt := now.Add(nodeidentity.TokenTTL)
	// 关联旧节点（新列，见 nodemigrate 迁移 002）。
	if err := s.store.PutReissueToken(ctx, hash, expiresAt, oldNodeID); err != nil {
		return nil, err
	}
	// 审计：**不含**令牌明文与哈希。
	s.appendAudit(ctx, ActorSystem, ActionReissueTokenIssued, oldNodeID, map[string]any{
		"operator":    operator,
		"old_node_id": oldNodeID,
		"reason":      reason,
		"expires_at":  expiresAt.Format(time.RFC3339),
		"mode":        string(s.mode),
		"single_use":  true,
	})
	return &ReissueOutcome{NodeID: oldNodeID, Token: plain, ExpiresAt: expiresAt}, nil
}

// EvaluateOffline 按控制面时钟判定离线，落库并写审计（恰好一条/次迁移）。
func (s *Service) EvaluateOffline(ctx context.Context) ([]nodehealth.Transition, error) {
	transitions := s.tracker.EvaluateAll()
	for _, tr := range transitions {
		if err := s.store.SetNodeStatus(ctx, tr.NodeID, string(tr.To)); err != nil {
			return nil, err
		}
		s.appendAudit(ctx, NodeActor(tr.NodeID), ActionOffline, tr.NodeID, map[string]any{
			"node_id": tr.NodeID, "from": string(tr.From), "to": string(tr.To),
			"reason": tr.Reason, "misses": tr.Misses,
		})
	}
	return transitions, nil
}

// RevokeCert 吊销证书（本轮仅测试模式提供内部入口）。
//
// reason 是**受控取值**（吊销表的 CHECK 约束只有 revoked | superseded）：
// 这里固定写 RevokeReason（"revoked"），调用方提供的 reason 只进入**审计 payload**
// 作为运维说明——把它直接写进吊销表会违反约束，也会让"吊销原因"这一列
// 失去机器可读性（下游要按它区分 superseded）。
func (s *Service) RevokeCert(ctx context.Context, serial, nodeID, reason string) error {
	now := s.now().UTC()
	if err := s.store.Revoke(ctx, serial, nodeID, RevokeReason, now); err != nil {
		return err
	}
	if _, err := s.tracker.Revoke(nodeID); err != nil && !errors.Is(err, nodehealth.ErrUnknownNode) {
		return err
	}
	// payload 含 serial 与 node_id，**不含证书 PEM**。
	note := strings.TrimSpace(reason)
	if note == "" {
		note = RevokeReason
	}
	s.appendAudit(ctx, ActorSystem, ActionCertRevoked, nodeID, map[string]any{
		"node_id": nodeID, "serial": serial,
		// 吊销表的受控原因 + 调用方说明（后者仅供人读）。
		"reason":        RevokeReason,
		"operator_note": note,
		"revoked_at":    now.Format(time.RFC3339),
	})
	return nil
}

// Restore 控制面重启后从 PG 恢复节点状态（N6）。
//
// 同时把吊销表注入 CA（保证重启后吊销依然生效）。
func (s *Service) Restore(ctx context.Context) (int, error) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return 0, err
	}
	for _, rec := range nodes {
		s.tracker.Restore(nodehealth.NodeSnapshot{
			NodeID:         rec.NodeID,
			Status:         nodehealth.Status(rec.Status),
			LastReceivedAt: rec.LastReceivedAt,
			LastSentAt:     rec.LastSentAt,
			LastSkew:       rec.LastSkew,
		})
	}
	s.ca.SetRevocations(s.store.RevocationChecker(ctx))
	return len(nodes), nil
}

// appendAudit 写一条审计事件（失败只记录不阻断业务？不——fail-closed：返回错误由调用方决定）。
//
// 这里采用"尽力写 + 记录"的策略：审计写入失败不应让已完成的注册/心跳回滚，
// 但调用方可通过 auditVerify 对账。为简洁起见，本方法吞掉错误（见 TODO）。
func (s *Service) appendAudit(ctx context.Context, actor, action, target string, payload map[string]any) {
	_, _ = s.audit.Append(ctx, audit.Event{
		ID:      fmt.Sprintf("%s-%d", action, s.now().UnixNano()),
		Actor:   actor,
		Action:  action,
		Target:  target,
		Payload: payload,
	})
}

// auditRejected 写一条拒绝审计（actor = system；payload 只含内部 reason）。
func (s *Service) auditRejected(ctx context.Context, action, actor, reason, nodeID string) {
	payload := map[string]any{"reason": reason}
	if nodeID != "" {
		payload["node_id"] = nodeID
	}
	s.appendAudit(ctx, actor, action, nodeID, payload)
}

// AuditCountByAction 审计行数（测试断言用）。
func (s *Service) AuditCountByAction(ctx context.Context, action string) (int, error) {
	evs, err := s.audit.ListByAction(ctx, action)
	if err != nil {
		return 0, err
	}
	return len(evs), nil
}

// caValidity 读取 CA 配置的证书有效期（估算到期时刻用；CA 为 nil 时返回 0）。
func caValidity(ca *nodeidentity.TestCA) time.Duration {
	if ca == nil {
		return 0
	}
	return ca.Validity()
}

// —— 扫描器节流状态（T2）——

// sweepStateLast 读取上次告警时刻（零值 = 从未写过）。
func (s *Service) sweepStateLast(ctx context.Context, nodeID, event string) (time.Time, error) {
	// 表可能不存在（迁移未执行）：此时视为"从未写过"，让扫描器仍然能工作
	// （宁可多告警一次，也不要因为缺表而完全不告警）。
	var last time.Time
	err := s.store.Pool().QueryRow(ctx,
		fmt.Sprintf(`SELECT last_emit_at FROM %s WHERE node_id = $1 AND event = $2`,
			s.SweepStateTable()), nodeID, event).Scan(&last)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		if isUndefinedTable(err) {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("nodesvc：读取扫描节流状态失败：%w", err)
	}
	return last.UTC(), nil
}

// sweepStateRecord 记录告警时刻（幂等 upsert）。
func (s *Service) sweepStateRecord(ctx context.Context, nodeID, event string, at time.Time) error {
	_, err := s.store.Pool().Exec(ctx, fmt.Sprintf(
		`INSERT INTO %s (node_id, event, last_emit_at) VALUES ($1,$2,$3)
         ON CONFLICT (node_id, event) DO UPDATE SET last_emit_at = EXCLUDED.last_emit_at`,
		s.SweepStateTable()), nodeID, event, at.UTC())
	if err != nil {
		if isUndefinedTable(err) {
			return nil // 迁移未执行：降级为"不节流"
		}
		return fmt.Errorf("nodesvc：写入扫描节流状态失败：%w", err)
	}
	return nil
}

// isUndefinedTable 判定 pg 错误是否为"表不存在"（SQLSTATE 42P01）。
func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "42P01"
	}
	return false
}
