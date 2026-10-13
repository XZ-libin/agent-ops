// Package gateway 实现执行网关（第八轮；第九轮审批执行；第十轮修订）：
//
// 提交链路（顺序固定，不可绕过）：
//
//	请求参数校验 → 能力查找（未声明即拒）→ destructive 网关级直接拒绝
//	→ policy.Evaluate 策略引擎 → 网关低风险白名单门控（生产清单为空）
//	→ 审计决策（写入失败即 fail-closed 阻止执行）
//	→ 按 decision 分支：
//	   deny：直接返回拒绝（不执行）；
//	   require_approval：只创建 pending 审批记录并返回 pending（不执行，
//	      批准后执行走 ExecuteApproved）；pending 去重键为 (actor, request_hash)
//	      ——同一内容换幂等键仍返回同一审批 ID；同键不同内容 422；
//	   auto：幂等检查（同 (actor, API, key) 只执行一次；同键不同内容 422、
//	      处理中/已放弃 409）→ 执行已注册 Handler → 审计 executed/failed
//	      （审计写入失败则执行失败）→ 写入幂等响应。
//
// 审批通过后的受控执行（第十轮修订，ADR-010）：
//
//	校验审批（存在、approved、内容与请求人一致、四眼、执行窗口内）
//	→ 能力查找（未声明即拒）→ destructive 拒绝 → test_only 不得出现在生产注册表
//	→ 策略重评（只拦截「不可通过审批解除」的条件：能力不存在、destructive、
//	  test_only 泄漏、策略 deny；require_approval 由有效审批满足，不再拦截）
//	→ **原子 CAS 抢占（approved → executing，影响行数 0 即拒绝）**
//	→ 写 gateway.executing 审计 → 幂等检查 → 执行 → 写 executed/failed 审计
//	→ 审批置 consumed（executing → consumed）。
//
//	抢占后未产生终态（崩溃或幂等跳过）的审批由 Reconcile 标记 abandoned，
//	**不重放**（需重新提交审批）。
//
// 安全语义：
//   - destructive=true 的操作在网关层直接拒绝、不进入审批、不触达执行层
//     （适配器/SSH），由注册表 Handler 调用计数与集成测试双重断言；
//   - 所有决策（allow / require_approval / deny）与执行结果（executed / failed）
//     写入审计；审计 payload 一律不包含凭据与错误原文（凭据保护）；
//   - 生产低风险自动执行清单保持为空（第八轮约束 6）；测试配置须注明「仅测试」。
package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/gateway/internal/approvals"
	"github.com/ORG/agent-ops/internal/audit"
	"github.com/ORG/agent-ops/internal/idempotency"
	"github.com/ORG/agent-ops/internal/policy"
)

// ScopeAPI 幂等键作用域中的 API 标识：网关执行接口（工程默认，
// 对应「接口」= gateway.Execute gRPC 方法）。
const ScopeAPI = "gateway.Execute"

// Request 一次网关执行请求（第八轮为 Go 层 API；gRPC 服务接线在后续批次，
// 契约侧无需新增 proto 字段——复用 Action/Environment/Actor 语义）。
type Request struct {
	// Actor 操作人/Agent（审批与审计记录主体）。
	Actor string
	// IdempotencyKey 调用方携带的幂等键（必填）。
	IdempotencyKey string
	// Action 执行动作（capability/params/target/impact_scope/expected）。
	Action *contractv1.Action
	// Environment 目标环境（prod/staging/test 固定枚举）。
	Environment contractv1.Environment
	// FreezeWindow 是否处于变更冻结窗口（由调用方判断传入；
	// policy.Evaluate 是纯函数，不读取时间）。
	FreezeWindow bool
}

// Status 网关返回状态。
type Status string

const (
	// StatusSuccess 已执行成功。
	StatusSuccess Status = "success"
	// StatusFailed 执行失败（含审计成功但 Handler 失败、审计写入失败两种）。
	StatusFailed Status = "failed"
	// StatusPendingApproval 已创建待审批记录，未执行（第八轮约束 5）。
	StatusPendingApproval Status = "pending"
	// StatusDenied 被网关/策略拒绝。
	StatusDenied Status = "denied"
	// StatusConflict 幂等键已存在且请求内容不同（HTTP 422）。
	StatusConflict Status = "conflict"
	// StatusInProgress 幂等键处理中或已放弃（HTTP 409）。
	StatusInProgress Status = "in_progress"
)

// Response 一次网关执行的结果。
type Response struct {
	// Status 见 Status 定义。
	Status Status `json:"status"`
	// Decision 最终生效的决策（allow / require_approval / deny）。
	Decision contractv1.Decision `json:"decision"`
	// Reasons 策略判定理由（含网关级门控追加的理由）。
	Reasons []string `json:"reasons,omitempty"`
	// ApprovalID require_approval 分支创建的审批记录 ID。
	ApprovalID string `json:"approval_id,omitempty"`
	// Result 执行结果（success / 幂等重放时有效）。
	Result *contractv1.ActionResult `json:"result,omitempty"`
	// Message 人读说明（错误信息经凭据保护脱敏）。
	Message string `json:"message,omitempty"`
	// Code 机器可读结局分类（gRPC 错误码映射依据；见 errors.go）。
	// 仅对非成功结局设置；success 恒为 CodeNone。
	Code Code `json:"code,omitempty"`
	// Replayed 本次响应来自幂等存储的重放（未真正执行）。
	Replayed bool `json:"replayed,omitempty"`
}

// AuditSink 审计写入与只读查询的最小接口（audit.Store 满足）：
// Append 写入事件；ListByAction 供 R4 对账扫描 executing 事件。
type AuditSink interface {
	Append(ctx context.Context, ev audit.Event) (string, error)
	ListByAction(ctx context.Context, action string) ([]audit.StoredEvent, error)
}

// ApprovalSink 审批存取的最小接口（approvals.PostgresStore 满足）。
type ApprovalSink interface {
	Create(ctx context.Context, n approvals.NewRecord) (approvals.Record, error)
	Get(ctx context.Context, id string) (approvals.Record, error)
	Approve(ctx context.Context, id, approver, reason string) (approvals.Record, error)
	Reject(ctx context.Context, id, decider, reason string) (approvals.Record, error)
	// CheckExecutable approved 且执行窗口内的记录可执行；
	// 超窗则把记录作废并返回 ErrApprovalVoided。
	CheckExecutable(ctx context.Context, id string) (approvals.Record, error)
	// Claim 原子抢占（approved → executing，写入执行租约）；失败返回
	// ErrNotClaimable / ErrApprovalVoided（第十轮 F2 + 第十一轮 H1）。
	// lease 为本次执行的租约时长（第十二轮 H6：按能力超时经 approvals.LeaseFor 推导）。
	Claim(ctx context.Context, id string, lease time.Duration) (approvals.Record, error)
	// Renew 续期执行租约（H1/H6）：执行期间定期调用；lease 必须与 Claim 一致；
	// 失败（含租约过期）时调用方必须中止执行。
	Renew(ctx context.Context, id string, lease time.Duration) (approvals.Record, error)
	// Consume executing → consumed（抢占成功后的收口）。
	Consume(ctx context.Context, id string) (approvals.Record, error)
	// MarkAbandoned executing → abandoned（对账标记崩溃/跳过的审批，不重放）。
	MarkAbandoned(ctx context.Context, id string) (approvals.Record, error)
	// ListExecuting 列出处于 executing 的审批（单实例守卫）。
	ListExecuting(ctx context.Context) ([]approvals.Record, error)
	// ListExpiredExecuting 列出租约已过期的 executing 审批（对账，H1）。
	ListExpiredExecuting(ctx context.Context, now time.Time) ([]approvals.Record, error)
}

// Config 网关配置。
type Config struct {
	// Policy 策略引擎配置（生产用 policy.DefaultConfig()）。
	Policy policy.Config
	// AutoExecAllowlist 低风险自动执行清单：生产保持为空（第八轮约束 6）；
	// 测试配置必须注明「仅测试」。
	AutoExecAllowlist map[string]bool
	// ApprovalTTL pending 审批有效时长（<=0 用 policy.DefaultApprovalTimeout）。
	ApprovalTTL time.Duration
	// LeaseRenewInterval 执行租约续期间隔（第十二轮 H6：固定 20 秒，
	// approvals.DefaultLeaseRenewInterval）。租约时长不再全局固定，而是按能力
	// 超时逐个推导：租约 = 能力超时 + 2 × 本间隔（approvals.LeaseFor）。
	LeaseRenewInterval time.Duration
	// Now 注入时钟（测试用；审批过期时间计算）。
	Now func() time.Time
}

// DefaultConfig 生产默认配置：低风险自动执行清单为空（约束 6）。
func DefaultConfig() Config {
	return Config{
		Policy:             policy.DefaultConfig(),
		AutoExecAllowlist:  map[string]bool{}, // 生产清单为空：任何非只读 auto 都转审批
		ApprovalTTL:        policy.DefaultApprovalTimeout,
		LeaseRenewInterval: approvals.DefaultLeaseRenewInterval,
		Now:                time.Now,
	}
}

// Service 执行网关。
type Service struct {
	cfg       Config
	idem      idempotency.Store
	audit     AuditSink
	approvals ApprovalSink
	registry  *Registry
}

// New 构建网关服务；依赖缺失直接拒绝（fail-closed）。
func New(cfg Config, idem idempotency.Store, auditSink AuditSink, approvalSink ApprovalSink, registry *Registry) (*Service, error) {
	if idem == nil || auditSink == nil || approvalSink == nil || registry == nil {
		return nil, errors.New("gateway：幂等存储/审计/审批/注册表依赖均必填")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ApprovalTTL <= 0 {
		cfg.ApprovalTTL = policy.DefaultApprovalTimeout
	}
	// H1/H6：续期间隔固定为 20 秒；租约按能力超时逐个推导（LeaseFor），
	// 启动时对每个已注册能力强校验：租约必须 > 2×续期间隔、
	// 且不得小于该能力超时。任一项不满足即拒绝启动（fail-closed）。
	if cfg.LeaseRenewInterval <= 0 {
		cfg.LeaseRenewInterval = approvals.DefaultLeaseRenewInterval
	}
	if err := registry.validateLeasePolicy(cfg.LeaseRenewInterval); err != nil {
		return nil, err
	}
	if cfg.AutoExecAllowlist == nil {
		cfg.AutoExecAllowlist = map[string]bool{}
	}
	if cfg.Policy.DecisionForTier == nil {
		return nil, errors.New("gateway：策略配置缺失等级→决策映射")
	}
	return &Service{
		cfg:       cfg,
		idem:      idem,
		audit:     auditSink,
		approvals: approvalSink,
		registry:  registry,
	}, nil
}

// Execute 按固定链路执行（顺序见包注释）。返回值语义：
//   - 业务结果（拒绝/pending/执行结果/幂等冲突）以 Response 表达，err 为 nil；
//   - 基础设施性失败（含决策审计写入失败 fail-closed）返回 (nil, err)。
func (s *Service) Execute(ctx context.Context, req Request) (*Response, error) {
	// 1. 请求边界校验（失败不写审计：这不是针对某个能力的决策）。
	if strings.TrimSpace(req.Actor) == "" {
		return nil, Errorf(CodeInvalidArgument, "gateway：请求缺少操作人 actor")
	}
	if strings.TrimSpace(req.IdempotencyKey) == "" {
		return nil, Errorf(CodeInvalidArgument, "gateway：请求缺少幂等键 idempotency_key")
	}
	if req.Action == nil || strings.TrimSpace(req.Action.Capability) == "" {
		return nil, Errorf(CodeInvalidArgument, "gateway：请求缺少执行动作/能力名")
	}

	capability := req.Action.Capability
	reg, ok := s.registry.Lookup(capability)
	if !ok {
		// 未声明能力一律拒绝（审计决策 deny）。
		reasons := []string{fmt.Sprintf("能力 %s 未在注册表声明，拒绝（deny）", capability)}
		if err := s.auditDecision(ctx, req, contractv1.Decision_DECISION_DENY, contractv1.RiskTier_RISK_TIER_UNSPECIFIED, reasons); err != nil {
			return nil, Wrap(CodeAuditFailed,
				fmt.Errorf("gateway：决策审计写入失败（fail closed，已阻止执行）：%w", err))
		}
		return &Response{Status: StatusDenied, Decision: contractv1.Decision_DECISION_DENY,
			Reasons: reasons, Code: CodePolicyDenied, Message: "能力未声明，已拒绝"}, nil
	}

	// 2. destructive 网关级直接拒绝（第八轮约束 4）：
	// 不进入审批、不进入策略、绝不触达执行层（Handler/SSH）。
	if reg.Decl.Destructive {
		reasons := []string{"能力标记为破坏性（destructive=true），网关直接拒绝，不进入审批"}
		if err := s.auditDecision(ctx, req, contractv1.Decision_DECISION_DENY, reg.Decl.RiskTier, reasons); err != nil {
			return nil, Wrap(CodeAuditFailed,
				fmt.Errorf("gateway：决策审计写入失败（fail closed，已阻止执行）：%w", err))
		}
		return &Response{Status: StatusDenied, Decision: contractv1.Decision_DECISION_DENY,
			Reasons: reasons, Code: CodePolicyDenied,
			Message: "破坏性（destructive=true）操作在网关层直接拒绝，不进入审批：能力 " + capability}, nil
	}

	// 3. 策略引擎（纯函数；先于幂等检查，链路固定）。
	pres := policy.Evaluate(s.cfg.Policy, policy.Request{
		Capability:   reg.Decl,
		Environment:  req.Environment,
		ImpactScope:  impactScope(req.Action),
		FreezeWindow: req.FreezeWindow,
	})
	decision, reasons := pres.Decision, pres.Reasons

	// 4. 网关低风险白名单门控：auto 且非只读的能力必须在清单内
	//（生产清单为空 → 一律转审批；测试配置须注明「仅测试」）。
	if decision == contractv1.Decision_DECISION_AUTO &&
		pres.Tier != contractv1.RiskTier_RISK_TIER_READ_ONLY &&
		!s.cfg.AutoExecAllowlist[capability] {
		decision = contractv1.Decision_DECISION_REQUIRE_APPROVAL
		reasons = append(reasons,
			fmt.Sprintf("低风险自动执行清单未包含 %s（生产清单为空），转审批", capability))
	}

	// 5. 审计决策（allow / require_approval / deny 全量覆盖；先于执行）。
	if err := s.auditDecision(ctx, req, decision, pres.Tier, reasons); err != nil {
		return nil, Wrap(CodeAuditFailed,
			fmt.Errorf("gateway：决策审计写入失败（fail closed，已阻止执行）：%w", err))
	}

	switch decision {
	case contractv1.Decision_DECISION_DENY:
		return &Response{Status: StatusDenied, Decision: decision, Reasons: reasons,
			Code: CodePolicyDenied, Message: "策略拒绝：" + strings.Join(reasons, "；")}, nil

	case contractv1.Decision_DECISION_REQUIRE_APPROVAL:
		// 只创建 pending 审批记录并返回 pending，不执行（约束 5）。
		// 去重键：(actor, request_hash)（第十轮 F3）——同一内容换幂等键仍返回该审批。
		rec, err := s.approvals.Create(ctx, approvals.NewRecord{
			Actor:          req.Actor,
			Capability:     capability,
			RequestHash:    hashRequest(req),
			IdempotencyKey: req.IdempotencyKey,
			ExpiresAt:      s.cfg.Now().Add(s.cfg.ApprovalTTL),
		})
		if errors.Is(err, approvals.ErrContentConflict) {
			return &Response{Status: StatusConflict, Decision: decision, Reasons: reasons,
				Code:    CodeIdemConflict,
				Message: "审批幂等键已存在且请求内容不同（HTTP 422）"}, nil
		}
		if err != nil {
			return nil, Wrap(CodeInternal, fmt.Errorf("gateway：创建审批记录失败：%w", err))
		}
		if err := s.auditApprovalCreated(ctx, req, rec); err != nil {
			return nil, Wrap(CodeAuditFailed,
				fmt.Errorf("gateway：审批创建审计写入失败（fail closed）：%w", err))
		}
		return &Response{Status: StatusPendingApproval, Decision: decision, Reasons: reasons,
			ApprovalID: rec.ID, Message: "已创建待审批记录，未执行（批准后执行走 ExecuteApproved）"}, nil

	default: // DECISION_AUTO
		return s.executeAuto(ctx, req, reg, decision, reasons)
	}
}

// executeAuto auto 分支（只读能力）：幂等检查 → 执行 → 审计执行结果 → 写幂等响应。
// 注：executing 审计（R4）用于审批写路径（ExecuteApproved，先于幂等写 executing）；
// 只读 auto 路径维持第八轮的两事件序列（decision → executed）。
func (s *Service) executeAuto(ctx context.Context, req Request, reg Registration,
	decision contractv1.Decision, reasons []string) (*Response, error) {

	scope := idempotency.Scope{Actor: req.Actor, API: ScopeAPI, Key: req.IdempotencyKey}
	br, err := s.idem.Begin(ctx, scope, canonicalRequestBytes(req))
	switch {
	case errors.Is(err, idempotency.ErrContentConflict):
		// 同键不同请求内容 → 422。
		return &Response{Status: StatusConflict, Decision: decision, Reasons: reasons,
			Code:    CodeIdemConflict,
			Message: "幂等键已存在且请求内容不同（HTTP 422）"}, nil
	case errors.Is(err, idempotency.ErrInProgress), errors.Is(err, idempotency.ErrAbandoned):
		// 处理中/已放弃 → 409。
		return &Response{Status: StatusInProgress, Decision: decision, Reasons: reasons,
			Code:    CodeIdemConflict,
			Message: "幂等键处理中或已放弃，请勿重复提交/请更换新 key 重试（HTTP 409）"}, nil
	case err != nil:
		return nil, Wrap(CodeInternal, fmt.Errorf("gateway：幂等检查失败：%w", err))
	}

	if !br.Fresh {
		// 同键同内容已完成：返回已存响应（不重新执行）。
		resp, err := storedResponseToResponse(br.Entry.Response)
		if err != nil {
			return nil, Wrap(CodeInternal, fmt.Errorf("gateway：解析已存幂等响应失败：%w", err))
		}
		resp.Replayed = true
		return resp, nil
	}

	return s.executeNow(ctx, req, reg, decision, reasons, scope, "", "")
}

// executeNow 已具备 executing 审计（或无需）后的执行、结果审计与幂等响应落库。
// approvalID 为空表示非审批路径（auto 只读）。
//
// H1（执行租约）：审批路径在执行期间按 cfg.LeaseRenewInterval 续期租约；
// 续期失败（含租约已过期）即取消执行上下文 → Handler 中止 → 写 failed 审计，
// 调用方随即将审批标记 abandoned（不重放、不消费）。
func (s *Service) executeNow(ctx context.Context, req Request, reg Registration,
	decision contractv1.Decision, reasons []string, scope idempotency.Scope,
	executionID, approvalID string) (*Response, error) {

	// 执行（能力声明的超时作为上限；适配器内部还有单命令超时双保险）。
	execCtx := ctx
	if d := reg.Decl.Timeout; d != nil && d.AsDuration() > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, d.AsDuration())
		defer cancel()
	}
	// H1/H6：审批路径启动租约续期；续期失败会取消 execCtx 使执行中止。
	// 租约时长由能力超时推导（LeaseFor），续期必须用同一租约值。
	if approvalID != "" {
		lease := approvals.LeaseFor(capabilityTimeout(reg))
		var renewCancel context.CancelFunc
		execCtx, renewCancel = context.WithCancel(execCtx)
		defer renewCancel()
		stopCh, renewErrCh := s.startLeaseRenewal(execCtx, approvalID, lease)
		// 续期失败 → 立即取消执行（Handler 观察 ctx.Done 后中止）。
		go func() {
			select {
			case <-renewErrCh:
				renewCancel()
			case <-stopCh:
			case <-ctx.Done():
			}
		}()
	}

	result, execErr := reg.Handler(execCtx, req)
	failureMsg := sanitizeError(execErr)
	if execErr == nil && result == nil {
		failureMsg = "执行结果为空"
	}
	// H1：上下文被取消且来自续期失败（而非调用方取消/能力超时）时，标注执行租约，
	// 让 ExecuteApproved 走 abandoned（不重放）而非 consumed。
	leaseAborted := approvalID != "" && execCtx.Err() == context.Canceled &&
		ctx.Err() == nil && errors.Is(execErr, context.Canceled)
	if leaseAborted {
		failureMsg = "执行租约续期失败，执行已中止（结果未知，不重放）：" + failureMsg
	}

	if execErr != nil || result == nil || !result.Success {
		// 执行失败：审计 failed（payload 不含错误原文——凭据保护），
		// 审计失败同样使请求失败（fail closed）。
		if failureMsg == "" {
			failureMsg = "执行结果为失败"
		}
		if aerr := s.auditExecution(ctx, req, false, executionID, approvalID); aerr != nil {
			_ = s.idem.Complete(ctx, scope, responseToStored(&Response{
				Status: StatusFailed, Decision: decision, Reasons: reasons,
				Message: "审计写入失败（fail closed），执行结果按失败处理"}))
			return &Response{Status: StatusFailed, Decision: decision, Reasons: reasons,
				Result: result, Message: "执行失败且执行审计写入失败（fail closed）"}, nil
		}
		_ = s.idem.Complete(ctx, scope, responseToStored(&Response{
			Status: StatusFailed, Decision: decision, Reasons: reasons,
			Result: result, Message: "执行失败：" + failureMsg}))
		return &Response{Status: StatusFailed, Decision: decision, Reasons: reasons,
			Result: result, Message: "执行失败：" + failureMsg}, nil
	}

	// 执行成功：审计 executed（最后写审计，链路固定）。
	if aerr := s.auditExecution(ctx, req, true, executionID, approvalID); aerr != nil {
		_ = s.idem.Complete(ctx, scope, responseToStored(&Response{
			Status: StatusFailed, Decision: decision, Reasons: reasons,
			Message: "审计写入失败（fail closed），执行结果按失败处理"}))
		return &Response{Status: StatusFailed, Decision: decision, Reasons: reasons,
			Result: result, Message: "执行已发生但审计写入失败（fail closed），按执行失败返回"}, nil
	}

	okResp := &Response{Status: StatusSuccess, Decision: decision, Reasons: reasons, Result: result}
	if err := s.idem.Complete(ctx, scope, responseToStored(okResp)); err != nil {
		return nil, Wrap(CodeInternal, fmt.Errorf("gateway：写入幂等响应失败：%w", err))
	}
	return okResp, nil
}

// capabilityTimeout 取能力声明的执行超时（注册期已保证为正；防御性兜底返回 0，
// 由 approvals.LeaseFor 推导出的租约在启动校验中即被拒绝）。
func capabilityTimeout(reg Registration) time.Duration {
	if reg.Decl == nil || reg.Decl.Timeout == nil {
		return 0
	}
	return reg.Decl.Timeout.AsDuration()
}

// startLeaseRenewal 启动执行租约续期循环（H1）。
// 返回 stop（停止续期，幂等）与 renewErr（续期失败时收到第一次错误）。
// 循环按 cfg.LeaseRenewInterval 调用 approvals.Renew；失败即停止并通知错误通道，
// 由 executeNow 取消执行上下文，使执行中止（Handler 观察 ctx.Done）。
func (s *Service) startLeaseRenewal(ctx context.Context, approvalID string, lease time.Duration) (stopCh <-chan struct{}, renewErr <-chan error) {
	done := make(chan struct{})
	errCh := make(chan error, 1)
	var once sync.Once
	stopFn := func() { once.Do(func() { close(done) }) }
	go func() {
		ticker := time.NewTicker(s.cfg.LeaseRenewInterval)
		defer ticker.Stop()
		defer stopFn() // 退出时确保 stopCh 关闭（幂等）
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.approvals.Renew(context.Background(), approvalID, lease); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}
	}()
	return done, errCh
}

// GuardSingleInstance 单实例守卫（第十一轮 H1）：启动时若检测到其他实例持有的
// **有效**执行租约（executing 且 lease_until 未过期），拒绝启动。
// 多实例部署在本机制完善前被明令禁止。
func (s *Service) GuardSingleInstance(ctx context.Context) error {
	recs, err := s.approvals.ListExecuting(ctx)
	if err != nil {
		return Wrap(CodeInternal, fmt.Errorf("gateway：单实例守卫检查失败：%w", err))
	}
	now := s.cfg.Now()
	var live []string
	for _, rec := range recs {
		if rec.LeaseUntil == nil || !now.Before(*rec.LeaseUntil) {
			continue // 租约已过期：持有者已崩溃，不阻塞本次启动
		}
		live = append(live, fmt.Sprintf("%s(租约至 %s)", rec.ID, rec.LeaseUntil.Format(time.RFC3339)))
	}
	if len(live) > 0 {
		return Wrap(CodeApprovalState, fmt.Errorf(
			"gateway：检测到其他实例的有效执行租约（%s）；本进程要求单实例运行，多实例部署被禁止，拒绝启动",
			strings.Join(live, "、")))
	}
	return nil
}

// GetApproval 读取审批记录（G1：gRPC GetApproval 用；不存在返回带
// CodeNotFound 的错误）。
func (s *Service) GetApproval(ctx context.Context, approvalID string) (approvals.Record, error) {
	if strings.TrimSpace(approvalID) == "" {
		return approvals.Record{}, Errorf(CodeInvalidArgument, "gateway：缺少审批记录 ID")
	}
	rec, err := s.approvals.Get(ctx, approvalID)
	if err != nil {
		if errors.Is(err, approvals.ErrNotFound) {
			return approvals.Record{}, Wrap(CodeNotFound, fmt.Errorf("gateway：审批记录不存在：%s", approvalID))
		}
		return approvals.Record{}, Wrap(CodeInternal, fmt.Errorf("gateway：读取审批记录失败：%w", err))
	}
	return rec, nil
}

// Approve 审批通过（四眼原则由存储层强制：approver 必须与请求人不同）。
// 审计 approval.approved；审计失败 → fail-closed 返回错误。
func (s *Service) Approve(ctx context.Context, approvalID, approver, reason string) (approvals.Record, error) {
	rec, err := s.approvals.Approve(ctx, approvalID, approver, reason)
	if err != nil {
		return approvals.Record{}, approvalError("gateway：审批失败", err)
	}
	if err := s.auditApprovalState(ctx, rec, "approval.approved"); err != nil {
		return rec, Wrap(CodeAuditFailed,
			fmt.Errorf("gateway：审批审计写入失败（fail closed）：%w", err))
	}
	return rec, nil
}

// Reject 审批拒绝。审计 approval.rejected；审计失败 → fail-closed。
func (s *Service) Reject(ctx context.Context, approvalID, decider, reason string) (approvals.Record, error) {
	rec, err := s.approvals.Reject(ctx, approvalID, decider, reason)
	if err != nil {
		return approvals.Record{}, approvalError("gateway：拒绝失败", err)
	}
	if err := s.auditApprovalState(ctx, rec, "approval.rejected"); err != nil {
		return rec, Wrap(CodeAuditFailed,
			fmt.Errorf("gateway：审批审计写入失败（fail closed）：%w", err))
	}
	return rec, nil
}

// approvalError 把审批存储错误贴上 Code（供 gRPC 层映射固定错误码）：
// 四眼原则拒绝 → PERMISSION_DENIED；非法状态迁移/状态不允许 → FAILED_PRECONDITION；
// 记录不存在 → NOT_FOUND；其余 → INTERNAL。
func approvalError(prefix string, err error) error {
	switch {
	case errors.Is(err, approvals.ErrApproverMustDiffer):
		return Wrap(CodePolicyDenied, fmt.Errorf("%s：%w", prefix, err))
	case errors.Is(err, approvals.ErrIllegalTransition),
		errors.Is(err, approvals.ErrNotApproved),
		errors.Is(err, approvals.ErrApprovalVoided),
		errors.Is(err, approvals.ErrNotClaimable),
		errors.Is(err, approvals.ErrNotExecuting):
		return Wrap(CodeApprovalState, fmt.Errorf("%s：%w", prefix, err))
	case errors.Is(err, approvals.ErrNotFound):
		return Wrap(CodeNotFound, fmt.Errorf("%s：%w", prefix, err))
	}
	return Wrap(CodeInternal, fmt.Errorf("%s：%w", prefix, err))
}

// ExecuteApproved 审批通过后的受控执行（第九轮 A；第十轮 F1/F2 修订）：
//  1. 校验审批（存在、状态 approved、请求内容与请求人一致、四眼、执行窗口内）；
//  2. 能力查找（未声明即拒）→ destructive 拒绝 → test_only 不得出现在生产注册表；
//  3. 策略重评（第十轮语义）：只拦截「不可通过审批解除」的条件——能力不存在、
//     destructive、test_only 出现在生产注册表、策略返回 deny；require_approval
//     由已存在的有效审批（未过期、未消费、审批人不同于请求人）满足，不再拦截；
//  4. 原子抢占 CAS（approved → executing）：影响行数为 0 即返回
//     「审批已被使用或已过期」，不执行、不写执行审计；
//  5. executing 审计 → 幂等检查 → 执行 → executed/failed 审计 → 审批置 consumed。
//     幂等跳过（422/409）时把已抢占的审批标记 abandoned（不重放）。
func (s *Service) ExecuteApproved(ctx context.Context, req Request, approvalID string) (*Response, error) {
	if strings.TrimSpace(req.Actor) == "" || strings.TrimSpace(req.IdempotencyKey) == "" ||
		req.Action == nil || strings.TrimSpace(req.Action.Capability) == "" {
		return nil, Errorf(CodeInvalidArgument, "gateway：请求缺少操作人/幂等键/执行动作")
	}
	if strings.TrimSpace(approvalID) == "" {
		return nil, Errorf(CodeInvalidArgument, "gateway：缺少审批记录 ID")
	}

	// refuse 拒绝并写 deny 决策审计（审计失败 → fail closed）。
	refuse := func(code Code, reasons []string, msg string) (*Response, error) {
		if err := s.auditDecision(ctx, req, contractv1.Decision_DECISION_DENY,
			contractv1.RiskTier_RISK_TIER_UNSPECIFIED, reasons); err != nil {
			return nil, Wrap(CodeAuditFailed,
				fmt.Errorf("gateway：决策审计写入失败（fail closed）：%w", err))
		}
		return &Response{Status: StatusDenied, Decision: contractv1.Decision_DECISION_DENY,
			Reasons: reasons, Message: msg, Code: code}, nil
	}

	// 1. 校验审批。
	rec, err := s.approvals.Get(ctx, approvalID)
	if errors.Is(err, approvals.ErrNotFound) {
		return nil, Wrap(CodeNotFound, fmt.Errorf("gateway：审批记录不存在：%s", approvalID))
	}
	if err != nil {
		return nil, Wrap(CodeInternal, fmt.Errorf("gateway：读取审批记录失败：%w", err))
	}
	if rec.RequestHash != hashRequest(req) {
		return refuse(CodeApprovalState, []string{"请求内容与审批记录不一致"},
			"审批与请求内容不一致，拒绝执行")
	}
	if rec.Actor != req.Actor {
		return refuse(CodeApprovalState, []string{"请求人与审批发起人不一致"},
			"请求人与审批发起人不一致，拒绝执行")
	}
	switch rec.Status {
	case approvals.StatusPending:
		return refuse(CodeApprovalState, []string{"审批记录仍为 pending，未经批准"}, "审批未通过，拒绝执行")
	case approvals.StatusRejected:
		return refuse(CodeApprovalState, []string{"审批已被拒绝"}, "审批已被拒绝，拒绝执行")
	case approvals.StatusExpired:
		return refuse(CodeApprovalState, []string{"审批已过期/作废"}, "审批已过期，拒绝执行")
	case approvals.StatusConsumed:
		return refuse(CodeApprovalState, []string{"审批已消费，不可再次执行"}, "审批已消费（consumed），不可再次执行")
	case approvals.StatusExecuting:
		return refuse(CodeApprovalState, []string{"审批已被抢占执行中"}, "审批正在执行中（executing），拒绝重复执行")
	case approvals.StatusAbandoned:
		return refuse(CodeApprovalState, []string{"审批已被放弃（抢占后无终态），需重新提交审批"},
			"审批已放弃（abandoned），不可重放，请重新提交审批")
	case approvals.StatusApproved:
		// 执行窗口校验由 Claim（原子 CAS，含超窗作废）承担：此处不做先查后写，
		// 避免"校验通过 → 被他人抢占"的竞态（第十轮 F2）。
	}
	// 四眼原则（执行期复核）：审批人必须存在且不同于请求人。
	if strings.TrimSpace(rec.DecidedBy) == "" || rec.DecidedBy == rec.Actor {
		return refuse(CodeApprovalState, []string{"审批人缺失或与请求人相同（四眼原则）"},
			"审批记录不满足四眼原则（审批人缺失或与请求人相同），拒绝执行")
	}

	// 2. 能力查找（生产目录不可见测试能力；未声明即拒）。
	capability := req.Action.Capability
	reg, ok := s.registry.Lookup(capability)
	if !ok {
		return refuse(CodePolicyDenied, []string{"能力未声明"}, "能力未声明，拒绝执行")
	}
	// 破坏性：即使已批准也直接拒绝（约束 4），绝不触达执行层。
	if reg.Decl.Destructive {
		return refuse(CodePolicyDenied, []string{"能力标记为破坏性，即使已批准也拒绝"},
			"破坏性（destructive=true）操作即使已批准也直接拒绝：能力 "+capability)
	}
	// test_only 能力不出现在生产注册表（约束 5/6）：防御性复核（注册表注册期已拒绝）。
	if reg.Decl.TestOnly && !s.registry.AllowsTestOnly() {
		return refuse(CodePolicyDenied, []string{"test_only 能力不得出现在生产注册表"},
			"仅测试（test_only）能力在生产注册表不可见：能力 "+capability)
	}

	// 3. 策略重评（第十轮语义：只拦截不可通过审批解除的条件）。
	pres := policy.Evaluate(s.cfg.Policy, policy.Request{
		Capability:   reg.Decl,
		Environment:  req.Environment,
		ImpactScope:  impactScope(req.Action),
		FreezeWindow: req.FreezeWindow,
	})
	if pres.Decision == contractv1.Decision_DECISION_DENY {
		reasons := append([]string{}, pres.Reasons...)
		reasons = append(reasons, "审批通过后策略重评返回 deny，拒绝执行")
		return refuse(CodePolicyDenied, reasons, "审批通过后策略重评返回 deny，拒绝执行")
	}
	// DECISION_REQUIRE_APPROVAL：由上方已校验的有效审批满足（未过期、未消费、四眼），
	// 不再拦截；DECISION_AUTO：直接放行。

	// 4. 先占后执行（F2）：原子 CAS approved → executing。
	// 抢占失败（影响行数 0）：不执行、不写 executing 审计。
	// H6：租约按能力超时推导（超时 + 2×续期间隔）。
	lease := approvals.LeaseFor(capabilityTimeout(reg))
	if _, cerr := s.approvals.Claim(ctx, approvalID, lease); cerr != nil {
		if errors.Is(cerr, approvals.ErrApprovalVoided) {
			_ = s.auditApprovalState(ctx, expiredApprovalView(rec), "approval.expired")
			return refuse(CodeApprovalState, []string{"审批超过 30 分钟执行窗口，已作废"},
				"审批超过 30 分钟执行窗口，已作废，拒绝执行")
		}
		if errors.Is(cerr, approvals.ErrNotFound) {
			return nil, Wrap(CodeNotFound, fmt.Errorf("gateway：审批记录不存在：%s", approvalID))
		}
		if errors.Is(cerr, approvals.ErrNotClaimable) {
			return refuse(CodeApprovalState, []string{"审批已被使用或已过期（抢占失败）"},
				"审批已被使用或已过期（抢占失败），拒绝执行")
		}
		return nil, Wrap(CodeInternal, fmt.Errorf("gateway：审批抢占失败：%w", cerr))
	}

	// 5. executing 审计（R4：先于幂等与执行；失败即 fail-closed，
	// 审批停留在 executing，由对账标记 abandoned，不重放）。
	executionID := newExecutionID()
	if aerr := s.auditExecuting(ctx, req, executionID, approvalID); aerr != nil {
		return nil, Wrap(CodeAuditFailed,
			fmt.Errorf("gateway：executing 审计写入失败（fail closed，已阻止执行）：%w", aerr))
	}

	// 6. 幂等检查 → 7. 执行 → 终态审计 → 8. 审批消费。
	scope := idempotency.Scope{Actor: req.Actor, API: ScopeAPI, Key: req.IdempotencyKey}
	br, err := s.idem.Begin(ctx, scope, canonicalRequestBytes(req))
	switch {
	case errors.Is(err, idempotency.ErrContentConflict):
		_ = s.auditSkipped(ctx, req, executionID, approvalID, "幂等内容冲突（422）")
		s.abandonClaimed(ctx, approvalID)
		return &Response{Status: StatusConflict, Decision: contractv1.Decision_DECISION_AUTO,
			Code: CodeIdemConflict, Message: "幂等键已存在且请求内容不同（HTTP 422）"}, nil
	case errors.Is(err, idempotency.ErrInProgress), errors.Is(err, idempotency.ErrAbandoned):
		_ = s.auditSkipped(ctx, req, executionID, approvalID, "幂等处理中/已放弃（409）")
		s.abandonClaimed(ctx, approvalID)
		return &Response{Status: StatusInProgress, Decision: contractv1.Decision_DECISION_AUTO,
			Code:    CodeIdemConflict,
			Message: "幂等键处理中或已放弃，请勿重复提交/请更换新 key 重试（HTTP 409）"}, nil
	case err != nil:
		s.abandonClaimed(ctx, approvalID)
		return nil, Wrap(CodeInternal, fmt.Errorf("gateway：幂等检查失败：%w", err))
	}

	if !br.Fresh {
		// 同键同内容已完成：重放已存响应（不重新执行），闭合 executing 并消费审批。
		resp, err := storedResponseToResponse(br.Entry.Response)
		if err != nil {
			return nil, Wrap(CodeInternal, fmt.Errorf("gateway：解析已存幂等响应失败：%w", err))
		}
		_ = s.auditReplayed(ctx, req, executionID, approvalID)
		resp.Replayed = true
		if _, cerr := s.approvals.Consume(ctx, approvalID); cerr != nil {
			return resp, Wrap(CodeApprovalState, fmt.Errorf("gateway：审批消费失败：%w", cerr))
		}
		return resp, nil
	}

	resp, err := s.executeNow(ctx, req, reg, contractv1.Decision_DECISION_AUTO, pres.Reasons,
		scope, executionID, approvalID)
	if err != nil {
		return nil, err
	}
	// H1：续期失败导致执行被中止 → 审批标记 abandoned（不重放、不消费）：
	// 远端结果未知，唯一语义是"需重新提交审批"。
	if resp.Status == StatusFailed && strings.Contains(resp.Message, "执行租约") {
		s.abandonClaimed(ctx, approvalID)
		return resp, nil
	}
	// 审批消费（executed/failed 均已写入终态审计；消费失败 → fail-closed 返回错误，
	// 同键重放受幂等记录保护）。
	if _, cerr := s.approvals.Consume(ctx, approvalID); cerr != nil {
		return nil, Wrap(CodeApprovalState, fmt.Errorf("gateway：审批消费失败：%w", cerr))
	}
	return resp, nil
}

// abandonClaimed 把已抢占但未执行的审批标记 abandoned（幂等跳过路径）：
// 抢占已消耗审批的一次使用权，且幂等键不可复用 → 绝不重放，需重新提交审批。
func (s *Service) abandonClaimed(ctx context.Context, approvalID string) {
	if _, err := s.approvals.MarkAbandoned(ctx, approvalID); err != nil {
		return // 已被消费/放弃或存储故障：不覆盖主路径的返回语义
	}
	rec, err := s.approvals.Get(ctx, approvalID)
	if err != nil {
		return
	}
	_ = s.auditApprovalState(ctx, rec, "approval.abandoned")
}

// expiredApprovalView 用于超窗作废后的审计视图（记录已被存储层置 expired）。
func expiredApprovalView(rec approvals.Record) approvals.Record {
	rec.Status = approvals.StatusExpired
	rec.DecidedBy = "system"
	rec.Reason = "approved 超过 30 分钟执行窗口，已作废"
	return rec
}

// HashRequest 计算请求的幂等哈希（ADR-009 规范化）。
// 供需要事先绑定审批记录/幂等键的调用方使用（如集成测试）。
func HashRequest(req Request) string { return hashRequest(req) }

// impactScope 从 Action.impact_scope 文本映射策略影响范围（工程默认）：
// "multi"（不区分大小写）→ 多实例；其余一律按单实例。
func impactScope(action *contractv1.Action) policy.ImpactScope {
	if action != nil && strings.EqualFold(strings.TrimSpace(action.ImpactScope), "multi") {
		return policy.ImpactScopeMulti
	}
	return policy.ImpactScopeSingle
}
