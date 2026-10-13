package console

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"

	consolev1 "github.com/XZ-libin/agent-ops/contract/gen/go/agent_ops/console/v1"
	"github.com/XZ-libin/agent-ops/internal/audit"
	"github.com/XZ-libin/agent-ops/internal/policy"
)

// ManifestProvider 能力清单来源。
//
// 控制台**不 import 适配器包**（适配器上有执行函数，属写侧；见 C4 的守卫），
// 清单由装配方注入。真实部署的提供方在控制层，本轮用夹具提供。
type ManifestProvider interface {
	Manifest(ctx context.Context) ([]*consolev1.AdapterManifestView, error)
}

// Reader 只读数据访问层。全部语句都是 SELECT。
type Reader struct {
	pool     *pgxpool.Pool
	cfg      Config
	manifest ManifestProvider
	policy   policy.Config
}

// NewReader 构造只读访问层。
func NewReader(pool *pgxpool.Pool, cfg Config, manifest ManifestProvider, pol policy.Config) (*Reader, error) {
	if pool == nil {
		return nil, errors.New("console：连接池为空")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, errors.New("console：缺少能力清单来源（ManifestProvider）")
	}
	return &Reader{pool: pool, cfg: cfg, manifest: manifest, policy: pol}, nil
}

// —— 节点 ——

// ListNodes 列出节点摘要（内部封顶 DefaultNodeRows，防止无界查询）。
func (r *Reader) ListNodes(ctx context.Context) ([]*consolev1.NodeView, error) {
	q := fmt.Sprintf(`SELECT n.node_id, n.status, n.last_received_at, n.cert_serial,
       c.state, c.not_after, c.confirmed_at
  FROM %s n LEFT JOIN %s c ON c.serial = n.cert_serial
 ORDER BY n.node_id LIMIT %d`, r.cfg.NodesTable, r.cfg.CertsTable, DefaultNodeRows)
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*consolev1.NodeView
	for rows.Next() {
		v, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetNode 按 node_id 取节点摘要；不存在返回 (nil, nil)。
func (r *Reader) GetNode(ctx context.Context, nodeID string) (*consolev1.NodeView, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, nil
	}
	q := fmt.Sprintf(`SELECT n.node_id, n.status, n.last_received_at, n.cert_serial,
       c.state, c.not_after, c.confirmed_at
  FROM %s n LEFT JOIN %s c ON c.serial = n.cert_serial WHERE n.node_id = $1`,
		r.cfg.NodesTable, r.cfg.CertsTable)
	row := r.pool.QueryRow(ctx, q, nodeID)
	v, err := scanNode(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// nodeRow 节点查询的行（可空列用指针）。
type nodeRow interface {
	Scan(dest ...any) error
}

func scanNode(row nodeRow) (*consolev1.NodeView, error) {
	var (
		nodeID, status, serial string
		lastReceived           *time.Time
		state                  *string
		notAfter, confirmedAt  *time.Time
	)
	if err := row.Scan(&nodeID, &status, &lastReceived, &serial, &state, &notAfter, &confirmedAt); err != nil {
		return nil, err
	}
	return &consolev1.NodeView{
		NodeId:          nodeID,
		Status:          status,
		LastSeen:        tsOf(lastReceived),
		CertSerial:      serial,
		CertState:       derefStr(state),
		CertNotAfter:    tsOf(notAfter),
		CertConfirmedAt: tsOf(confirmedAt),
	}, nil
}

// —— 审批 ——

// ListApprovals 按状态过滤、以 approval_id 为游标（返回 id > cursor，升序）分页。
func (r *Reader) ListApprovals(ctx context.Context, status string, limit int, cursor string) ([]*consolev1.ApprovalView, error) {
	if limit <= 0 || limit > MaxLimit {
		return nil, ErrBadLimit
	}
	q := fmt.Sprintf(`SELECT id, capability, status, actor, decided_by, created_at, expires_at, request_hash
  FROM %s WHERE ($1 = '' OR status = $1) AND id > $2 ORDER BY id LIMIT $3`,
		r.cfg.ApprovalsTable)
	rows, err := r.pool.Query(ctx, q, status, cursor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tiers, err := r.tierIndex(ctx)
	if err != nil {
		return nil, err
	}
	var out []*consolev1.ApprovalView
	for rows.Next() {
		var (
			id, capability, st, actor, decidedBy, requestHash string
			createdAt, expiresAt                              time.Time
		)
		if err := rows.Scan(&id, &capability, &st, &actor, &decidedBy, &createdAt, &expiresAt, &requestHash); err != nil {
			return nil, err
		}
		out = append(out, &consolev1.ApprovalView{
			ApprovalId:  id,
			Capability:  capability,
			Tier:        tiers[capability],
			Status:      st,
			Requester:   actor,
			Approver:    decidedBy,
			CreatedAt:   timestamppb.New(createdAt.UTC()),
			ExpiresAt:   timestamppb.New(expiresAt.UTC()),
			RequestHash: requestHash,
		})
	}
	return out, rows.Err()
}

// GetApproval 按 id 取审批；不存在返回 (nil, nil)。
func (r *Reader) GetApproval(ctx context.Context, id string) (*consolev1.ApprovalView, error) {
	if strings.TrimSpace(id) == "" {
		return nil, nil
	}
	q := fmt.Sprintf(`SELECT id, capability, status, actor, decided_by, created_at, expires_at, request_hash
  FROM %s WHERE id = $1`, r.cfg.ApprovalsTable)
	var (
		capability, st, actor, decidedBy, requestHash string
		createdAt, expiresAt                          time.Time
	)
	err := r.pool.QueryRow(ctx, q, id).Scan(&id, &capability, &st, &actor, &decidedBy,
		&createdAt, &expiresAt, &requestHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	tiers, terr := r.tierIndex(ctx)
	if terr != nil {
		return nil, terr
	}
	return &consolev1.ApprovalView{
		ApprovalId:  id,
		Capability:  capability,
		Tier:        tiers[capability],
		Status:      st,
		Requester:   actor,
		Approver:    decidedBy,
		CreatedAt:   timestamppb.New(createdAt.UTC()),
		ExpiresAt:   timestamppb.New(expiresAt.UTC()),
		RequestHash: requestHash,
	}, nil
}

// tierIndex capability → tier 序列化名（来自注入的能力清单）。
func (r *Reader) tierIndex(ctx context.Context) (map[string]string, error) {
	items, err := r.manifest.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(items))
	for _, it := range items {
		out[it.Capability] = it.Tier
	}
	return out, nil
}

// —— 审计 ——

// ListAuditEvents 以 seq 游标升序读取事件，payload 走白名单投影。
func (r *Reader) ListAuditEvents(ctx context.Context, afterSeq int64, limit int) ([]*consolev1.AuditEventView, error) {
	if limit <= 0 || limit > MaxLimit {
		return nil, ErrBadLimit
	}
	q := fmt.Sprintf(`SELECT seq, id, actor, action, target, payload, created_at
  FROM %s WHERE seq > $1 ORDER BY seq LIMIT $2`, r.cfg.AuditTable)
	rows, err := r.pool.Query(ctx, q, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*consolev1.AuditEventView
	for rows.Next() {
		var (
			seq                       int64
			id, actor, action, target string
			payload                   []byte
			createdAt                 time.Time
		)
		if err := rows.Scan(&seq, &id, &actor, &action, &target, &payload, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, &consolev1.AuditEventView{
			Seq:       seq,
			Id:        id,
			Actor:     actor,
			Action:    action,
			Target:    target,
			CreatedAt: timestamppb.New(createdAt.UTC()),
			Payload:   ProjectPayload(action, payload),
		})
	}
	return out, rows.Err()
}

// VerifyAudit 校验审计哈希链（复用 internal/audit 的唯一实现，避免出现第二套规范化方式）。
//
// 这里只调用它的只读校验；控制台代码永不出现 Append/EnsureSchema
// （由 TestConsoleNoWriteImports 静态断言）。
func (r *Reader) VerifyAudit(ctx context.Context) (*consolev1.AuditVerifyResult, error) {
	store := audit.NewTestStore(r.pool, r.cfg.AuditTable)
	total, err := r.countAudit(ctx)
	if err != nil {
		return &consolev1.AuditVerifyResult{
			Ok: false, Reason: consolev1.VerifyReason_VERIFY_REASON_INTERNAL_ERROR,
		}, nil
	}
	firstBad, reason, verr := store.VerifyWithReason(ctx)
	if verr != nil {
		// 读取失败也不回显内部错误内容，只报码。
		return &consolev1.AuditVerifyResult{
			Ok: false, EventsTotal: total,
			Reason: consolev1.VerifyReason_VERIFY_REASON_INTERNAL_ERROR,
		}, nil
	}
	if firstBad == 0 {
		return &consolev1.AuditVerifyResult{
			Ok: true, FirstBadSeq: 0, EventsTotal: total,
			Reason: consolev1.VerifyReason_VERIFY_REASON_OK,
		}, nil
	}
	code := consolev1.VerifyReason_VERIFY_REASON_HASH_MISMATCH
	if strings.HasPrefix(reason, "seq ") {
		code = consolev1.VerifyReason_VERIFY_REASON_SEQ_GAP
	}
	return &consolev1.AuditVerifyResult{
		Ok: false, FirstBadSeq: firstBad, EventsTotal: total, Reason: code,
	}, nil
}

func (r *Reader) countAudit(ctx context.Context) (int64, error) {
	var n int64
	err := r.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, r.cfg.AuditTable)).Scan(&n)
	return n, err
}

// —— 能力清单与策略 ——

// Adapters 返回注入的能力清单（只读描述）。
func (r *Reader) Adapters(ctx context.Context) ([]*consolev1.AdapterManifestView, error) {
	return r.manifest.Manifest(ctx)
}

// Policy 返回有效策略摘要（只有映射与条数，不含规则内容与任何凭据）。
func (r *Reader) Policy(_ context.Context) (*consolev1.PolicyView, error) {
	view := &consolev1.PolicyView{
		DecisionForTier:        map[string]string{},
		EnvironmentMinTier:     map[string]string{},
		MultiImpactMinTier:     r.policy.MultiImpactMinTier.String(),
		NotRollbackableMinTier: r.policy.NotRollbackableMinTier.String(),
		FreezeWindowMinTier:    r.policy.FreezeWindowMinTier.String(),
		HardDenyRules:          int64(len(r.policy.HardDeny)),
	}
	for tier, decision := range r.policy.DecisionForTier {
		view.DecisionForTier[tier.String()] = decision.String()
	}
	for env, tier := range r.policy.EnvironmentMinTier {
		view.EnvironmentMinTier[env.String()] = tier.String()
	}
	return view, nil
}

// —— 健康 ——

// Health 探测数据库连通与迁移版本。任何失败都体现为 db_ok=false，不返回错误细节。
func (r *Reader) Health(ctx context.Context) *consolev1.HealthView {
	view := &consolev1.HealthView{Status: "degraded", DbOk: false, SchemaVersion: 0}
	var one int
	if err := r.pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return view
	}
	view.DbOk = true
	if exists, err := r.tableExists(ctx, r.cfg.LedgerTable); err == nil && exists {
		var version sql.NullInt64
		q := fmt.Sprintf(`SELECT max(version) FROM %s`, r.cfg.LedgerTable)
		if verr := r.pool.QueryRow(ctx, q).Scan(&version); verr == nil && version.Valid {
			view.SchemaVersion = version.Int64
		}
	}
	if view.DbOk {
		view.Status = "ok"
	}
	return view
}

func (r *Reader) tableExists(ctx context.Context, table string) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM information_schema.tables
		  WHERE table_schema = current_schema() AND table_name = $1)`, table).Scan(&ok)
	return ok, err
}

// —— 小工具 ——

func tsOf(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(t.UTC())
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
