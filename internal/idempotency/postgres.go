package idempotency

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ORG/agent-ops/internal/audit"
)

// DefaultLocalDSN 本地开发/测试的默认连接串（占位值，非真实凭据）。
// 宿主端口 55432 与 deploy/docker-compose.yaml 一致（避免与其他项目的 5432 冲突）；
// 测试可用环境变量 AGENT_OPS_TEST_DATABASE_URL 覆盖。
const DefaultLocalDSN = "postgres://agent_ops:agent_ops@localhost:55432/agent_ops?sslmode=disable"

// schemaDDL 幂等键表结构（主键：scope_user + scope_api + key）。
// 全部时间列（created_at/expires_at/lease_until）由应用以注入时钟写入与比较，
// 不使用数据库 now()；DEFAULT now() 仅用于旧表结构的回填。
const schemaDDL = `
CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope_user   text        NOT NULL,
    scope_api    text        NOT NULL,
    key          text        NOT NULL,
    request_hash text        NOT NULL,
    status       text        NOT NULL,
    response     jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    lease_until  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_user, scope_api, key)
);`

// schemaDDLAlter 兼容第四轮的旧表结构（无 lease_until 列）。
const schemaDDLAlter = `
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS lease_until timestamptz NOT NULL DEFAULT now();`

// PostgresStore PostgreSQL 幂等键实现（ADR-002/Q10；Store 接口签名不变）。
// 判定原子性：Begin 使用 INSERT ... ON CONFLICT DO UPDATE（过期时原地回收），
// 不使用应用层先查后写；所有查询参数化，无字符串拼接 SQL。
// 过期与租约判定统一使用注入时钟（WithClock），作为查询参数传入，
// 不使用数据库 now()。过期清理为惰性方式；不实现后台清理任务。
// TODO(待决策)：幂等过期清理的调度方式（后台任务）未定。
type PostgresStore struct {
	pool *pgxpool.Pool
	cfg  storeConfig
}

// NewPostgresStore 构建 PostgreSQL 实现。
func NewPostgresStore(pool *pgxpool.Pool, opts ...Option) *PostgresStore {
	return &PostgresStore{pool: pool, cfg: applyOptions(opts...)}
}

// EnsureSchema 创建/升级幂等键表（幂等语句，应用启动或测试初始化时调用）。
func (s *PostgresStore) EnsureSchema(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, schemaDDL); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, schemaDDLAlter)
	return err
}

// beginSQL：插入新记录（时间全部来自注入时钟 $6/$8，now 参数 $9 用于过期比较）；
// 与既有记录冲突且其已过期时原子回收为本次请求。
// rowsAffected == 1 → 本次为创建方（fresh）；== 0 → 记录存在且未过期，需读取判定。
const beginSQL = `
INSERT INTO idempotency_keys
    (scope_user, scope_api, key, request_hash, status, response, created_at, expires_at, lease_until)
VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8)
ON CONFLICT (scope_user, scope_api, key) DO UPDATE
    SET request_hash = EXCLUDED.request_hash,
        status       = EXCLUDED.status,
        response     = NULL,
        created_at   = EXCLUDED.created_at,
        expires_at   = EXCLUDED.expires_at,
        lease_until  = EXCLUDED.lease_until
    WHERE idempotency_keys.expires_at <= $9`

const selectSQL = `
SELECT status, request_hash, response, created_at, lease_until
FROM idempotency_keys
WHERE scope_user = $1 AND scope_api = $2 AND key = $3 AND expires_at > $4`

// abandonSQL：处理超时（lease_until <= now 参数）时把状态转为 abandoned。
const abandonSQL = `
UPDATE idempotency_keys
SET status = 'abandoned'
WHERE scope_user = $1 AND scope_api = $2 AND key = $3
  AND status = 'processing' AND lease_until <= $4`

const completeSQL = `
UPDATE idempotency_keys
SET status = $4, response = $5
WHERE scope_user = $1 AND scope_api = $2 AND key = $3 AND expires_at > $6`

// Begin 见 Store 接口文档。
func (s *PostgresStore) Begin(ctx context.Context, scope Scope, request []byte) (BeginResult, error) {
	h := hashRequest(request)
	now := s.cfg.now()
	expires := now.Add(s.cfg.ttl)
	lease := now.Add(s.cfg.lease)

	// 最多重试 2 次：冲突行恰在插入与读取之间过期时，重新走插入路径。
	for attempt := 0; attempt < 2; attempt++ {
		tag, err := s.pool.Exec(ctx, beginSQL,
			scope.Actor, scope.API, scope.Key, h, string(StatusProcessing),
			now, expires, lease, now)
		if err != nil {
			return BeginResult{}, err
		}
		if tag.RowsAffected() == 1 {
			return BeginResult{
				Entry: &Entry{
					Scope:       scope,
					RequestHash: h,
					Status:      StatusProcessing,
					CreatedAt:   now,
					LeaseUntil:  lease,
				},
				Fresh: true,
			}, nil
		}

		var (
			status     string
			reqHash    string
			response   []byte
			createdAt  time.Time
			leaseUntil time.Time
		)
		err = s.pool.QueryRow(ctx, selectSQL, scope.Actor, scope.API, scope.Key, now).
			Scan(&status, &reqHash, &response, &createdAt, &leaseUntil)
		if err == pgx.ErrNoRows {
			continue // 记录恰已过期，重试插入
		}
		if err != nil {
			return BeginResult{}, err
		}

		if reqHash != h {
			return BeginResult{}, ErrContentConflict
		}
		switch status {
		case string(StatusCompleted):
			entry := &Entry{
				Scope:       scope,
				RequestHash: reqHash,
				Status:      StatusCompleted,
				CreatedAt:   createdAt,
				LeaseUntil:  leaseUntil,
			}
			if len(response) > 0 {
				var v any
				if err := json.Unmarshal(response, &v); err != nil {
					return BeginResult{}, err
				}
				entry.Response = v
			}
			return BeginResult{Entry: entry, Fresh: false}, nil
		case string(StatusAbandoned):
			// 已放弃：绝不同 key 重新执行。
			return BeginResult{}, ErrAbandoned
		case string(StatusProcessing):
			if !now.Before(leaseUntil) {
				// 处理超时：状态转为 abandoned 后返回 409，并记录审计事件。
				if _, err := s.pool.Exec(ctx, abandonSQL,
					scope.Actor, scope.API, scope.Key, now); err != nil {
					return BeginResult{}, err
				}
				s.recordAbandoned(ctx, scope)
				return BeginResult{}, ErrAbandoned
			}
			return BeginResult{}, ErrInProgress
		}
	}

	// 防御性兜底：两轮内既未插入成功也未读到未过期记录，按处理中返回。
	return BeginResult{}, ErrInProgress
}

// Complete 见 Store 接口文档。
func (s *PostgresStore) Complete(ctx context.Context, scope Scope, response any) error {
	b, err := json.Marshal(response)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, completeSQL,
		scope.Actor, scope.API, scope.Key, string(StatusCompleted), b, s.cfg.now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRecordMissing
	}
	return nil
}

// CleanupExpired 清理过期的幂等记录（可调度入口；频率见 CleanupIntervalDefault，
// 工程默认值每小时一次，调度器不实现）。使用注入时钟作参数；审计记录不清理。
// 返回清理行数。
func (s *PostgresStore) CleanupExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM idempotency_keys WHERE expires_at <= $1`, s.cfg.now())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// recordAbandoned 写入 idempotency.abandoned 审计事件（未注入 Recorder 时跳过）。
// 记录失败不影响幂等判定语义（由审计链路自身暴露问题）。
func (s *PostgresStore) recordAbandoned(ctx context.Context, scope Scope) {
	if s.cfg.recorder == nil {
		return
	}
	_ = s.cfg.recorder.RecordIdempotencyAbandoned(ctx, audit.IdempotencyAbandoned{
		Key:         scope.Key,
		Actor:       scope.Actor,
		API:         scope.API,
		Destructive: scope.Destructive,
	})
}
