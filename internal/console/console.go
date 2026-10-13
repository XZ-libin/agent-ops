// Package console 是控制台只读 API 的数据访问与鉴权层（第二十七轮，ADR-024）。
//
// **只读是本包的存在理由**，并且是三层强制而不是一句注释：
//  1. 包内只有 SELECT 语句，没有任何写方法；
//  2. 静态守卫 `TestConsoleNoWriteImports` 禁止本包 import 网关写路径、
//     `internal/exec`、适配器执行函数，也禁止出现 Append/EnsureSchema 等写符号；
//  3. 部署形态使用仅有 SELECT 权限的数据库角色 `test_console_reader`
//     （ADR-024 §5；由 `TestConsoleDBRoleReadOnly` 自证 INSERT/UPDATE/DELETE 全部被拒）。
//
// 表名一律必须是 `test_` 前缀的合法标识符（fail-closed，与 nodestore/approvals 同一口径）：
// 本仓库尚未确定生产表名（见 internal/policy/defaults.go 的 TODO(待决策) 与 ADR-024 §8），
// 因此这里不允许任意表名进入 SQL 拼接。
package console

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Mode 运行模式。
type Mode string

const (
	// ModeTest 测试模式：合成 JWKS 夹具鉴权。
	ModeTest Mode = "test"
	// ModeProd 生产模式：OIDC（ADR-019 规则），**拒绝静态令牌**。
	ModeProd Mode = "prod"
)

// 工程默认值（ADR-024 §4，均标注"待确认"）。
const (
	// DefaultLimit 分页默认条数。
	DefaultLimit = 50
	// MaxLimit 分页上限：超过即 400。
	MaxLimit = 200
	// DefaultTimeout 单请求服务端超时。
	DefaultTimeout = 10 * time.Second
	// DefaultClockSkew OIDC 时钟偏差容忍。
	DefaultClockSkew = 60 * time.Second
	// DefaultNodeRows 节点列表的内部封顶（无分页参数时防止无界查询）。
	DefaultNodeRows = 200
)

// ErrBadLimit limit 非法（0、负数、超过 MaxLimit、非数字）。
var ErrBadLimit = errors.New("console：limit 非法")

// ErrBadTable 表名不符合 `test_` 前缀规则。
var ErrBadTable = errors.New("console：表名必须以 test_ 开头且为合法标识符")

// ErrBadMode 模式取值不合法（必须显式给 test/prod）。
var ErrBadMode = errors.New("console：模式必须显式为 test 或 prod")

// tablePattern 只允许 test_ 前缀的小写标识符。
var tablePattern = regexp.MustCompile(`^test_[a-z0-9_]+$`)

// Config 配置。
type Config struct {
	// Mode 运行模式（必填，无默认值——与 gateway 的 parseMode 同一口径）。
	Mode Mode
	// NodesTable / CertsTable / ApprovalsTable / AuditTable / LedgerTable 只读对象。
	NodesTable     string
	CertsTable     string
	ApprovalsTable string
	AuditTable     string
	// LedgerTable 迁移台账表（仅用于 health 的 schema_version 展示）。
	LedgerTable string
	// Now 注入时钟（测试用；nil 用 time.Now）。
	Now func() time.Time
}

// DefaultConfig 默认表名（与 nodestore / approvals / audit 的默认值对齐）。
func DefaultConfig() Config {
	return Config{
		NodesTable:     "test_nodes",
		CertsTable:     "test_node_certs",
		ApprovalsTable: "test_approvals",
		AuditTable:     "test_audit_events",
		LedgerTable:    "test_node_schema_migrations",
	}
}

// ParseMode 解析模式字符串：必须显式为 test 或 prod（空值也拒绝）。
func ParseMode(s string) (Mode, error) {
	switch strings.TrimSpace(s) {
	case string(ModeTest):
		return ModeTest, nil
	case string(ModeProd):
		return ModeProd, nil
	default:
		return "", fmt.Errorf("%w：%q", ErrBadMode, s)
	}
}

// Validate 校验配置（fail-closed）。
func (c Config) Validate() error {
	if c.Mode != ModeTest && c.Mode != ModeProd {
		return fmt.Errorf("%w：%q", ErrBadMode, string(c.Mode))
	}
	for _, t := range []string{c.NodesTable, c.CertsTable, c.ApprovalsTable,
		c.AuditTable, c.LedgerTable} {
		if !tablePattern.MatchString(t) {
			return fmt.Errorf("%w：%q", ErrBadTable, t)
		}
	}
	return nil
}

// Clock 返回注入时钟或系统时钟。
func (c Config) Clock() func() time.Time {
	if c.Now != nil {
		return c.Now
	}
	return time.Now
}

// NormalizeLimit 把查询参数 limit 归一化：空值取默认值；
// 非数字、0、负数、超过 MaxLimit 一律返回 ErrBadLimit（由 HTTP 层映射为 400）。
func NormalizeLimit(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, ErrBadLimit
	}
	if n <= 0 || n > MaxLimit {
		return 0, ErrBadLimit
	}
	return n, nil
}

// NormalizeAfterSeq 解析游标参数 after_seq：空值表示从头开始。
func NormalizeAfterSeq(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, ErrBadLimit
	}
	return n, nil
}
