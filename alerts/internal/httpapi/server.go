// Package httpapi 是告警入口的 HTTP 层（第十四轮 A1）：
// POST /v1/alerts —— 校验签名与字段、去重、写库与 outbox。
//
// 安全边界（ADR-013）：
//   - 签名密钥只从环境变量读取，日志与错误中不出现签名值或密钥；
//   - 请求体上限 64KB（超出 413）；
//   - 本轮不实现诊断：不调用任何适配器、不执行任何命令。
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ORG/agent-ops/alerts/internal/ingest"
)

// DefaultMaxBodyBytes 请求体上限（裁决：64KB）。
const DefaultMaxBodyBytes int64 = 64 << 10

// Server 告警入口 HTTP 服务。
type Server struct {
	sources      *ingest.SourceSet
	limiter      *ingest.Limiter
	recorder     Recorder
	now          func() time.Time
	dedupWindow  time.Duration
	tolerance    time.Duration
	maxBodyBytes int64
}

// Recorder 记录一条告警（store.Store 满足；此处定义接口以避免循环依赖）。
type Recorder interface {
	Record(ctx context.Context, a ingest.Alert, window time.Duration, now time.Time) (ingest.Decision, error)
}

// Config 服务配置。
type Config struct {
	// Sources 源白名单与每源密钥（必填；第十五轮 R3）。
	Sources *ingest.SourceSet
	// Recorder 存储（必填）。
	Recorder Recorder
	// Limiter 每源令牌桶（nil 时使用默认 60/min、突发 10）。
	Limiter *ingest.Limiter
	// Now 注入时钟（测试用；默认 time.Now）。
	Now func() time.Time
	// DedupWindow 去重窗口（<=0 用 ingest.DefaultDedupWindow=5 分钟）。
	DedupWindow time.Duration
	// SignatureTolerance 签名时间戳容忍窗口（<=0 用默认 5 分钟）。
	SignatureTolerance time.Duration
	// MaxBodyBytes 请求体上限（<=0 用 64KB）。
	MaxBodyBytes int64
}

// New 构建服务（配置缺失直接拒绝，fail-closed）。
func New(cfg Config) (*Server, error) {
	if cfg.Sources == nil {
		return nil, errors.New("httpapi：缺少源白名单与每源密钥（fail-closed）")
	}
	if cfg.Recorder == nil {
		return nil, errors.New("httpapi：缺少存储依赖")
	}
	limiter := cfg.Limiter
	if limiter == nil {
		// 默认按白名单预分配桶（R2：桶表大小 = 白名单长度，运行期不新增键）。
		limiter = ingest.NewLimiterForSources(cfg.Sources.Names(), 0, 0, cfg.Now)
	}
	s := &Server{
		sources:      cfg.Sources,
		limiter:      limiter,
		recorder:     cfg.Recorder,
		now:          cfg.Now,
		dedupWindow:  cfg.DedupWindow,
		tolerance:    cfg.SignatureTolerance,
		maxBodyBytes: cfg.MaxBodyBytes,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.dedupWindow <= 0 {
		s.dedupWindow = ingest.DefaultDedupWindow
	}
	if s.tolerance <= 0 {
		s.tolerance = ingest.DefaultSignatureTolerance
	}
	if s.maxBodyBytes <= 0 {
		s.maxBodyBytes = DefaultMaxBodyBytes
	}
	return s, nil
}

// Run 在 addr 上监听并提供服务，直到 ctx 取消（优雅停机）。
//
// 第十五轮 R5/R1：入站 HTTP 的**全部**符号（http.Server / net.Listen /
// ListenAndServe 等）只出现在本文件——调用方（cmd/alerts）不接触 net/http，
// 仓库级守卫据此把入站允许列表固定为唯一文件。
func (s *Server) Run(ctx context.Context, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("alerts：监听 %s 失败：%w", addr, err)
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(lis) }()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("alerts：HTTP 服务异常退出：%w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	}
}

// Handler 返回路由（目前只有 POST /v1/alerts）。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/alerts", s.handleAlert)
	return mux
}

// alertResponse 成功响应（不含签名与密钥）。
type alertResponse struct {
	Status       string `json:"status"`
	Fingerprint  string `json:"fingerprint"`
	Count        int64  `json:"count"`
	Deduplicated bool   `json:"deduplicated"`
}

// handleAlert 处理 POST /v1/alerts。
func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "只接受 POST")
		return
	}
	// 1) 读取请求体（上限 64KB；多读 1 字节判定超限）。
	body, err := io.ReadAll(io.LimitReader(r.Body, s.maxBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "读取请求体失败")
		return
	}
	if int64(len(body)) > s.maxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "请求体超过上限")
		return
	}

	// 2) 字段解析（先取 source 用于限流与白名单判定；失败 400）。
	var a ingest.Alert
	if derr := json.Unmarshal(body, &a); derr != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}

	// 3) 源白名单（R1 顺序：白名单最先）：不在白名单 → 403，
	//    不做签名校验、不分配任何限流桶、不写任何表。
	if !s.sources.Allowed(a.Source) {
		writeError(w, http.StatusForbidden, ingest.ErrSourceNotAllowed.Error())
		return
	}

	// 4) 签名校验：使用**该源**的密钥（失败 401，不消耗令牌）。
	now := s.now()
	if verr := ingest.VerifySignature(s.sources.KeyFor(a.Source),
		r.Header.Get(ingest.HeaderTimestamp), r.Header.Get(ingest.HeaderSignature),
		body, now, s.tolerance); verr != nil {
		writeError(w, http.StatusUnauthorized, verr.Error())
		return
	}

	// 5) 每源限流（R1 顺序：签名之后；桶已按白名单预分配，运行期不新增键）。
	if allowed, retry, known := s.limiter.Allow(a.Source); !known {
		// 防御性：白名单已放行却无桶，说明配置不一致 → fail-closed。
		writeError(w, http.StatusForbidden, ingest.ErrSourceNotAllowed.Error())
		return
	} else if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeError(w, http.StatusTooManyRequests, "超过每源速率限制")
		return
	}

	// 6) 字段校验（severity 白名单、必填字段）。
	if verr := ingest.Validate(a); verr != nil {
		writeError(w, http.StatusBadRequest, verr.Error())
		return
	}

	// received_at 由服务端注入（忽略请求体中的同名字段）。
	a.ReceivedAt = now.UTC()

	// 7) 去重 + 写库 + outbox。
	decision, rerr := s.recorder.Record(r.Context(), a, s.dedupWindow, now)
	if rerr != nil {
		// 错误信息不含请求内容与密钥；详情只进服务端日志（不写签名/密钥）。
		log.Printf("alerts：记录告警失败（fingerprint=%s）：%v", a.Fingerprint, rerr)
		writeError(w, http.StatusInternalServerError, "记录告警失败")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(alertResponse{
		Status:       "recorded",
		Fingerprint:  a.Fingerprint,
		Count:        decision.ExistingCount,
		Deduplicated: decision.Deduplicated,
	})
}

// errorResponse 错误响应体。
type errorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// writeError 写错误响应（message 由调用方保证不含密钥与签名）。
func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(errorResponse{Status: "error", Message: msg})
}
