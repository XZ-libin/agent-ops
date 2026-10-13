// Package httpapi 是控制台只读 API 的 HTTP 层（第二十七轮 C3，见 ADR-024）。
//
// **本目录是 repoguard 入站 HTTP 白名单的第二个条目**（第一个是
// `alerts/internal/httpapi/server.go`）。登记的理由是"要把端口暴露出去"这一事实本身：
// `http.Server` / `http.ListenAndServe` 属于入站符号，按 ADR-013/015 的口径
// 必须逐文件登记，而不是"顺手起个 server"。例外范围由 `TestConsoleInboundHTTPAllowlistExact`
// 钉死为**恰好两项**，多一个也算失败。
//
// 只读边界在本层有三处落点：
//  1. 路由表里每条的 Method 都是 "GET"（`TestConsoleRouteTableGETOnly` 用 go/parser 校验）；
//  2. 非 GET 命中已登记路径 → 405 + `Allow: GET`；未登记路径 → 404；
//  3. 处理函数只调用 `console.Reader` 的读取方法，不接触任何写路径。
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/XZ-libin/agent-ops/internal/console"
)

// Route 一条路由登记。
type Route struct {
	// Method 恒为 "GET"（守卫强制）。
	Method string
	// Path 精确路径；含 `{param}` 段表示路径参数。
	Path string
	// Param 路径参数名（无则空）。
	Param string
}

// routeTable 路由表的唯一来源（守卫与 OpenAPI 一致性测试都读它）。
func routeTable() []Route {
	return []Route{
		{Method: "GET", Path: "/v1/health"},
		{Method: "GET", Path: "/v1/nodes"},
		{Method: "GET", Path: "/v1/nodes/{node_id}", Param: "node_id"},
		{Method: "GET", Path: "/v1/approvals"},
		{Method: "GET", Path: "/v1/approvals/{approval_id}", Param: "approval_id"},
		{Method: "GET", Path: "/v1/audit/events"},
		{Method: "GET", Path: "/v1/audit/verify"},
		{Method: "GET", Path: "/v1/adapters"},
		{Method: "GET", Path: "/v1/policy"},
	}
}

// Routes 对外暴露路由表（供守卫与文档生成使用）。
func Routes() []Route { return routeTable() }

// errorMessages 错误码 → **固定**消息（不回显内部错误，ADR-024 §4）。
var errorMessages = map[string]string{
	"unauthorized":       "需要有效的访问令牌",
	"not_found":          "资源不存在",
	"method_not_allowed": "该接口只支持 GET",
	"bad_request":        "查询参数不合法",
	"internal":           "服务暂时不可用",
}

// Server 只读 API 服务。
type Server struct {
	reader  *console.Reader
	auth    *console.Verifier
	timeout time.Duration
	httpSrv *http.Server
}

// NewServer 构造服务。timeout <= 0 时用 console.DefaultTimeout（10 秒）。
func NewServer(reader *console.Reader, auth *console.Verifier, timeout time.Duration) (*Server, error) {
	if reader == nil {
		return nil, errors.New("httpapi：缺少只读数据访问层")
	}
	if auth == nil {
		return nil, errors.New("httpapi：缺少鉴权器")
	}
	if timeout <= 0 {
		timeout = console.DefaultTimeout
	}
	return &Server{reader: reader, auth: auth, timeout: timeout}, nil
}

// Handler 返回纯 HTTP 处理器（测试与装配都走这里）。
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

// ListenAndServe 在指定地址上启动只读服务。
//
// 入站符号（http.Server / ListenAndServe）在此出现，正是 ADR-024 登记本目录的原因。
func (s *Server) ListenAndServe(addr string) error {
	s.httpSrv = &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s.httpSrv.ListenAndServe()
}

// Shutdown 优雅关闭（未启动时为 nil，直接返回）。
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// serve 请求主流程：响应头 → 超时 → 鉴权 → 路由 → 处理。
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()

	// 鉴权先于路由：不向未认证者暴露"这个路径存在吗"。
	actor, err := s.auth.Authenticate(ctx, r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	route, matched, methodOK := matchRoute(r.Method, r.URL.Path)
	if !matched {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if !methodOK {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	s.dispatch(ctx, w, r, route, actor)
}

// dispatch 按路径分派到读取方法。
func (s *Server) dispatch(ctx context.Context, w http.ResponseWriter, r *http.Request, route Route, actor string) {
	q := r.URL.Query()
	switch route.Path {
	case "/v1/health":
		writeProto(w, http.StatusOK, s.reader.Health(ctx))
	case "/v1/nodes":
		items, err := s.reader.ListNodes(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeList(w, items)
	case "/v1/nodes/{node_id}":
		id := pathParam(r.URL.Path, "/v1/nodes/")
		item, err := s.reader.GetNode(ctx, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		if item == nil {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		writeProto(w, http.StatusOK, item)
	case "/v1/approvals":
		limit, err := console.NormalizeLimit(q.Get("limit"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		items, err := s.reader.ListApprovals(ctx, q.Get("status"), limit, q.Get("cursor"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeList(w, items)
	case "/v1/approvals/{approval_id}":
		id := pathParam(r.URL.Path, "/v1/approvals/")
		item, err := s.reader.GetApproval(ctx, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		if item == nil {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		writeProto(w, http.StatusOK, item)
	case "/v1/audit/events":
		limit, err := console.NormalizeLimit(q.Get("limit"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		after, err := console.NormalizeAfterSeq(q.Get("after_seq"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		items, err := s.reader.ListAuditEvents(ctx, after, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeList(w, items)
	case "/v1/audit/verify":
		res, err := s.reader.VerifyAudit(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeProto(w, http.StatusOK, res)
	case "/v1/adapters":
		items, err := s.reader.Adapters(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeList(w, items)
	case "/v1/policy":
		view, err := s.reader.Policy(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		writeProto(w, http.StatusOK, view)
	default:
		writeError(w, http.StatusNotFound, "not_found")
	}
	_ = actor // actor 仅用于鉴权判定与审计关联，不进入响应
}

// matchRoute 匹配路径与方法。
//
// 返回 (路由, 是否命中路径, 方法是否允许)。方法不对时 matched=true、methodOK=false，
// 由调用方补 `Allow: GET`。
func matchRoute(method, path string) (Route, bool, bool) {
	clean := strings.TrimRight(path, "/")
	if clean == "" {
		clean = "/"
	}
	for _, rt := range routeTable() {
		want := strings.TrimRight(rt.Path, "/")
		var got bool
		if rt.Param == "" {
			got = clean == want
		} else {
			prefix := strings.TrimRight(want[:strings.Index(want, "{")], "/") + "/"
			got = strings.HasPrefix(clean, prefix) &&
				strings.Index(clean[len(prefix):], "/") < 0 &&
				clean[len(prefix):] != ""
		}
		if got {
			return rt, true, method == rt.Method
		}
	}
	return Route{}, false, false
}

// pathParam 取出 `/v1/nodes/<id>` 形式的参数值。
func pathParam(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	return strings.TrimRight(strings.TrimPrefix(path, prefix), "/")
}

// —— 响应写出 ——

// marshalOpts 编码约定（ADR-024 §4）：
//   - UseProtoNames：键名用 proto 原样 snake_case，与 openapi/console.yaml 一致；
//   - EmitUnpopulated：**必须**输出零值字段。否则 `ok:false`、`schema_version:0`、
//     `cert_state:""` 这类"否定的事实"会从响应里消失——控制台上"没有这个字段"和
//     "值为 false/空"是两回事，前者会让运维误判。
var marshalOpts = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}

func writeProto(w http.ResponseWriter, status int, msg proto.Message) {
	body, err := marshalOpts.Marshal(msg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	writeJSON(w, status, body)
}

// writeList 把消息列表编码为 JSON 数组（列表本身不是契约消息，见 ADR-024 §6）。
func writeList[T proto.Message](w http.ResponseWriter, items []T) {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		body, err := marshalOpts.Marshal(it)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
		parts = append(parts, string(body))
	}
	writeJSON(w, http.StatusOK, []byte("["+strings.Join(parts, ",")+"]"))
}

// envelope 错误信封（传输层结构，不属于 proto 契约）。
type envelope struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code string) {
	msg, ok := errorMessages[code]
	if !ok {
		msg = errorMessages["internal"]
	}
	body, err := json.Marshal(map[string]envelope{"error": {Code: code, Message: msg}})
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
