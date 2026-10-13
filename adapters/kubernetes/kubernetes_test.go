package kubernetes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	contractv1 "github.com/ORG/agent-ops/contract/gen/go/agent_ops/contract/v1"

	"github.com/ORG/agent-ops/internal/validation"
)

// —— 测试辅助 ——

// newFakeAPIServer 启动一个假的 Kubernetes API Server（仅测试；不接触真实集群）。
// 记录每个请求的方法与路径，便于断言"只发 GET 白名单端点"。
func newFakeAPIServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *[]string) {
	t.Helper()
	seen := &[]string{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+r.URL.Path)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

// testAdapter 用假 API Server 构建适配器（直接注入客户端，跳过 kubeconfig 解析）。
func testAdapter(t *testing.T, srv *httptest.Server) *Adapter {
	t.Helper()
	a, err := New(Config{
		Mode:           ModeTest,
		KubeconfigPath: writeKubeconfig(t, srv.URL),
	})
	if err != nil {
		t.Fatalf("构建适配器失败：%v", err)
	}
	return a
}

// —— K1/K2：端点白名单 ——

// TestAllowedEndpointWhitelist 白名单：只允许五个只读 GET 端点形态；
// secrets、exec、log、写方法一律拒绝。
func TestAllowedEndpointWhitelist(t *testing.T) {
	allowed := []string{
		"/version",
		"/api/v1/namespaces/agent-ops-test",
		"/api/v1/namespaces/agent-ops-test/pods",
		"/api/v1/namespaces/agent-ops-test/pods/busybox-1",
		"/apis/apps/v1/namespaces/agent-ops-test/deployments",
	}
	for _, p := range allowed {
		if err := AllowedEndpoint(http.MethodGet, p); err != nil {
			t.Errorf("白名单端点应放行：%s → %v", p, err)
		}
	}

	secrets := []string{
		"/api/v1/secrets",
		"/api/v1/namespaces/agent-ops-test/secrets",
		"/api/v1/namespaces/agent-ops-test/secrets/db-password",
		"/api/v1/namespaces/default/secrets",
		"/api/v1/secret",
	}
	for _, p := range secrets {
		err := AllowedEndpoint(http.MethodGet, p)
		if !errors.Is(err, ErrSecretAccessForbidden) {
			t.Errorf("secrets 路径必须拒绝（永不读取 Secret）：%s → %v", p, err)
		}
	}

	denied := []string{
		"/api/v1/namespaces/agent-ops-test/pods/busybox-1/exec",
		"/api/v1/namespaces/agent-ops-test/pods/busybox-1/log",
		"/api/v1/namespaces/agent-ops-test/pods/busybox-1/portforward",
		"/api/v1/namespaces/agent-ops-test/pods/busybox-1/attach",
		"/api/v1/namespaces/agent-ops-test/serviceaccounts/default",
		"/api/v1/namespaces/agent-ops-test/serviceaccounts/default/token",
		"/api/v1/nodes",
		"/api/v1/namespaces",
		"/api/v1/namespaces/agent-ops-test/configmaps",
		"/api/v1/namespaces/agent-ops-test/services",
		"/api/v1/namespaces/agent-ops-test/pods/busybox-1/status",
		"/api/v1/namespaces/agent-ops-test/pods/../secrets",
		"/version/../secrets",
		"/api/v1/namespaces/Agent-Ops-Test/pods",
		"/apis/apps/v1/namespaces/agent-ops-test/deployments/app",
		"/apis/apps/v1/namespaces/agent-ops-test/statefulsets",
	}
	for _, p := range denied {
		if err := AllowedEndpoint(http.MethodGet, p); err == nil {
			t.Errorf("非白名单端点必须拒绝：%s", p)
		}
	}

	// 写方法一律拒绝。
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		err := AllowedEndpoint(m, "/api/v1/namespaces/agent-ops-test/pods")
		if !errors.Is(err, ErrWriteMethodForbidden) {
			t.Errorf("%s 必须被拒绝（写方法）：%v", m, err)
		}
	}
}

// TestClientNeverSendsForbiddenRequests 客户端只发 GET 白名单端点。
func TestClientNeverSendsForbiddenRequests(t *testing.T) {
	srv, seen := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"major":"1","minor":"31","gitVersion":"v1.31.0"}`))
		case "/api/v1/namespaces/agent-ops-test":
			_, _ = w.Write([]byte(`{"metadata":{"name":"agent-ops-test","labels":{"agent-ops.test":"true"}}}`))
		case "/api/v1/namespaces/agent-ops-test/pods":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"p1","labels":{"agent-ops.test":"true"}}}]}`))
		case "/api/v1/namespaces/agent-ops-test/pods/p1":
			_, _ = w.Write([]byte(`{"metadata":{"name":"p1","labels":{"agent-ops.test":"true"}},"status":{"phase":"Running"}}`))
		case "/apis/apps/v1/namespaces/agent-ops-test/deployments":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"d1","labels":{"agent-ops.test":"true"}}}]}`))
		default:
			t.Errorf("客户端请求了白名单之外的端点：%s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	a := testAdapter(t, srv)
	ctx := context.Background()

	if _, err := a.Discover(ctx, &contractv1.AssetTarget{AssetId: "ast_k8s"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Health(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Diagnose(ctx, nil, QuestionNamespaceGet+"agent-ops-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Diagnose(ctx, nil, QuestionPodList+"agent-ops-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Diagnose(ctx, nil, QuestionPodStatus+"agent-ops-test/p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Diagnose(ctx, nil, QuestionDeploymentList+"agent-ops-test"); err != nil {
		t.Fatal(err)
	}
	for _, got := range *seen {
		parts := strings.SplitN(got, " ", 2)
		if parts[0] != http.MethodGet {
			t.Fatalf("只读适配器不得发送非 GET 请求：%s", got)
		}
		if err := AllowedEndpoint(parts[0], parts[1]); err != nil {
			t.Fatalf("请求端点不在白名单内：%s（%v）", got, err)
		}
	}
}

// TestSecretsNeverRequested 永不读取 Secret：适配器层直接拒绝，不发往集群。
func TestSecretsNeverRequested(t *testing.T) {
	srv, seen := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("不得向集群发起任何请求（secrets 在适配器层即被拒绝）")
		w.WriteHeader(http.StatusForbidden)
	})
	a := testAdapter(t, srv)

	for _, p := range []string{
		"/api/v1/secrets",
		"/api/v1/namespaces/agent-ops-test/secrets",
	} {
		if _, err := a.client.get(context.Background(), p, nil); !errors.Is(err, ErrSecretAccessForbidden) {
			t.Fatalf("secrets 路径必须被拒绝：%s → %v", p, err)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("secrets 请求不得发往集群：%v", *seen)
	}
}

// —— K1/K2：屏蔽规则 ——

// TestMaskPodWhitelistKeepsOnlyAllowedFields（H2）Pod spec 白名单裁剪：
// 只保留明确列出的字段；注入未知字段（ephemeralContainers、lifecycle、
// command、args、volumes、envFrom 等）必须不出现在输出中。
func TestMaskPodWhitelistKeepsOnlyAllowedFields(t *testing.T) {
	raw := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "busybox-1",
			"namespace": "agent-ops-test",
			"labels": map[string]any{
				TestLabel:      "true",
				"app":          "itest",
				"secret.label": "must-not-leak",
			},
			"annotations": map[string]any{
				"agent-ops.test/owner": "ops",
				"secret.db-password":   "s3cr3t",
				"token.github":         "ghp_xxx",
				"credential.aws":       "AKIA",
				"kubectl.kubernetes.io/last-applied-configuration": `{"spec":{"containers":[{"env":[{"value":"must-not-leak"}]}]}}`,
			},
			"managedFields":   []any{map[string]any{"fieldsV1": map[string]any{}}},
			"ownerReferences": []any{map[string]any{"name": "rs-1"}},
		},
		"spec": map[string]any{
			"nodeName":           "node-1",
			"restartPolicy":      "Always",
			"serviceAccountName": "default",
			"containers": []any{
				map[string]any{
					"name":            "app",
					"image":           "busybox:1.36",
					"imagePullPolicy": "IfNotPresent",
					"resources":       map[string]any{"limits": map[string]any{"cpu": "100m"}},
					"ports":           []any{map[string]any{"name": "http", "containerPort": 8080, "protocol": "TCP", "hostPort": 9999}},
					// 以下字段一律不得返回
					"env":             []any{map[string]any{"name": "DB_PASSWORD", "value": "must-not-leak"}},
					"envFrom":         []any{map[string]any{"secretRef": map[string]any{"name": "s"}}},
					"lifecycle":       map[string]any{"preStop": map[string]any{"exec": map[string]any{"command": []any{"rm", "-rf", "/"}}}},
					"command":         []any{"sh", "-c", "echo must-not-leak"},
					"args":            []any{"--secret=must-not-leak"},
					"volumeMounts":    []any{map[string]any{"name": "v", "mountPath": "/data"}},
					"securityContext": map[string]any{"runAsUser": 0},
					"livenessProbe":   map[string]any{"exec": map[string]any{"command": []any{"true"}}},
				},
			},
			"initContainers":      []any{map[string]any{"name": "init", "image": "busybox:1.36", "command": []any{"must-not-leak"}}},
			"ephemeralContainers": []any{map[string]any{"name": "debug", "image": "busybox:1.36", "command": []any{"must-not-leak"}}},
			"volumes":             []any{map[string]any{"name": "v", "secret": map[string]any{"secretName": "db-password"}}},
			"tolerations":         []any{map[string]any{"key": "k"}},
			"nodeSelector":        map[string]any{"disktype": "ssd"},
			"hostNetwork":         true,
		},
		"status": map[string]any{
			"phase":  "Running",
			"podIP":  "10.0.0.1",
			"hostIP": "172.19.0.2",
			"conditions": []any{
				map[string]any{"type": "Ready", "status": "True", "lastTransitionTime": "2026-01-01T00:00:00Z", "reason": "ContainersReady"},
			},
			"containerStatuses": []any{map[string]any{"name": "app", "image": "busybox:1.36"}},
		},
	}
	masked, dropped := MaskPod(raw)

	// 1) 已知字段保留。
	md := masked["metadata"].(map[string]any)
	if md["name"] != "busybox-1" || md["namespace"] != "agent-ops-test" {
		t.Fatalf("metadata 白名单字段应保留：%v", md)
	}
	spec := masked["spec"].(map[string]any)
	if spec["nodeName"] != "node-1" || spec["restartPolicy"] != "Always" || spec["serviceAccountName"] != "default" {
		t.Fatalf("spec 白名单字段应保留：%v", spec)
	}
	c := spec["containers"].([]any)[0].(map[string]any)
	if c["name"] != "app" || c["image"] != "busybox:1.36" || c["imagePullPolicy"] != "IfNotPresent" {
		t.Fatalf("containers 白名单字段应保留：%v", c)
	}
	if _, has := c["resources"]; !has {
		t.Fatal("resources 应保留")
	}
	port := c["ports"].([]any)[0].(map[string]any)
	if port["name"] != "http" || port["containerPort"] != 8080 {
		t.Fatalf("ports 白名单字段应保留：%v", port)
	}
	if _, has := port["protocol"]; has {
		t.Fatal("ports 只保留 name 与 containerPort")
	}
	st := masked["status"].(map[string]any)
	if st["phase"] != "Running" {
		t.Fatalf("status.phase 应保留：%v", st)
	}
	cond := st["conditions"].([]any)[0].(map[string]any)
	if cond["type"] != "Ready" || cond["status"] != "True" {
		t.Fatalf("conditions 白名单字段应保留：%v", cond)
	}
	if _, has := cond["reason"]; has {
		t.Fatal("Pod conditions 只保留 type 与 status（不含 reason）")
	}

	// 2) 注入的未知/敏感字段一律不出现。
	forbidden := []string{
		"ephemeralContainers", "initContainers", "volumes", "tolerations", "nodeSelector",
		"hostNetwork", "ownerReferences", "managedFields", "containerStatuses",
		"podIP", "hostIP",
	}
	for _, k := range forbidden {
		if _, has := spec[k]; has {
			t.Fatalf("spec.%s 不得返回", k)
		}
		if _, has := st[k]; has {
			t.Fatalf("status.%s 不得返回", k)
		}
		if _, has := md[k]; has {
			t.Fatalf("metadata.%s 不得返回", k)
		}
	}
	for _, k := range []string{"env", "envFrom", "lifecycle", "command", "args", "volumeMounts", "securityContext", "livenessProbe"} {
		if _, has := c[k]; has {
			t.Fatalf("containers[0].%s 不得返回", k)
		}
	}
	ann := md["annotations"].(map[string]any)
	for _, k := range []string{"secret.db-password", "token.github", "credential.aws", "kubectl.kubernetes.io/last-applied-configuration"} {
		if _, has := ann[k]; has {
			t.Fatalf("annotations %s 不得返回", k)
		}
	}
	if ann["agent-ops.test/owner"] != "ops" {
		t.Fatalf("非敏感注解应保留：%v", ann)
	}
	labels := md["labels"].(map[string]any)
	if _, has := labels["secret.label"]; has {
		t.Fatal("凭据类标签不得返回")
	}

	// 3) 输出中不得出现任何敏感值。
	blob := marshalIndent(masked)
	for _, secret := range []string{"must-not-leak", "s3cr3t", "ghp_xxx", "AKIA", "db-password"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("白名单裁剪输出泄露 %q：%s", secret, blob)
		}
	}
	// 4) 被裁剪路径应记录（便于核对）。
	joined := strings.Join(dropped, ",")
	for _, want := range []string{"spec.ephemeralContainers", "spec.initContainers", "spec.volumes", "spec.containers[0].env", "spec.containers[0].command", "metadata.managedFields"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("裁剪记录应包含 %s，实际 %v", want, dropped)
		}
	}
}

// TestMaskDeploymentWhitelist（H2）Deployment 白名单裁剪：
// replicas/selector/strategy.type/template 按 Pod spec 裁剪；
// status 只保留 phase/replicas/readyReplicas/availableReplicas/conditions(type,status,reason)。
func TestMaskDeploymentWhitelist(t *testing.T) {
	raw := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":        "app",
			"labels":      map[string]any{TestLabel: "true"},
			"annotations": map[string]any{"token.x": "t0k", "keep": "v"},
		},
		"spec": map[string]any{
			"replicas": 3,
			"selector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
			"strategy": map[string]any{
				"type":          "RollingUpdate",
				"rollingUpdate": map[string]any{"maxSurge": 1},
			},
			"revisionHistoryLimit": 10,
			"template": map[string]any{
				"metadata": map[string]any{
					"labels":      map[string]any{"app": "x", "secret.l": "must-not-leak"},
					"annotations": map[string]any{"secret.a": "s0", "keep2": "v2"},
				},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":    "app",
							"image":   "busybox:1.36",
							"env":     []any{map[string]any{"name": "P", "value": "must-not-leak"}},
							"envFrom": []any{map[string]any{"secretRef": map[string]any{"name": "s"}}},
							"command": []any{"must-not-leak"},
						},
					},
					"volumes": []any{map[string]any{"name": "v", "secret": map[string]any{"secretName": "s"}}},
				},
			},
		},
		"status": map[string]any{
			"replicas":            3,
			"readyReplicas":       2,
			"availableReplicas":   2,
			"unavailableReplicas": 1,
			"observedGeneration":  1,
			"conditions": []any{
				map[string]any{"type": "Available", "status": "True", "reason": "MinimumReplicasAvailable", "message": "leak-me"},
			},
		},
	}
	masked, dropped := MaskDeployment(raw)
	spec := masked["spec"].(map[string]any)
	if spec["replicas"] != 3 {
		t.Fatalf("replicas 应保留：%v", spec)
	}
	if _, has := spec["selector"]; !has {
		t.Fatal("selector 应保留")
	}
	strategy := spec["strategy"].(map[string]any)
	if strategy["type"] != "RollingUpdate" {
		t.Fatalf("strategy.type 应保留：%v", strategy)
	}
	if _, has := strategy["rollingUpdate"]; has {
		t.Fatal("strategy 只保留 type")
	}
	if _, has := spec["revisionHistoryLimit"]; has {
		t.Fatal("revisionHistoryLimit 不得返回")
	}
	tmpl := spec["template"].(map[string]any)
	tspec := tmpl["spec"].(map[string]any)
	tc := tspec["containers"].([]any)[0].(map[string]any)
	for _, k := range []string{"env", "envFrom", "command"} {
		if _, has := tc[k]; has {
			t.Fatalf("Pod 模板 containers[0].%s 不得返回", k)
		}
	}
	if _, has := tspec["volumes"]; has {
		t.Fatal("Pod 模板 volumes 不得返回")
	}
	if _, has := tmpl["metadata"].(map[string]any)["annotations"].(map[string]any)["secret.a"]; has {
		t.Fatal("Pod 模板凭据类注解不得返回")
	}
	if _, has := tmpl["metadata"].(map[string]any)["labels"].(map[string]any)["secret.l"]; has {
		t.Fatal("Pod 模板凭据类标签不得返回")
	}
	st := masked["status"].(map[string]any)
	if st["replicas"] != 3 || st["readyReplicas"] != 2 || st["availableReplicas"] != 2 {
		t.Fatalf("status 白名单字段应保留：%v", st)
	}
	if _, has := st["unavailableReplicas"]; has {
		t.Fatal("status.unavailableReplicas 不得返回")
	}
	cond := st["conditions"].([]any)[0].(map[string]any)
	if cond["type"] != "Available" || cond["status"] != "True" || cond["reason"] != "MinimumReplicasAvailable" {
		t.Fatalf("Deployment conditions 应保留 type/status/reason：%v", cond)
	}
	if _, has := cond["message"]; has {
		t.Fatal("conditions.message 不得返回")
	}
	blob := marshalIndent(masked)
	for _, secret := range []string{"must-not-leak", "t0k", "s0", "leak-me"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("白名单裁剪输出泄露 %q：%s", secret, blob)
		}
	}
	if !strings.Contains(strings.Join(dropped, ","), "spec.template.spec.containers[0].env") {
		t.Fatalf("裁剪记录应包含模板 env：%v", dropped)
	}
}

// TestMaskNamespaceWhitelist 命名空间白名单裁剪（凭据类注解与标签删除）。
func TestMaskNamespaceWhitelist(t *testing.T) {
	raw := map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":          "agent-ops-test",
			"labels":        map[string]any{TestLabel: "true", "token.l": "must-not-leak"},
			"annotations":   map[string]any{"secret.k": "v", "token.k": "v", "password.k": "v", "credential.k": "v", "keep": "ok"},
			"managedFields": []any{map[string]any{}},
		},
		"status": map[string]any{"phase": "Active"},
	}
	masked, dropped := MaskNamespace(raw)
	md := masked["metadata"].(map[string]any)
	ann := md["annotations"].(map[string]any)
	if len(ann) != 1 || ann["keep"] != "ok" {
		t.Fatalf("只应保留非凭据注解：%v", ann)
	}
	if _, has := md["labels"].(map[string]any)["token.l"]; has {
		t.Fatal("凭据类标签不得返回")
	}
	if _, has := md["managedFields"]; has {
		t.Fatal("managedFields 不得返回")
	}
	if len(dropped) < 5 {
		t.Fatalf("应记录被裁剪项：%v", dropped)
	}
}

// —— K1/K2：标签过滤与空列表报错 ——

// TestListPodsFiltersByLabel 只返回带测试标签的 Pod（逐项复核）。
func TestListPodsFiltersByLabel(t *testing.T) {
	var gotSelector string
	srv, _ := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotSelector = r.URL.Query().Get("labelSelector")
		_, _ = w.Write([]byte(`{"items":[
			{"metadata":{"name":"p1","labels":{"agent-ops.test":"true"}},"status":{"phase":"Running"}},
			{"metadata":{"name":"kube-dns","labels":{"k8s-app":"kube-dns"}},"status":{"phase":"Running"}},
			{"metadata":{"name":"p2","labels":{"agent-ops.test":"false"}},"status":{"phase":"Running"}}
		]}`))
	})
	a := testAdapter(t, srv)
	pods, err := a.client.ListPods(context.Background(), "agent-ops-test")
	if err != nil {
		t.Fatalf("应返回过滤后的列表：%v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("只应返回 1 个测试标签 Pod：%v", pods)
	}
	md := pods[0]["metadata"].(map[string]any)
	if md["name"] != "p1" {
		t.Fatalf("返回的 Pod 不符：%v", md)
	}
	if !strings.Contains(gotSelector, TestLabel+"=true") {
		t.Fatalf("必须下发标签选择器，实际 %q", gotSelector)
	}
}

// TestEmptyListReturnsExplicitError 空列表 → 明确报错（不静默）。
func TestEmptyListReturnsExplicitError(t *testing.T) {
	srv, _ := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	a := testAdapter(t, srv)
	if _, err := a.client.ListPods(context.Background(), "agent-ops-test"); !errors.Is(err, ErrNoLabelledObjects) {
		t.Fatalf("空 Pod 列表应明确报错：%v", err)
	}
	if _, err := a.client.ListDeployments(context.Background(), "agent-ops-test"); !errors.Is(err, ErrNoLabelledObjects) {
		t.Fatalf("空 Deployment 列表应明确报错：%v", err)
	}
	if _, err := a.Diagnose(context.Background(), nil, QuestionPodList+"agent-ops-test"); !errors.Is(err, ErrNoLabelledObjects) {
		t.Fatalf("Diagnose 空列表应明确报错：%v", err)
	}
}

// TestUnlabelledObjectRejected 无测试标签的对象不得读取（命名空间与 Pod）。
func TestUnlabelledObjectRejected(t *testing.T) {
	srv, _ := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"metadata":{"name":"kube-system","labels":{"kubernetes.io/metadata.name":"kube-system"}}}`))
	})
	a := testAdapter(t, srv)
	if _, _, err := a.client.GetNamespace(context.Background(), "kube-system"); !errors.Is(err, ErrNoLabelledObjects) {
		t.Fatalf("无测试标签的命名空间不得读取：%v", err)
	}
	if _, _, err := a.client.GetPod(context.Background(), "kube-system", "coredns"); !errors.Is(err, ErrNoLabelledObjects) {
		t.Fatalf("无测试标签的 Pod 不得读取：%v", err)
	}
}

// —— K1/K2：超时、响应体上限、写方法、只读语义 ——

// TestRequestTimeout 超时（默认 10s，可配）。
func TestRequestTimeout(t *testing.T) {
	srv, _ := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(500 * time.Millisecond):
			_, _ = w.Write([]byte(`{}`))
		case <-r.Context().Done():
		}
	})
	a := testAdapter(t, srv)
	a.client.http.Timeout = 50 * time.Millisecond
	start := time.Now()
	if _, err := a.client.Version(context.Background()); err == nil {
		t.Fatal("超时请求应报错")
	}
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Fatalf("应在超时时长内返回：%v", elapsed)
	}
	if DefaultTimeout != 10*time.Second {
		t.Fatalf("默认超时应为 10 秒，实际 %v", DefaultTimeout)
	}
}

// TestResponseBodyLimit 响应体上限（默认 1MB，可配）。
func TestResponseBodyLimit(t *testing.T) {
	big := strings.Repeat("x", 4096)
	srv, _ := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"blob":"` + big + `"}`))
	})
	a := testAdapter(t, srv)
	a.client.maxBody = 1024
	if _, err := a.client.Version(context.Background()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("超过响应体上限应报错：%v", err)
	}
	if DefaultMaxBodyBytes != 1<<20 {
		t.Fatalf("默认上限应为 1MB，实际 %d", DefaultMaxBodyBytes)
	}
}

// TestExecuteRejectsReadOnlyCapabilities Execute 对只读能力直接拒绝；
// PlanRollback 返回 ErrNoRollbackNeeded。
func TestExecuteRejectsReadOnlyCapabilities(t *testing.T) {
	srv, seen := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	a := testAdapter(t, srv)
	ctx := context.Background()
	for _, capName := range []string{
		"k8s.version", "k8s.namespace.get", "k8s.pod.list", "k8s.pod.status", "k8s.deployment.list",
	} {
		_, err := a.Execute(ctx, &contractv1.Action{Capability: capName}, &contractv1.AuthZ{AuthorizationId: "az"})
		if !errors.Is(err, ErrReadOnlyHint) {
			t.Fatalf("%s 应被拒绝并提示走 Diagnose/Health：%v", capName, err)
		}
	}
	if _, err := a.Execute(ctx, &contractv1.Action{Capability: "k8s.pod.delete"}, nil); err == nil {
		t.Fatal("未声明能力必须拒绝")
	}
	if _, err := a.PlanRollback(ctx, &contractv1.ActionRecord{}); !errors.Is(err, ErrNoRollbackNeeded) {
		t.Fatalf("只读适配器回滚计划应返回 ErrNoRollbackNeeded：%v", err)
	}
	if len(*seen) != 0 {
		t.Fatalf("Execute/PlanRollback 不得发起任何集群请求：%v", *seen)
	}
}

// TestDiagnoseRejectsFreeText 自由文本与非法标识一律拒绝。
func TestDiagnoseRejectsFreeText(t *testing.T) {
	srv, seen := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	a := testAdapter(t, srv)
	for _, q := range []string{
		"get all pods", "kubectl get secrets", "pod_list:", "pod_list:../secrets",
		"pod_list:Agent-Ops", "pod_status:agent-ops-test", "pod_status:ns/../secrets",
		"namespace_get:", "deployment_list:../..",
	} {
		if _, err := a.Diagnose(context.Background(), nil, q); err == nil {
			t.Fatalf("非法诊断问题必须拒绝：%q", q)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("非法问题不得发起请求：%v", *seen)
	}
}

// TestManifestIsReadOnlyOnly 清单：五个只读能力、rollbackable=false、
// destructive=false、超时为正。
func TestManifestIsReadOnlyOnly(t *testing.T) {
	srv, _ := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	a := testAdapter(t, srv)
	m := a.Manifest()
	if m == nil || len(m.Capabilities) != 5 {
		t.Fatalf("应声明 5 个能力：%+v", m)
	}
	want := map[string]bool{
		"k8s.version": true, "k8s.namespace.get": true, "k8s.pod.list": true,
		"k8s.pod.status": true, "k8s.deployment.list": true,
	}
	for _, c := range m.Capabilities {
		if !want[c.Name] {
			t.Fatalf("未预期的能力：%s", c.Name)
		}
		delete(want, c.Name)
		if c.RiskTier != contractv1.RiskTier_RISK_TIER_READ_ONLY || c.Rollbackable || c.Destructive {
			t.Fatalf("%s 必须是只读且不可回滚/非破坏：%+v", c.Name, c)
		}
		if c.Timeout == nil || c.Timeout.AsDuration() <= 0 {
			t.Fatalf("%s 必须声明正超时", c.Name)
		}
		if !validation.ValidCapabilityName(c.Name) {
			t.Fatalf("%s 名称不合法", c.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("缺少能力声明：%v", want)
	}
}

// TestConfigValidation 连接配置校验：模式必填、test 需 kubeconfig、
// prod 仅接受 ServiceAccount（本轮不做生产连接）。
func TestConfigValidation(t *testing.T) {
	if _, err := NewClient(Config{}); err == nil {
		t.Fatal("未指定模式必须拒绝")
	}
	if _, err := NewClient(Config{Mode: ModeTest}); err == nil {
		t.Fatal("test 模式缺少 kubeconfig 必须拒绝")
	}
	if _, err := NewClient(Config{Mode: ModeTest, KubeconfigPath: "/nonexistent/kubeconfig"}); err == nil {
		t.Fatal("kubeconfig 不存在必须拒绝")
	}
	if _, err := NewClient(Config{Mode: ModeProd}); !errors.Is(err, ErrProdServiceAccountOnly) {
		t.Fatalf("prod 模式必须要求 ServiceAccount：%v", err)
	}
	if _, err := NewClient(Config{Mode: ModeProd, ServiceAccount: &ServiceAccountConfig{
		APIServer: "http://insecure:6443",
	}}); err == nil {
		t.Fatal("prod 模式 APIServer 必须为 https")
	}
	if _, err := NewClient(Config{Mode: ModeProd, ServiceAccount: &ServiceAccountConfig{
		APIServer: "https://k8s.example:6443", TokenFile: "/var/run/secrets/token", CAFile: "/var/run/secrets/ca.crt",
	}}); err != nil {
		t.Fatalf("prod 模式配置校验应通过（不建立连接）：%v", err)
	}
}

// TestParseModeRequiresExplicitValue 模式必须显式指定。
func TestParseModeRequiresExplicitValue(t *testing.T) {
	if _, err := ParseMode(""); err == nil {
		t.Fatal("空模式必须拒绝")
	}
	if _, err := ParseMode("staging"); err == nil {
		t.Fatal("未知模式必须拒绝")
	}
	if m, err := ParseMode("test"); err != nil || m != ModeTest {
		t.Fatalf("test 应解析成功：%v %v", m, err)
	}
}

// TestMaskPodRemovesLastAppliedConfiguration 回归测试（K2 集成测试在真实集群上
// 发现的泄露）：kubectl apply 写入的 last-applied-configuration 注解内嵌完整清单
// JSON（含 env 取值与 secret 类注解原值），必须整条删除；
// metadata.managedFields 一并删除。
func TestMaskPodRemovesLastAppliedConfiguration(t *testing.T) {
	raw := map[string]any{
		"metadata": map[string]any{
			"name":   "busybox-1",
			"labels": map[string]any{TestLabel: "true"},
			"annotations": map[string]any{
				"kubectl.kubernetes.io/last-applied-configuration": `{"spec":{"containers":[{"env":[{"name":"S","value":"must-not-leak"}]}]}}`,
				"agent-ops.test/owner":                             "ops",
			},
			"managedFields": []any{
				map[string]any{"fieldsV1": map[string]any{"f:metadata": map[string]any{"f:annotations": map[string]any{"f:secret.itest": map[string]any{}}}}},
			},
		},
		"spec":   map[string]any{"containers": []any{map[string]any{"name": "c", "env": []any{map[string]any{"name": "S", "value": "must-not-leak"}}}}},
		"status": map[string]any{"phase": "Running"},
	}
	masked, paths := MaskPod(raw)
	md := masked["metadata"].(map[string]any)
	ann := md["annotations"].(map[string]any)
	if _, has := ann["kubectl.kubernetes.io/last-applied-configuration"]; has {
		t.Fatal("last-applied-configuration 注解必须整条删除（内嵌完整清单）")
	}
	if ann["agent-ops.test/owner"] != "ops" {
		t.Fatalf("非敏感注解必须保留：%v", ann)
	}
	if _, has := md["managedFields"]; has {
		t.Fatal("managedFields 必须删除")
	}
	blob := marshalIndent(masked)
	if strings.Contains(blob, "must-not-leak") {
		t.Fatalf("屏蔽结果泄露敏感值：%s", blob)
	}
	joined := strings.Join(paths, ",")
	for _, want := range []string{"annotations.kubectl.kubernetes.io/last-applied-configuration", "managedFields", "spec.containers[0].env"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("屏蔽路径应包含 %s，实际 %v", want, paths)
		}
	}
}
