package kubernetes

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// writeKubeconfig 写入一份指向假 API Server 的 kubeconfig（仅测试；
// 证书来自 httptest 的自签证书，不涉及任何真实集群凭据）。
func writeKubeconfig(t *testing.T, serverURL string) string {
	t.Helper()
	// httptest.NewTLSServer 使用自签证书：测试中显式信任其 CA。
	// 这里把 server 指向假服务端；CA 校验在测试里通过 InsecureSkipVerify 关闭
	// （仅测试；生产走 ServiceAccount + CAFile）。
	kc := `apiVersion: v1
kind: Config
current-context: agent-ops-itest
clusters:
  - name: itest
    cluster:
      server: ` + serverURL + `
      insecure-skip-tls-verify: true
contexts:
  - name: agent-ops-itest
    context:
      cluster: itest
      user: itest
users:
  - name: itest
    user: {}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

var _ = base64.StdEncoding
