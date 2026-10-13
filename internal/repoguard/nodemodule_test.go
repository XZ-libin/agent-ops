// 节点模块守卫（第二十一轮硬性约束 6）：
//   - node-agent 模块**不得** import net/http（含测试文件）；
//   - 节点相关代码不得引入 PEM 私钥字样（与既有私钥守卫呼应，这里限定在节点相关路径）。
//
// 为什么单独一条：仓库级守卫（scanAST）只扫描**非测试** .go 文件；节点模块目前只有
// 一个骨架 main.go，容易在后续实现中"顺手"引入 net/http（例如用 HTTP 做注册回调），
// 而本轮的协议选型是 gRPC（ADR-020 §2）。这条守卫把选型固化下来。
package repoguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nodeModuleDir 节点代理模块目录（相对仓库根）。
const nodeModuleDir = "node-agent"

// TestNodeAgentModuleAvoidsHTTP（硬性约束 6）node-agent 不得 import net/http。
func TestNodeAgentModuleAvoidsHTTP(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, nodeModuleDir)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("未找到节点模块目录 %s：%v", nodeModuleDir, err)
	}
	var offenders []string
	scanned := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		scanned++
		text := string(raw)
		// import 声明中的 net/http / net/http/... 一律违规。
		if strings.Contains(text, `"net/http"`) || strings.Contains(text, `"net/http/`) {
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("扫描节点模块失败：%v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("[约束 6] node-agent 模块不得 import net/http（协议选型为 gRPC）：%v", offenders)
	}
	if scanned == 0 {
		t.Fatal("未扫描到任何 .go 文件（守卫可能失效）")
	}
	t.Logf("[约束 6] node-agent 模块 %d 个 .go 文件均未 import net/http（协议为 gRPC）", scanned)
}

// TestNodePathsContainNoPrivateKeyMarkers（N2 约束）节点相关代码不含 PEM 私钥字样。
//
// 说明：仓库级 TestNoPrivateKeysCommittedInRepo 已覆盖全仓；这里额外把**节点相关
// 路径**（node-agent 模块 + control-plane/internal/nodeidentity）单独断言一次，
// 因为本轮引入了 CA/证书签发代码，是最容易误提交私钥的位置。
func TestNodePathsContainNoPrivateKeyMarkers(t *testing.T) {
	root := repoRoot(t)
	targets := []string{
		filepath.Join(root, nodeModuleDir),
		filepath.Join(root, "internal", "nodeidentity"),
		filepath.Join(root, "internal", "nodehealth"),
	}
	begin := "-----BEGIN "
	end := "PRIVATE KEY-----"
	markers := []string{begin + end, begin + "RSA " + end, begin + "EC " + end, begin + "OPENSSH " + end}

	scanned := 0
	var offenders []string
	for _, dir := range targets {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("未找到目录 %s：%v", dir, err)
		}
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			raw, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			scanned++
			for _, m := range markers {
				if strings.Contains(string(raw), m) {
					rel, _ := filepath.Rel(root, path)
					offenders = append(offenders, rel)
					break
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("扫描 %s 失败：%v", dir, err)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("[N2] 节点相关路径不得含 PEM 私钥：%v", offenders)
	}
	t.Logf("[N2] 节点相关路径共扫描 %d 个文件，无 PRIVATE KEY 字样（CA 私钥仅内存）", scanned)
}

// TestNodeAgentModuleAvoidsInsecureTLS（D4 硬性约束）node-agent 不得使用
// InsecureSkipVerify 或等价的"跳过校验"选项。
//
// 用 go/parser 做 AST 级检查（而非字符串匹配），避免被注释/字符串字面量误伤，
// 也避免"换个写法绕过"：
//   - tls.Config 字面量中出现 InsecureSkipVerify 字段（无论真假值）；
//   - grpc 的 WithInsecure / insecure.NewCredentials（明文连接）。
func TestNodeAgentModuleAvoidsInsecureTLS(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, nodeModuleDir)

	// 等价"跳过校验"的符号（AST selector 形态）。
	forbiddenSelectors := map[string]string{
		"InsecureSkipVerify":    "禁止设置 InsecureSkipVerify（任何取值）",
		"WithInsecure":          "禁止使用 grpc.WithInsecure（明文连接）",
		"NewCredentials":        "禁止使用 insecure.NewCredentials（明文连接）",
		"VerifyPeerCertificate": "禁止自定义 VerifyPeerCertificate 绕过链校验",
	}
	// NewCredentials 仅当来自 insecure 包时才算违规：这里按 selector 名 + 包名判断。
	var offenders []string
	scanned := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		scanned++
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, raw, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name := sel.Sel.Name
			reason, bad := forbiddenSelectors[name]
			if !bad {
				return true
			}
			// insecure.NewCredentials：只在包名为 insecure 时判定。
			if name == "NewCredentials" {
				id, isIdent := sel.X.(*ast.Ident)
				if !isIdent || id.Name != "insecure" {
					return true
				}
			}
			offenders = append(offenders, fmt.Sprintf("%s:%d %s（%s）",
				rel, fset.Position(sel.Pos()).Line, name, reason))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("扫描节点模块失败：%v", err)
	}
	if len(offenders) > 0 {
		for _, o := range offenders {
			t.Errorf("[D4] %s", o)
		}
		t.Fatalf("[D4] node-agent 不得跳过 TLS 校验（发现 %d 处）", len(offenders))
	}
	if scanned == 0 {
		t.Fatal("未扫描到任何 .go 文件（守卫可能失效）")
	}
	t.Logf("[D4] node-agent %d 个 .go 文件：无 InsecureSkipVerify / WithInsecure / insecure.NewCredentials / 自定义 VerifyPeerCertificate", scanned)
}
