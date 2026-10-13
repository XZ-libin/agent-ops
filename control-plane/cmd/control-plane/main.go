// Command control-plane 是 Agent Ops 控制层服务入口。
// 当前为骨架占位：不注入任何模块与业务逻辑，服务端监听与 /api/v1 接入随后续批次实现。
package main

import "fmt"

const version = "0.1.0-dev"

func main() {
	fmt.Printf("agent-ops control-plane %s (skeleton)\n", version)
}
