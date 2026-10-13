SHELL := /bin/bash
GO ?= go

# 代码生成工具链版本固定（ADR-002：生成产物进仓库，CI 校验一致性）。
BUF_VERSION     := v1.47.2
GEN_GO_VERSION  := v1.36.1
GEN_GO_GRPC_VER := v1.5.1

BUF        := $(GO) run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
GOBIN      := $(shell $(GO) env GOPATH)/bin
GO_MODULES := . contract control-plane gateway node-agent adapters alerts

.PHONY: deps gen gen-check build test test-verbose fmt residual-check ci

## 安装代码生成插件（protoc-gen-go / protoc-gen-go-grpc，版本固定）
deps:
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(GEN_GO_VERSION)
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(GEN_GO_GRPC_VER)

## 从 proto 生成 Go 代码（写入 contract/gen/go，产物进版本库）
gen: deps
	PATH="$(GOBIN):$$PATH" $(BUF) generate --template buf.gen.yaml

## 校验生成代码与源文件一致（ADR-002 的 CI 门禁）：
## 临时生成到 .gen-check 后与仓库内产物比对，不一致即失败，防止手改生成文件。
## 后续批次纳入：由 proto 生成的 OpenAPI 与 TS/Python 生成产物（Q2/Q18）。
gen-check: deps
	rm -rf .gen-check
	PATH="$(GOBIN):$$PATH" $(BUF) generate --template buf.gen.check.yaml
	diff -r contract/gen/go .gen-check
	rm -rf .gen-check
	@echo "gen-check: OK"

## 编译全部 Go 模块（go workspace；清理 main 包落盘的二进制产物）
build:
	@for m in $(GO_MODULES); do \
		(cd $$m && $(GO) build ./... && rm -f $$(basename $$PWD)) || exit 1; \
	done

## 运行全部单元测试（仅本地模拟，不接入真实资产）
## 运行全部单元测试（仅本地模拟，不接入真实资产）。
## 第十一轮 H2：测试一律连接独立数据库 agent_ops_test（55432），
## 库名校验见 internal/testdb；可用 AGENT_OPS_TEST_DATABASE_URL 覆盖。
test:
	@for m in $(GO_MODULES); do (cd $$m && $(GO) test ./...) || exit 1; done

## 与 test 相同，但输出 -v 且禁用缓存（第二十轮 C1：CI 的 test job 使用本目标，
## 保证 CI 输出可归档、不受本地测试缓存影响）。
test-verbose:
	@for m in $(GO_MODULES); do \
		echo "===== MODULE: $$m ====="; \
		(cd $$m && $(GO) test ./... -v -count=1) || exit 1; \
	done

## 格式化（排除生成目录 contract/gen）
fmt:
	@for m in $(GO_MODULES); do \
		(cd $$m && gofmt -w $$(find . -path './gen' -prune -o -name '*.go' -print)) || exit 1; \
	done

## 残留检查门禁（第十九轮 F1）：强制开启全局残留检查。
## 任一残留（kind 集群 / agent-ops.test=true 容器 / test_run_* schema）即非零退出码；
## 用例被 SKIP（门禁未真正执行）同样视为失败——"SKIP 不计入通过"。
## 必须在整套测试**之后**单独运行（并行包会让全局检查误报）。
residual-check:
	@out=$$(AGENT_OPS_RESIDUAL_CHECK=1 $(GO) test ./internal/k8stest/ \
		-run TestNoLeftoversAfterSuite -v -count=1 2>&1); rc=$$?; echo "$$out"; \
	if [ $$rc -ne 0 ]; then echo "residual-check: FAILED (leftovers found, go test exit=$$rc)"; exit $$rc; fi; \
	if echo "$$out" | grep -q -- "--- SKIP"; then \
		echo "residual-check: FAILED (gate test was SKIPPED - equals no check)"; exit 1; fi; \
	echo "residual-check: OK (no leftovers)"

## CI 门禁（第十九轮 F1）：生成一致性 → 编译 → 全部测试 → **残留检查（独立必选步骤）**。
## 串行执行（不用 -j 展开前置），任一步失败即整体失败，残留检查不允许跳过。
ci: gen-check build
	@$(MAKE) test
	@$(MAKE) residual-check
	@echo "ci: OK"