# adapters

每个组件一个独立的 Go 包（进程内，由执行网关加载），并附带声明式清单 YAML。
**本目录目前只有占位，不含任何适配器实现。**

- 每个适配器子目录：实现 contract.Adapter 接口（Discover/Health/Diagnose/Execute/PlanRollback），
  并提供 YAML 清单（组件名、支持版本范围、接入方式、能力列表）。
- 适配器发布前必须通过 contract-tests/ 的统一契约测试（只读副作用、能力声明一致、超时安全终止等）。
- 首批范围占位目录：linux / docker / kubernetes / monitoring；
  数据库类适配器待定（docs/OPEN_QUESTIONS.md Q5）。