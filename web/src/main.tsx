import React from "react";
import ReactDOM from "react-dom/client";
import { Button } from "antd";

// 前端骨架占位：组件库 Ant Design（已确认）。
// 工程默认值（默认值，待运维确认，Q18）：openapi-typescript 生成类型在下一批次接入；
// 页面与 /api/v1 对接随后续批次实现。
function App() {
  return (
    <div style={{ padding: 24 }}>
      <h1>Agent Ops</h1>
      <Button type="primary">占位</Button>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);