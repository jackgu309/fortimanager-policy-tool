# FortiManager Policy 管理工具 — 设计文档 (Spec)

- 日期：2026-08-19
- 版本：v1（设计确认稿）
- 依据：Superpowers 技能 v6.3.0（brainstorming → writing-plans 流程）
- 参考文档：https://how-to-fortimanager-api.readthedocs.io/en/latest/

---

## 1. 背景与目标

用户需要一套**图形化**工具，通过 FortiManager (FMG) 的 JSON-RPC API 管理 FortiProxy 的上网策略。具体目标：

1. 登录 FMG（指定 FMG 地址 + 用户名/密码）
2. 查询指定 ADOM 下某个 Policy Package 的**全部 firewall policy**
3. 将某个 policy **移动**到指定位置（相对另一个 policy 之前/之后）
4. （增强，已确认）移动后**一键安装**该 Policy Package 到 FortiProxy 设备

技术栈：Python + Streamlit，上述功能全部在 GUI 完成。

---

## 2. 关键概念澄清

- **FortiManager (FMG)**：中央管理平面，本工具通过它的 `POST /jsonrpc` 接口操作。
- **FortiProxy**：真正管理用户上网的设备。FMG 上的 policy 必须挂在某个 **Policy Package** 下，该 package 绑定到 FortiProxy 设备；只有把 package **安装（推送）**到设备后，policy 变更才在 FortiProxy 上生效。
- 因此"指定 fortiproxy"在工具中体现为：
  - 选择 **ADOM** → 选择该 FortiProxy 对应的 **Policy Package**；
  - 安装时推送到该 package 绑定的 FortiProxy 设备（`dev` 可留空=推全部绑定设备，或显式指定设备名）。

---

## 3. 技术栈与依赖

- Python 3.11+
- `streamlit`（GUI）
- `requests`（HTTP 调用 FMG JSON-RPC）
- `requirements.txt` 仅含上述两项第三方依赖。

---

## 4. 架构与文件结构

```
D:\haiguang\fortimanager_policy_tool\
├── app.py                      # Streamlit 入口与界面
├── fmg_client.py               # FMG JSON-RPC 客户端（纯逻辑，可单测）
├── requirements.txt            # streamlit, requests
├── tests/
│   └── test_fmg_client.py      # 请求体构造 + mock 响应的单元测试
└── docs/specs/
    └── 2026-08-19-fortimanager-policy-tool-design.md
```

**职责划分**
- `fmg_client.py`：封装所有 FMG API（登录、列包、查 policy、移动、安装、登出），与 UI 解耦；所有请求体由纯函数构造，便于测试。
- `app.py`：仅负责 Streamlit 界面与状态管理（`st.session_state` 保存 session、当前 ADOM/包/策略列表），调用 `fmg_client`。

---

## 5. API 契约（已据文档核实）

所有请求：`POST {fmg_host}/jsonrpc`，body 含 `id / method / params / session / verbose:1`。

### 5.1 登录
```json
{
  "id": 1,
  "method": "exec",
  "params": [
    { "url": "sys/login/user",
      "data": [ { "user": "admin", "passwd": "fortinet" } ] }
  ],
  "session": null,
  "verbose": 1
}
```
响应 `result[0].status.code == 0` 成功，返回 `session` 字符串，后续请求复用。

### 5.2 列出 Policy Package
```json
{
  "id": 1, "method": "get",
  "params": [ { "url": "/pm/pkg/adom/{adom}" } ],
  "session": "<session>", "verbose": 1
}
```
响应返回该 ADOM 下包列表（每个含 `name`）。

### 5.3 查询全部 policy
```json
{
  "id": 1, "method": "get",
  "params": [ { "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy" } ],
  "session": "<session>", "verbose": 1
}
```
响应返回该 package 下全部 policy（含 `policyid`、`name`、`srcintf`、`dstintf`、`action`、`status` 等）。

### 5.4 移动 policy
```json
{
  "id": 1, "method": "move",
  "params": [
    {
      "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}",
      "option": "after",
      "target": "<target_policyid>"
    }
  ],
  "session": "<session>", "verbose": 1
}
```
`option` ∈ `before` | `after`；`target` 为目标 policy 的 `policyid`。

### 5.5 安装（推送）到设备
```json
{
  "id": 1, "method": "exec",
  "params": [
    {
      "url": "securityconsole/install/package",
      "data": { "adom": "{adom}", "pkg": "{pkg}", "dev": ["{device}"] }
    }
  ],
  "session": "<session>", "verbose": 1
}
```
`dev` 可省略（安装到包绑定的全部设备）。响应 `result[0].data.task` 返回 task id，需轮询状态确认完成。

### 5.6 登出
```json
{ "id": 1, "method": "exec",
  "params": [ { "url": "sys/logout" } ],
  "session": "<session>", "verbose": 1 }
```

---

## 6. GUI 设计（Streamlit）

**侧边栏（连接）**
- FMG 地址（如 `https://10.0.0.1`）
- 用户名 / 密码
- SSL 校验开关（默认关闭校验，FMG 多为自签证书；关闭时界面提示安全风险）
- 「登录」/「登出」按钮

**主区域（登录后）**
1. ADOM 输入框（默认 `FortiProxy` 或 `root`，由用户填写）
2. 「加载策略包」按钮 → 下拉框列出该 ADOM 下的 Policy Package
3. 选择 package → 「加载 Policy」→ 表格展示（policyid / name / srcintf / dstintf / action / status …）
4. **移动区**：源 policy 下拉 + 目标 policy 下拉 + before/after 单选 → 「移动」按钮
5. **安装区**：可选「设备名（FortiProxy）」输入框（留空=推全部绑定设备）→ 「安装到 FortiProxy」按钮 → 显示 task 结果与状态

状态（session、当前 ADOM、当前 package、policy 列表）保存在 `st.session_state`。

---

## 7. 错误处理

- 所有响应统一检查 `result[0].status.code == 0`；非 0 在界面以红色提示展示错误码与 `message`。
- 网络异常 / SSL 异常 → 友好报错并建议检查地址或 SSL 开关。
- `session` 失效（如 code 非 0 且提示未登录）→ 提示重新登录。
- 凭据仅存于 `session_state`，**不落盘**、不写日志。

---

## 8. 测试策略（无真实 FMG 环境）

- **请求体构造单测**：对 `fmg_client.py` 中构造登录/列包/查 policy/移动/安装请求体的纯函数断言 `method / url / params` 正确（含 before/after、target 拼装）。
- **响应解析与错误分支**：用 `requests` mock 模拟登录成功/失败、列包、查 policy、移动、安装（返回 task id）的响应，验证解析逻辑与 `status.code != 0` 分支。
- 不连接真实设备；如后续有测试 FMG，可补充冒烟测试。

---

## 9. 范围与假设

- **范围内**：登录、列包、查 policy、移动（before/after）、安装到设备、登出，全部 GUI 完成。
- **范围外（YAGNI）**：创建/编辑/删除 policy、top/bottom 移动、多 ADOM 批量、定时任务。
- **假设**：
  - 用户已知目标 ADOM 名与对应的 FortiProxy Policy Package 名。
  - FMG 使用标准 JSON-RPC（文档示例未含 `jsonrpc:"2.0"` 字段，按文档格式实现）。
  - 安装为异步任务，工具触发后立即轮询状态并以结果展示。

---

## 10. 实现时需核对的细节

1. 安装状态轮询的具体 endpoint（`securityconsole/install/package` 返回 task id 后），实现时再据文档确认并补充。
2. 若目标 FMG 版本要求 `jsonrpc:"2.0"` 字段，则在 `fmg_client` 统一加注。
3. policy 列表字段以实际返回为准，表格列可动态展示返回字段。
