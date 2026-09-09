# FortiManager Policy 管理工具 — 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建一个 Streamlit 图形工具，通过 FortiManager JSON-RPC API 完成「登录 FMG → 查询指定 ADOM 下某个 Policy Package 的全部 firewall policy → 将 policy 移动到指定位置（before/after）→ 一键安装该 package 到 FortiProxy」全流程，且全部操作在 GUI 完成。

**Architecture:** `fmg_client.py` 封装所有 FMG JSON-RPC 调用（请求体由纯函数构造，便于单测；`FMGClient` 类封装 requests 会话）；`app.py` 仅做 Streamlit 界面与 `st.session_state` 状态管理，调用 `fmg_client`。逻辑与 UI 解耦。

**Tech Stack:** Python 3.11+，`streamlit`（GUI），`requests`（HTTP JSON-RPC），`pytest`（测试）。

**Spec:** `D:\haiguang\fortimanager_policy_tool\docs\specs\2026-08-19-fortimanager-policy-tool-design.md`

## Global Constraints

- 仅依赖 `streamlit` + `requests` 两个第三方包（见 spec §3）。
- Python 3.11+（见 spec §3）。
- 凭据仅存于 `st.session_state`，**不落盘、不写日志**（见 spec §7）。
- 所有响应统一检查 `result[0].status.code == 0`，非 0 抛 `FMGError` 并在 UI 红色提示（见 spec §7）。
- SSL 校验默认关闭（FMG 多为自签证书），关闭时 UI 提示风险（见 spec §6）。
- policy 列表字段以实际返回为准，表格动态展示（见 spec §10.3）。
- 安装为异步任务，触发后轮询 `/task/task/{id}` 状态直到 `state == "done"`/`"error"`/`"failed"`（见 spec §5.5、§10.1）。

---

## 已核实的 API 契约（实现时以此为准，修正 spec 中 `dev` 字段）

所有请求 `POST {host}/jsonrpc`，body 结构：`{id, method, params:[{url, ...}], session, verbose:1}`。
`session` 来自登录响应顶层 `"session"` 字段（见 Fortinet 官方 doc / community tip）。

- **登录**：`method:"exec"`, `url:"/sys/login/user"`, `data:[{user, passwd}]`, `session:null`
  → 响应顶层 `"session":"<token>"`, `result[0].status.code==0`。
- **列包**：`method:"get"`, `url:"/pm/pkg/adom/{adom}"` → `result[0].data` 为包列表（含 `name`）。
- **查 policy**：`method:"get"`, `url:"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy"` → `result[0].data` 为 policy 列表。
- **移动**：`method:"move"`, `url:"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}"`, 附加 `target:<int>`, `option:"before"|"after"`。
- **安装**：`method:"exec"`, `url:"/securityconsole/install/package"`, `data:{adom, pkg, flags:["none"], scope?:[{name, vdom}]}`
  - **修正**：spec §5.5 的 `dev:["{device}"]` 改为 `scope:[{name:"{device}", vdom:"root"}]`（已据 Fortinet 官方文档核实）。设备留空时**不传 scope**，安装到包绑定的全部设备。
  - 响应 `result[0].data.task` 返回 task id。
- **轮询任务**：`method:"get"`, `url:"/task/task/{task_id}"` → `result[0].data.state`（done/error/failed）、`percent`、`line[]`。
- **登出**：`method:"exec"`, `url:"/sys/logout"`。

---

## Task 1: 项目脚手架与依赖

**Files:**
- Create: `D:\haiguang\fortimanager_policy_tool\requirements.txt`
- Create: `D:\haiguang\fortimanager_policy_tool\fmg_client.py`（仅骨架）
- Create: `D:\haiguang\fortimanager_policy_tool\tests\test_fmg_client.py`（仅冒烟）
- Create: `D:\haiguang\fortimanager_policy_tool\tests\__init__.py`（空文件，便于 pytest 收集）

**Interfaces:** 无前置依赖。产出：`FMGError` 异常类，供后续任务使用。

- [ ] **Step 1: 写 `requirements.txt`**

```
streamlit>=1.30
requests>=2.28
pytest>=7.0
```

- [ ] **Step 2: 写 `fmg_client.py` 骨架（含 `FMGError`）**

```python
"""FortiManager JSON-RPC client.

封装 FMG 的登录 / 列包 / 查 policy / 移动 / 安装 / 轮询任务等 API。
请求体由纯函数构造，便于单元测试；FMGClient 负责 HTTP 与会话。
"""
import requests


class FMGError(Exception):
    """FMG API 返回非 0 状态码时抛出。"""

    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f"FMG API error {code}: {message}")
```

- [ ] **Step 3: 写冒烟测试 `tests/test_fmg_client.py`**

```python
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import fmg_client as c


def test_fmg_error_is_exception():
    e = c.FMGError(-1, "boom")
    assert isinstance(e, Exception)
    assert e.code == -1
    assert "boom" in str(e)
```

- [ ] **Step 4: 安装依赖并跑测试**

```bash
cd D:\haiguang\fortimanager_policy_tool
python -m pip install -r requirements.txt
python -m pytest tests/test_fmg_client.py -v
```

Expected: 1 passed.

- [ ] **Step 5: 提交（可选）**

> 工作区非 git 仓库，跳过 commit。如需版本管理先 `git init`（需用户确认）。

---

## Task 2: 请求体构造 + 响应解析（纯函数）

**Files:**
- Modify: `D:\haiguang\fortimanager_policy_tool\fmg_client.py`（追加 builder 与解析函数）
- Modify: `D:\haiguang\fortimanager_policy_tool\tests\test_fmg_client.py`（追加测试）

**Interfaces:**
- Consumes: `FMGError`（Task 1）。
- Produces: `build_login`, `build_logout`, `build_list_packages`, `build_list_policies`, `build_move_policy`, `build_install`, `build_task_status`, `parse_session`, `extract_rows`, `extract_task_id`, `extract_task`, `ensure_ok`（Task 3/4 的 `FMGClient` 调用这些）。

- [ ] **Step 1: 写失败测试（追加到 test_fmg_client.py）**

```python
def test_build_login_shape():
    b = c.build_login("admin", "pw")
    assert b["method"] == "exec"
    assert b["params"][0]["url"] == "/sys/login/user"
    assert b["params"][0]["data"] == [{"user": "admin", "passwd": "pw"}]
    assert b["session"] is None
    assert b["verbose"] == 1


def test_build_list_packages_url():
    b = c.build_list_packages("FortiProxy", "SESS")
    assert b["method"] == "get"
    assert b["params"][0]["url"] == "/pm/pkg/adom/FortiProxy"


def test_build_list_policies_url():
    b = c.build_list_policies("FortiProxy", "pkgX", "SESS")
    assert b["params"][0]["url"] == "/pm/config/adom/FortiProxy/pkg/pkgX/firewall/policy"


def test_build_move_policy():
    b = c.build_move_policy("FortiProxy", "pkgX", 5, 3, "after", "SESS")
    p = b["params"][0]
    assert b["method"] == "move"
    assert p["url"] == "/pm/config/adom/FortiProxy/pkg/pkgX/firewall/policy/5"
    assert p["target"] == 3
    assert p["option"] == "after"


def test_build_install_no_device():
    b = c.build_install("FortiProxy", "pkgX", "SESS")
    assert b["params"][0]["data"] == {"adom": "FortiProxy", "pkg": "pkgX", "flags": ["none"]}


def test_build_install_with_device():
    b = c.build_install("FortiProxy", "pkgX", "SESS", device="FP1", vdom="root")
    assert b["params"][0]["data"]["scope"] == [{"name": "FP1", "vdom": "root"}]


def test_parse_session_ok():
    resp = {"result": [{"status": {"code": 0, "message": "OK"}}], "session": "TOK"}
    assert c.parse_session(resp) == "TOK"


def test_parse_session_error_raises():
    resp = {"result": [{"status": {"code": -11, "message": "bad"}}], "session": None}
    try:
        c.parse_session(resp)
        assert False, "should raise"
    except c.FMGError as e:
        assert e.code == -11


def test_extract_rows():
    resp = {"result": [{"status": {"code": 0, "message": "OK"}, "data": [{"policyid": 1}]}]}
    assert c.extract_rows(resp) == [{"policyid": 1}]


def test_extract_task_id():
    resp = {"result": [{"status": {"code": 0, "message": "OK"}, "data": {"task": 2071}}]}
    assert c.extract_task_id(resp) == 2071


def test_extract_task():
    resp = {"result": [{"status": {"code": 0, "message": "OK"}, "data": {"state": "done"}}]}
    assert c.extract_task(resp) == {"state": "done"}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
python -m pytest tests/test_fmg_client.py -v
```

Expected: FAIL（`build_login` 等未定义）。

- [ ] **Step 3: 实现（追加到 fmg_client.py）**

```python
def _build(method, url, *, data=None, extra=None, session=None):
    params = {"url": url}
    if data is not None:
        params["data"] = data
    if extra:
        params.update(extra)
    return {"method": method, "params": [params], "session": session, "verbose": 1}


def build_login(user, passwd):
    return _build("exec", "/sys/login/user", data=[{"user": user, "passwd": passwd}], session=None)


def build_logout(session):
    return _build("exec", "/sys/logout", session=session)


def build_list_packages(adom, session):
    return _build("get", f"/pm/pkg/adom/{adom}", session=session)


def build_list_policies(adom, pkg, session):
    return _build("get", f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy", session=session)


def build_move_policy(adom, pkg, policyid, target, option, session):
    return _build(
        "move",
        f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}",
        extra={"target": target, "option": option},
        session=session,
    )


def build_install(adom, pkg, session, device=None, vdom="root"):
    data = {"adom": adom, "pkg": pkg, "flags": ["none"]}
    if device:
        data["scope"] = [{"name": device, "vdom": vdom}]
    return _build("exec", "/securityconsole/install/package", data=data, session=session)


def build_task_status(task_id, session):
    return _build("get", f"/task/task/{task_id}", session=session)


def _status_of(response):
    return response["result"][0]["status"]


def ensure_ok(response):
    st = _status_of(response)
    if st.get("code", -1) != 0:
        raise FMGError(st.get("code", -1), st.get("message", "unknown error"))


def parse_session(response):
    ensure_ok(response)
    return response["session"]


def extract_rows(response):
    ensure_ok(response)
    return response["result"][0]["data"]


def extract_task_id(response):
    ensure_ok(response)
    return response["result"][0]["data"]["task"]


def extract_task(response):
    ensure_ok(response)
    return response["result"][0]["data"]
```

- [ ] **Step 4: 运行测试确认通过**

```bash
python -m pytest tests/test_fmg_client.py -v
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交（可选）** — 工作区非 git 仓库，跳过。

---

## Task 3: FMGClient 基础方法（login/logout/list_packages/list_policies）

**Files:**
- Modify: `D:\haiguang\fortimanager_policy_tool\fmg_client.py`（追加 `FMGClient` 类）
- Create: `D:\haiguang\fortimanager_policy_tool\tests\test_fmg_client_basic.py`

**Interfaces:**
- Consumes: Task 2 的全部 builder 与解析函数。
- Produces: `FMGClient` 实例（`.session`、`.login`、`.logout`、`.list_packages`、`.list_policies`），供 Task 4 扩展与 app.py 使用。

- [ ] **Step 1: 写失败测试 `tests/test_fmg_client_basic.py`**

```python
import sys, os
from unittest.mock import patch
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import fmg_client as c


def _client():
    return c.FMGClient("https://fmg.example.com", verify_ssl=False)


def test_login_sets_session():
    cl = _client()
    resp = {"id": 1, "result": [{"status": {"code": 0, "message": "OK"}}], "session": "S1"}
    with patch.object(c.FMGClient, "_post", return_value=resp):
        s = cl.login("u", "p")
    assert s == "S1"
    assert cl.session == "S1"


def test_login_error_raises():
    cl = _client()
    resp = {"id": 1, "result": [{"status": {"code": -1, "message": "auth fail"}}], "session": None}
    with patch.object(c.FMGClient, "_post", return_value=resp):
        try:
            cl.login("u", "p")
            assert False
        except c.FMGError:
            pass


def test_list_packages_url_and_rows():
    cl = _client()
    cl.session = "S"
    resp = {"result": [{"status": {"code": 0, "message": "OK"},
                       "data": [{"name": "pkg1"}, {"name": "pkg2"}]}]}
    with patch.object(c.FMGClient, "_post", return_value=resp) as m:
        pkgs = cl.list_packages("FortiProxy")
    assert pkgs == [{"name": "pkg1"}, {"name": "pkg2"}]
    sent = m.call_args[0][0]
    assert sent["params"][0]["url"] == "/pm/pkg/adom/FortiProxy"


def test_list_policies_rows():
    cl = _client()
    cl.session = "S"
    resp = {"result": [{"status": {"code": 0, "message": "OK"},
                        "data": [{"policyid": 1, "name": "p1"}]}]}
    with patch.object(c.FMGClient, "_post", return_value=resp) as m:
        rows = cl.list_policies("FortiProxy", "pkg1")
    assert rows == [{"policyid": 1, "name": "p1"}]
    sent = m.call_args[0][0]
    assert sent["params"][0]["url"].endswith("/pkg/pkg1/firewall/policy")


def test_logout_clears_session():
    cl = _client()
    cl.session = "S"
    resp = {"result": [{"status": {"code": 0, "message": "OK"}}]}
    with patch.object(c.FMGClient, "_post", return_value=resp):
        cl.logout()
    assert cl.session is None
```

- [ ] **Step 2: 运行测试确认失败**

```bash
python -m pytest tests/test_fmg_client_basic.py -v
```

Expected: FAIL（`FMGClient` 未定义）。

- [ ] **Step 3: 实现（追加到 fmg_client.py，放在解析函数之后）**

```python
class FMGClient:
    def __init__(self, host, verify_ssl=True, timeout=30):
        self.host = host.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = None
        self._rid = 0

    def _post(self, body):
        self._rid += 1
        body = {**body, "id": self._rid}
        resp = requests.post(
            f"{self.host}/jsonrpc", json=body,
            verify=self.verify_ssl, timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def login(self, user, passwd):
        self.session = parse_session(self._post(build_login(user, passwd)))
        return self.session

    def logout(self):
        if self.session:
            ensure_ok(self._post(build_logout(self.session)))
            self.session = None

    def list_packages(self, adom):
        return extract_rows(self._post(build_list_packages(adom, self.session)))

    def list_policies(self, adom, pkg):
        return extract_rows(self._post(build_list_policies(adom, pkg, self.session)))
```

- [ ] **Step 4: 运行测试确认通过**

```bash
python -m pytest tests/test_fmg_client_basic.py -v
```

Expected: 全部 PASS。

- [ ] **Step 5: 提交（可选）** — 工作区非 git 仓库，跳过。

---

## Task 4: FMGClient 高级方法（move / install / task_status / wait_for_task）

**Files:**
- Modify: `D:\haiguang\fortimanager_policy_tool\fmg_client.py`（在 `FMGClient` 内追加方法）
- Create: `D:\haiguang\fortimanager_policy_tool\tests\test_fmg_client_adv.py`

**Interfaces:**
- Consumes: Task 2/3 的 builder、`extract_task_id`、`extract_task`、`ensure_ok`。
- Produces: `move_policy`, `install_package`, `task_status`, `wait_for_task` —— app.py 直接调用。

- [ ] **Step 1: 写失败测试 `tests/test_fmg_client_adv.py`**

```python
import sys, os, time
from unittest.mock import patch
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import fmg_client as c


def _client():
    cl = c.FMGClient("https://fmg.example.com", verify_ssl=False)
    cl.session = "S"
    return cl


def test_move_policy_url_and_params():
    cl = _client()
    resp = {"result": [{"status": {"code": 0, "message": "OK"}}]}
    with patch.object(c.FMGClient, "_post", return_value=resp) as m:
        cl.move_policy("FortiProxy", "pkg1", 5, 3, "after")
    sent = m.call_args[0][0]
    assert sent["method"] == "move"
    p = sent["params"][0]
    assert p["url"].endswith("/firewall/policy/5")
    assert p["target"] == 3
    assert p["option"] == "after"


def test_move_policy_error_raises():
    cl = _client()
    resp = {"result": [{"status": {"code": -3, "message": "no such policy"}}]}
    with patch.object(c.FMGClient, "_post", return_value=resp):
        try:
            cl.move_policy("FortiProxy", "pkg1", 5, 3, "after")
            assert False
        except c.FMGError as e:
            assert e.code == -3


def test_install_returns_task_id():
    cl = _client()
    resp = {"result": [{"status": {"code": 0, "message": "OK"}, "data": {"task": 99}}]}
    with patch.object(c.FMGClient, "_post", return_value=resp) as m:
        tid = cl.install_package("FortiProxy", "pkg1", device="FP1")
    assert tid == 99
    sent = m.call_args[0][0]
    assert sent["params"][0]["data"]["scope"] == [{"name": "FP1", "vdom": "root"}]


def test_install_no_device_no_scope():
    cl = _client()
    resp = {"result": [{"status": {"code": 0, "message": "OK"}, "data": {"task": 7}}]}
    with patch.object(c.FMGClient, "_post", return_value=resp) as m:
        cl.install_package("FortiProxy", "pkg1")
    assert "scope" not in m.call_args[0][0]["params"][0]["data"]


def test_task_status_returns_data():
    cl = _client()
    resp = {"result": [{"status": {"code": 0, "message": "OK"},
                        "data": {"state": "done", "percent": 100}}]}
    with patch.object(c.FMGClient, "_post", return_value=resp) as m:
        t = cl.task_status(99)
    assert t["state"] == "done"
    assert m.call_args[0][0]["params"][0]["url"] == "/task/task/99"


def test_wait_for_task_done():
    cl = _client()
    running = {"result": [{"status": {"code": 0, "message": "OK"},
                          "data": {"state": "running", "percent": 50}}]}
    done = {"result": [{"status": {"code": 0, "message": "OK"},
                        "data": {"state": "done", "percent": 100}}]}
    with patch.object(c.FMGClient, "_post", side_effect=[running, done]):
        with patch("time.sleep"):
            task = cl.wait_for_task(99, interval=1, timeout=10)
    assert task["state"] == "done"


def test_wait_for_task_terminal_on_error():
    cl = _client()
    errored = {"result": [{"status": {"code": 0, "message": "OK"},
                          "data": {"state": "error", "percent": 100}}]}
    with patch.object(c.FMGClient, "_post", return_value=errored):
        with patch("time.sleep"):
            task = cl.wait_for_task(99, interval=1, timeout=10)
    assert task["state"] == "error"
```

- [ ] **Step 2: 运行测试确认失败**

```bash
python -m pytest tests/test_fmg_client_adv.py -v
```

Expected: FAIL（方法未定义）。

- [ ] **Step 3: 实现（追加到 `FMGClient` 类内）**

```python
    def move_policy(self, adom, pkg, policyid, target, option):
        ensure_ok(self._post(
            build_move_policy(adom, pkg, policyid, target, option, self.session)))

    def install_package(self, adom, pkg, device=None, vdom="root"):
        return extract_task_id(
            self._post(build_install(adom, pkg, self.session, device=device, vdom=vdom)))

    def task_status(self, task_id):
        return extract_task(self._post(build_task_status(task_id, self.session)))

    def wait_for_task(self, task_id, interval=3, timeout=300):
        waited = 0
        while waited < timeout:
            task = self.task_status(task_id)
            state = task.get("state")
            if state in ("done", "error", "failed"):
                return task
            time.sleep(interval)
            waited += interval
        return self.task_status(task_id)
```

> 注意：文件顶部需 `import time`（若尚未导入）。

- [ ] **Step 4: 运行测试确认通过**

```bash
python -m pytest tests/ -v
```

Expected: 全部 PASS（含 Task 2/3 测试）。

- [ ] **Step 5: 提交（可选）** — 工作区非 git 仓库，跳过。

---

## Task 5: Streamlit GUI（app.py）

**Files:**
- Create: `D:\haiguang\fortimanager_policy_tool\app.py`
- Create: `D:\haiguang\fortimanager_policy_tool\tests\test_app_smoke.py`（语法/导入验证）

**Interfaces:**
- Consumes: `FMGClient`（Task 3/4 全部方法）。
- Produces: 可运行 GUI：`streamlit run app.py`。

- [ ] **Step 1: 写 `tests/test_app_smoke.py`（仅验证无语法错误，不启动浏览器）**

```python
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_app_imports():
    # 仅验证模块可被编译/导入（streamlit 在 import 时会初始化，但不渲染）
    import py_compile
    path = os.path.join(os.path.dirname(__file__), "..", "app.py")
    py_compile.compile(path, doraise=True)
```

- [ ] **Step 2: 运行冒烟测试确认失败**

```bash
python -m pytest tests/test_app_smoke.py -v
```

Expected: FAIL（app.py 不存在）。

- [ ] **Step 3: 实现 `app.py`**

```python
import time
import streamlit as st
import fmg_client as c

st.set_page_config(page_title="FortiManager Policy Manager", layout="wide")


def show_error(e):
    st.error(str(e))


with st.sidebar:
    st.title("FMG 连接")
    host = st.text_input("FMG 地址", value="https://", key="host")
    user = st.text_input("用户名", key="user")
    passwd = st.text_input("密码", type="password", key="passwd")
    verify_ssl = st.checkbox("校验 SSL 证书", value=False)
    if not verify_ssl:
        st.warning("未校验 SSL：仅限可信内网使用。")
    if st.button("登录"):
        try:
            cl = c.FMGClient(host, verify_ssl=verify_ssl)
            cl.login(user, passwd)
            st.session_state.client = cl
            st.success("登录成功")
        except Exception as e:
            show_error(e)
    if st.button("登出"):
        cl = st.session_state.get("client")
        if cl:
            try:
                cl.logout()
            except Exception:
                pass
        for k in ("client", "packages", "policies"):
            st.session_state.pop(k, None)

client = st.session_state.get("client")
if not client:
    st.info("请在左侧填写 FMG 地址、用户名、密码后点击「登录」。")
    st.stop()

st.header("策略包与 Policy")
adom = st.text_input("ADOM", value="FortiProxy")

if st.button("加载策略包"):
    try:
        st.session_state.packages = [
            p.get("name") for p in client.list_packages(adom) if p.get("name")
        ]
    except Exception as e:
        show_error(e)

pkg = st.selectbox("选择 Policy Package", st.session_state.get("packages", []))
if st.button("加载 Policy") and pkg:
    try:
        st.session_state.policies = client.list_policies(adom, pkg)
    except Exception as e:
        show_error(e)

policies = st.session_state.get("policies", [])
if policies:
    st.subheader("Policy 列表")
    st.dataframe(policies)

    st.subheader("移动 Policy")
    ids = [str(p.get("policyid")) for p in policies]
    src = st.selectbox("源 Policy", ids, key="src")
    tgt = st.selectbox("目标 Policy", ids, key="tgt")
    opt = st.radio("位置", ["after", "before"])
    if st.button("移动"):
        try:
            client.move_policy(adom, pkg, int(src), int(tgt), opt)
            st.success(f"已将 {src} 移动到 {tgt} 的 {opt} 位置")
            st.session_state.policies = client.list_policies(adom, pkg)
        except Exception as e:
            show_error(e)

    st.subheader("安装到 FortiProxy")
    dev = st.text_input("设备名（留空=全部绑定设备）", key="dev")
    if st.button("安装到 FortiProxy"):
        try:
            tid = client.install_package(adom, pkg, device=dev or None)
            with st.spinner(f"安装任务 {tid} 进行中..."):
                task = client.wait_for_task(tid)
            if task.get("state") == "done":
                st.success(f"安装完成（task {tid}）")
            else:
                st.error(f"安装状态：{task.get('state')}")
            st.json(task)
        except Exception as e:
            show_error(e)
```

- [ ] **Step 4: 运行冒烟测试确认通过**

```bash
python -m pytest tests/test_app_smoke.py -v
```

Expected: PASS（app.py 可编译）。

- [ ] **Step 5: 全量测试**

```bash
python -m pytest tests/ -v
```

Expected: 全部 PASS。

- [ ] **Step 6: 手动验证启动（无真实 FMG 时仅确认能起服务）**

```bash
cd D:\haiguang\fortimanager_policy_tool
streamlit run app.py --server.headless true
```

Expected: 终端打印本地 URL（如 `http://localhost:8501`），无 import/traceback 错误。
（真实功能需连 FMG 后手动点测；本步仅验证 GUI 可启动。）

- [ ] **Step 7: 提交（可选）** — 工作区非 git 仓库，跳过。

---

## 自审（Self-Review）

**1. Spec 覆盖：**
- 登录 FMG（指定地址+用户名/密码）→ Task 3 `login` + app 侧边栏 ✅
- 查询指定 ADOM 下某 Policy Package 的全部 policy → Task 3 `list_packages`/`list_policies` + app 主区 ✅
- 移动 policy 到指定位置（before/after）→ Task 4 `move_policy` + app 移动区 ✅
- 一键安装到 FortiProxy（增强项）→ Task 4 `install_package`/`wait_for_task` + app 安装区 ✅
- 登出 → Task 3 `logout` + app ✅
- SSL 默认关闭并提示 → app 侧边栏 `verify_ssl` 默认 False + warning ✅
- 凭据不落盘 → 仅 `st.session_state` ✅

**2. Placeholder 扫描：** 无 TBD/TODO/“类似 Task N”。所有步骤均含实际代码或确切命令。spec 中的 `dev` 字段已在「已核实 API 契约」中明确修正为 `scope`，非 placeholder。

**3. 类型一致性：** `build_*` / `extract_*` / `ensure_ok` 在 Task 2 定义，Task 3/4 的 `FMGClient` 方法以相同签名调用；`policyid`/`target` 在 builder 与测试里均为 int；`scope` 结构在 builder 测试与 client 测试里一致。无命名漂移。

**结论：** 计划完整、可独立逐任务执行、无占位符。
