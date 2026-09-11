# FortiManager Policy Management Tool - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Streamlit graphical tool that, via the FortiManager JSON-RPC API,
completes the full flow "log in to FMG -> query all firewall policies of a given
Policy Package under an ADOM -> move a policy to a target position (before/after)
-> one-click install the package to FortiProxy", entirely from the GUI.

**Architecture:** `fmg_client.py` wraps all FMG JSON-RPC calls (request bodies are
built by pure functions for easy unit testing; the `FMGClient` class wraps the
requests session); `app.py` only does the Streamlit UI and `st.session_state`
state management, calling `fmg_client`. Logic and UI are decoupled.

**Tech Stack:** Python 3.11+, `streamlit` (GUI), `requests` (HTTP JSON-RPC),
`pytest` (tests).

**Spec:** `D:\haiguang\fortimanager_policy_tool\docs\specs\2026-08-19-fortimanager-policy-tool-design.md`

## Global Constraints

- Depend only on the two third-party packages `streamlit` + `requests` (see spec §3).
- Python 3.11+ (see spec §3).
- Credentials live only in `st.session_state` - **never written to disk or logs**
  (see spec §7).
- Every response is checked uniformly: `result[0].status.code == 0`; non-zero raises
  `FMGError` and the UI shows it in red (see spec §7).
- SSL verification is off by default (FMG often uses self-signed certs); when off the
  UI warns about the risk (see spec §6).
- Policy list fields follow the actual response; the table shows them dynamically
  (see spec §10.3).
- Install is an async task; after triggering, poll `/task/task/{id}` until
  `state == "done"` / `"error"` / `"failed"` (see spec §5.5, §10.1).

---

## Verified API Contract (implement against this; corrects the `dev` field in the spec)

All requests `POST {host}/jsonrpc`, body shape:
`{id, method, params:[{url, ...}], session, verbose:1}`.
`session` comes from the top-level `"session"` field of the login response (see
Fortinet official docs / community tip).

- **Login**: `method:"exec"`, `url:"/sys/login/user"`, `data:[{user, passwd}]`,
  `session:null` -> response top-level `"session":"<token>"`,
  `result[0].status.code==0`.
- **List packages**: `method:"get"`, `url:"/pm/pkg/adom/{adom}"` ->
  `result[0].data` is the package list (with `name`).
- **List policies**: `method:"get"`,
  `url:"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy"` ->
  `result[0].data` is the policy list.
- **Move**: `method:"move"`,
  `url:"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policyid}"`, plus
  `target:<int>`, `option:"before"|"after"`.
- **Install**: `method:"exec"`, `url:"/securityconsole/install/package"`,
  `data:{adom, pkg, flags:["none"], scope?:[{name, vdom}]}`
  - **Correction**: the spec §5.5 `dev:["{device}"]` is replaced by
    `scope:[{name:"{device}", vdom:"root"}]` (verified against Fortinet official
    docs). When the device is blank, **do not send `scope`** - install to all
    devices bound to the package.
  - Response `result[0].data.task` returns the task id.
- **Poll task**: `method:"get"`, `url:"/task/task/{task_id}"` ->
  `result[0].data.state` (done/error/failed), `percent`, `line[]`.
- **Logout**: `method:"exec"`, `url:"/sys/logout"`.

---

## Task 1: Project Scaffold & Dependencies

**Files:**
- Create: `D:\haiguang\fortimanager_policy_tool\requirements.txt`
- Create: `D:\haiguang\fortimanager_policy_tool\fmg_client.py` (skeleton only)
- Create: `D:\haiguang\fortimanager_policy_tool\tests\test_fmg_client.py` (smoke only)
- Create: `D:\haiguang\fortimanager_policy_tool\tests\__init__.py` (empty, for pytest collection)

**Interfaces:** no prerequisites. Output: the `FMGError` exception class, used by later tasks.

- [ ] **Step 1: write `requirements.txt`**

```
streamlit>=1.30
requests>=2.28
pytest>=7.0
```

- [ ] **Step 2: write `fmg_client.py` skeleton (with `FMGError`)**

```python
"""FortiManager JSON-RPC client.

Wraps FMG login / list-packages / list-policies / move / install / task-poll APIs.
Request bodies are built by pure functions (easy to unit test); FMGClient handles
HTTP and the session.
"""
import requests


class FMGError(Exception):
    """Raised when the FMG API returns a non-zero status code."""

    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f"FMG API error {code}: {message}")
```

- [ ] **Step 3: write smoke test `tests/test_fmg_client.py`**

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

- [ ] **Step 4: install dependencies and run tests**

```bash
cd D:\haiguang\fortimanager_policy_tool
python -m pip install -r requirements.txt
python -m pytest tests/test_fmg_client.py -v
```

Expected: 1 passed.

- [ ] **Step 5: commit (optional)**

> Workspace is not a git repo yet; skip commit. Run `git init` first if version
> control is wanted (requires user confirmation).

---

## Task 2: Request Builders + Response Parsing (pure functions)

**Files:**
- Modify: `D:\haiguang\fortimanager_policy_tool\fmg_client.py` (append builders and parsing functions)
- Modify: `D:\haiguang\fortimanager_policy_tool\tests\test_fmg_client.py` (append tests)

**Interfaces:**
- Consumes: `FMGError` (Task 1).
- Produces: `build_login`, `build_logout`, `build_list_packages`, `build_list_policies`,
  `build_move_policy`, `build_install`, `build_task_status`, `parse_session`,
  `extract_rows`, `extract_task_id`, `extract_task`, `ensure_ok` (called by the
  `FMGClient` methods in Tasks 3/4).

- [ ] **Step 1: write failing tests (append to test_fmg_client.py)**

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

- [ ] **Step 2: run tests, confirm failure**

```bash
python -m pytest tests/test_fmg_client.py -v
```

Expected: FAIL (`build_login` etc. not defined).

- [ ] **Step 3: implement (append to fmg_client.py)**

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

- [ ] **Step 4: run tests, confirm pass**

```bash
python -m pytest tests/test_fmg_client.py -v
```

Expected: all PASS.

- [ ] **Step 5: commit (optional)** - workspace is not a git repo yet; skip.

---

## Task 3: FMGClient Base Methods (login/logout/list_packages/list_policies)

**Files:**
- Modify: `D:\haiguang\fortimanager_policy_tool\fmg_client.py` (append the `FMGClient` class)
- Create: `D:\haiguang\fortimanager_policy_tool\tests\test_fmg_client_basic.py`

**Interfaces:**
- Consumes: all builders and parsers from Task 2.
- Produces: an `FMGClient` instance (`.session`, `.login`, `.logout`, `.list_packages`,
  `.list_policies`), extended by Task 4 and used by app.py.

- [ ] **Step 1: write failing test `tests/test_fmg_client_basic.py`**

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

- [ ] **Step 2: run tests, confirm failure**

```bash
python -m pytest tests/test_fmg_client_basic.py -v
```

Expected: FAIL (`FMGClient` not defined).

- [ ] **Step 3: implement (append to fmg_client.py, after the parsers)**

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

- [ ] **Step 4: run tests, confirm pass**

```bash
python -m pytest tests/test_fmg_client_basic.py -v
```

Expected: all PASS.

- [ ] **Step 5: commit (optional)** - workspace is not a git repo yet; skip.

---

## Task 4: FMGClient Advanced Methods (move / install / task_status / wait_for_task)

**Files:**
- Modify: `D:\haiguang\fortimanager_policy_tool\fmg_client.py` (append methods inside `FMGClient`)
- Create: `D:\haiguang\fortimanager_policy_tool\tests\test_fmg_client_adv.py`

**Interfaces:**
- Consumes: builders from Task 2/3, `extract_task_id`, `extract_task`, `ensure_ok`.
- Produces: `move_policy`, `install_package`, `task_status`, `wait_for_task` - called
  directly by app.py.

- [ ] **Step 1: write failing test `tests/test_fmg_client_adv.py`**

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

- [ ] **Step 2: run tests, confirm failure**

```bash
python -m pytest tests/test_fmg_client_adv.py -v
```

Expected: FAIL (methods not defined).

- [ ] **Step 3: implement (append inside the `FMGClient` class)**

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

> Note: `import time` is required at the top of the file (if not already imported).

- [ ] **Step 4: run tests, confirm pass**

```bash
python -m pytest tests/ -v
```

Expected: all PASS (including Task 2/3 tests).

- [ ] **Step 5: commit (optional)** - workspace is not a git repo yet; skip.

---

## Task 5: Streamlit GUI (app.py)

**Files:**
- Create: `D:\haiguang\fortimanager_policy_tool\app.py`
- Create: `D:\haiguang\fortimanager_policy_tool\tests\test_app_smoke.py` (syntax/import check)

**Interfaces:**
- Consumes: `FMGClient` (all methods from Tasks 3/4).
- Produces: a runnable GUI: `streamlit run app.py`.

- [ ] **Step 1: write `tests/test_app_smoke.py` (verify no syntax errors, no browser launched)**

```python
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_app_imports():
    # Only verify the module can be compiled/imported (streamlit initializes on
    # import but does not render anything).
    import py_compile
    path = os.path.join(os.path.dirname(__file__), "..", "app.py")
    py_compile.compile(path, doraise=True)
```

- [ ] **Step 2: run smoke test, confirm failure**

```bash
python -m pytest tests/test_app_smoke.py -v
```

Expected: FAIL (app.py does not exist).

- [ ] **Step 3: implement `app.py`**

```python
import time
import streamlit as st
import fmg_client as c

st.set_page_config(page_title="FortiManager Policy Manager", layout="wide")


def show_error(e):
    st.error(str(e))


with st.sidebar:
    st.title("FMG Connection")
    host = st.text_input("FMG address", value="https://", key="host")
    user = st.text_input("Username", key="user")
    passwd = st.text_input("Password", type="password", key="passwd")
    verify_ssl = st.checkbox("Verify SSL certificate", value=False)
    if not verify_ssl:
        st.warning("SSL not verified: use only on trusted internal networks.")
    if st.button("Login"):
        try:
            cl = c.FMGClient(host, verify_ssl=verify_ssl)
            cl.login(user, passwd)
            st.session_state.client = cl
            st.success("Login successful")
        except Exception as e:
            show_error(e)
    if st.button("Logout"):
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
    st.info("Fill in the FMG address, username and password on the left, then click Login.")
    st.stop()

st.header("Policy Packages & Policies")
adom = st.text_input("ADOM", value="FortiProxy")

if st.button("Load Policy Packages"):
    try:
        st.session_state.packages = [
            p.get("name") for p in client.list_packages(adom) if p.get("name")
        ]
    except Exception as e:
        show_error(e)

pkg = st.selectbox("Select Policy Package", st.session_state.get("packages", []))
if st.button("Load Policies") and pkg:
    try:
        st.session_state.policies = client.list_policies(adom, pkg)
    except Exception as e:
        show_error(e)

policies = st.session_state.get("policies", [])
if policies:
    st.subheader("Policy List")
    st.dataframe(policies)

    st.subheader("Move Policy")
    ids = [str(p.get("policyid")) for p in policies]
    src = st.selectbox("Source Policy", ids, key="src")
    tgt = st.selectbox("Target Policy", ids, key="tgt")
    opt = st.radio("Position", ["after", "before"])
    if st.button("Move"):
        try:
            client.move_policy(adom, pkg, int(src), int(tgt), opt)
            st.success(f"Moved {src} to {opt} of {tgt}")
            st.session_state.policies = client.list_policies(adom, pkg)
        except Exception as e:
            show_error(e)

    st.subheader("Install to FortiProxy")
    dev = st.text_input("Device name (blank = all bound devices)", key="dev")
    if st.button("Install to FortiProxy"):
        try:
            tid = client.install_package(adom, pkg, device=dev or None)
            with st.spinner(f"Install task {tid} in progress..."):
                task = client.wait_for_task(tid)
            if task.get("state") == "done":
                st.success(f"Install complete (task {tid})")
            else:
                st.error(f"Install state: {task.get('state')}")
            st.json(task)
        except Exception as e:
            show_error(e)
```

- [ ] **Step 4: run smoke test, confirm pass**

```bash
python -m pytest tests/test_app_smoke.py -v
```

Expected: PASS (app.py compiles).

- [ ] **Step 5: full test suite**

```bash
python -m pytest tests/ -v
```

Expected: all PASS.

- [ ] **Step 6: manual launch check (without a real FMG, just confirm the service starts)**

```bash
cd D:\haiguang\fortimanager_policy_tool
streamlit run app.py --server.headless true
```

Expected: terminal prints a local URL (e.g. `http://localhost:8501`) with no import/traceback errors.
(Real functionality needs a FMG connection and manual click-through; this step only
verifies the GUI starts.)

- [ ] **Step 7: commit (optional)** - workspace is not a git repo yet; skip.

---

## Self-Review

**1. Spec coverage:**
- Log in to FMG (address + username/password) -> Task 3 `login` + app sidebar ✅
- Query all policies of a Policy Package under an ADOM -> Task 3 `list_packages`/
  `list_policies` + app main area ✅
- Move a policy to a position (before/after) -> Task 4 `move_policy` + app move area ✅
- One-click install to FortiProxy (enhancement) -> Task 4 `install_package`/
  `wait_for_task` + app install area ✅
- Logout -> Task 3 `logout` + app ✅
- SSL off by default with warning -> app sidebar `verify_ssl` defaults to False + warning ✅
- Credentials not persisted -> only `st.session_state` ✅

**2. Placeholder scan:** no TBD/TODO/"similar to Task N". Every step contains real code
or an exact command. The spec's `dev` field is explicitly corrected to `scope` in the
"Verified API Contract" section, not left as a placeholder.

**3. Type consistency:** `build_*` / `extract_*` / `ensure_ok` are defined in Task 2 and
called with the same signatures by the `FMGClient` methods in Tasks 3/4; `policyid`/
`target` are int in both builders and tests; the `scope` structure matches between the
builder test and the client test. No naming drift.

**Conclusion:** the plan is complete, executable task-by-task, and contains no placeholders.
