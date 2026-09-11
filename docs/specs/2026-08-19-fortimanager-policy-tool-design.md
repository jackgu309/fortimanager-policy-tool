# FortiManager Policy Management Tool - Design Document (Spec)

- Date: 2026-08-19
- Version: v1 (design baseline)
- Based on: Superpowers skill v6.3.0 (brainstorming -> writing-plans flow)
- Reference: https://how-to-fortimanager-api.readthedocs.io/en/latest/

---

## 1. Background & Goals

The user needs a **graphical** tool to manage FortiProxy internet-access policies
through the FortiManager (FMG) JSON-RPC API. Goals:

1. Log in to FMG (FMG address + username/password)
2. Query **all firewall policies** of a given Policy Package under an ADOM
3. **Move** a policy to a target position (before/after another policy)
4. (Enhancement, confirmed) **one-click install** the Policy Package to FortiProxy
   devices after moving

Tech stack: Python + Streamlit; all functionality delivered in the GUI.

---

## 2. Key Concept Clarification

- **FortiManager (FMG)**: central management plane. This tool drives it via its
  `POST /jsonrpc` interface.
- **FortiProxy**: the device that actually enforces user internet access. FMG
  policies must live under a **Policy Package**, which is bound to FortiProxy
  devices; policy changes only take effect on FortiProxy after the package is
  **installed (pushed)** to the device.
- Therefore "specify fortiproxy" in the tool means:
  - Choose **ADOM** -> choose the **Policy Package** for that FortiProxy;
  - At install time, push to the FortiProxy device(s) bound to the package
    (`dev` may be left empty = push to all bound devices, or a device name given).

---

## 3. Tech Stack & Dependencies

- Python 3.11+
- `streamlit` (GUI)
- `requests` (HTTP calls to FMG JSON-RPC)
- `requirements.txt` contains only the two third-party dependencies above.

---

## 4. Architecture & File Structure

```
D:\haiguang\fortimanager_policy_tool\
├── app.py                      # Streamlit entry point and UI
├── fmg_client.py               # FMG JSON-RPC client (pure logic, unit-testable)
├── requirements.txt            # streamlit, requests
├── tests/
│   └── test_fmg_client.py      # unit tests for request builders + mocked responses
└── docs/specs/
    └── 2026-08-19-fortimanager-policy-tool-design.md
```

**Responsibilities**
- `fmg_client.py`: wraps all FMG APIs (login, list packages, list policies, move,
  install, logout), decoupled from the UI; all request bodies are built by pure
  functions for easy testing.
- `app.py`: only Streamlit UI and state management (`st.session_state` holds the
  session, current ADOM/package/policy list); calls `fmg_client`.

---

## 5. API Contract (verified against docs)

All requests: `POST {fmg_host}/jsonrpc`, body contains `id / method / params /
session / verbose:1`.

### 5.1 Login
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
Response `result[0].status.code == 0` on success, returns a `session` string
reused by subsequent requests.

### 5.2 List Policy Package
```json
{
  "id": 1, "method": "get",
  "params": [ { "url": "/pm/pkg/adom/{adom}" } ],
  "session": "<session>", "verbose": 1
}
```
Response returns the package list under the ADOM (each with a `name`).

### 5.3 Query all policies
```json
{
  "id": 1, "method": "get",
  "params": [ { "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy" } ],
  "session": "<session>", "verbose": 1
}
```
Response returns all policies under the package (with `policyid`, `name`,
`srcintf`, `dstintf`, `action`, `status`, etc.).

### 5.4 Move policy
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
`option` in `before` | `after`; `target` is the target policy's `policyid`.

### 5.5 Install (push) to device
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
`dev` may be omitted (install to all devices bound to the package). The response
`result[0].data.task` returns a task id that must be polled to confirm completion.

### 5.6 Logout
```json
{ "id": 1, "method": "exec",
  "params": [ { "url": "sys/logout" } ],
  "session": "<session>", "verbose": 1 }
```

---

## 6. GUI Design (Streamlit)

**Sidebar (connection)**
- FMG address (e.g. `https://10.0.0.1`)
- Username / Password
- SSL verification toggle (off by default, since FMG often uses self-signed certs;
  a warning is shown when off)
- "Login" / "Logout" buttons

**Main area (after login)**
1. ADOM input (default `FortiProxy` or `root`, filled by the user)
2. "Load Policy Packages" button -> dropdown lists the Policy Packages under the ADOM
3. Select package -> "Load Policies" -> table (policyid / name / srcintf /
   dstintf / action / status ...)
4. **Move area**: source policy dropdown + target policy dropdown + before/after
   radio -> "Move" button
5. **Install area**: optional "Device name (FortiProxy)" input (blank = all bound
   devices) -> "Install to FortiProxy" button -> shows task result and status

State (session, current ADOM, current package, policy list) is kept in
`st.session_state`.

---

## 7. Error Handling

- Every response is checked uniformly: `result[0].status.code == 0`; non-zero
  raises `FMGError` and the UI shows the error code and `message` in red.
- Network / SSL exceptions -> friendly error suggesting to check the address or
  the SSL toggle.
- Stale `session` (non-zero code with a not-logged-in message) -> prompt to log in
  again.
- Credentials live only in `session_state` - **never written to disk or logs**.

---

## 8. Test Strategy (no real FMG available)

- **Request builder unit tests**: assert `method / url / params` for the pure
  functions building login / list-packages / list-policies / move / install bodies
  (including before/after and target assembly).
- **Response parsing & error branches**: mock `requests` to simulate login
  success/failure, list-packages, list-policies, move, and install (returning a
  task id), verifying parsing logic and the `status.code != 0` branch.
- No real device is contacted; a smoke test can be added later if a test FMG exists.

---

## 9. Scope & Assumptions

- **In scope**: login, list packages, list policies, move (before/after), install
  to device, logout - all in the GUI.
- **Out of scope (YAGNI)**: create/edit/delete policy, top/bottom move, multi-ADOM
  batch, scheduled tasks.
- **Assumptions**:
  - The user knows the target ADOM name and its FortiProxy Policy Package name.
  - FMG uses the standard JSON-RPC format (the doc examples omit `jsonrpc:"2.0"`;
    implement per the documented format).
  - Install is an async task; the tool polls status immediately after triggering
    and shows the result.

---

## 10. Details to Verify at Implementation Time

1. The exact endpoint for install-status polling (after
   `securityconsole/install/package` returns a task id) - confirm against docs.
2. If the target FMG version requires a `jsonrpc:"2.0"` field, add it uniformly in
   `fmg_client`.
3. Policy list fields follow the actual response; the table may show returned
   fields dynamically.
