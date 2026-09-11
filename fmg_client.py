"""FortiManager JSON-RPC client.

Wraps FMG login / list-packages / list-policies / move / install / task-poll
APIs. Request bodies are built by pure functions (easy to unit test); FMGClient
handles HTTP and the session.
"""
import requests
import time


class FMGError(Exception):
    """Raised when the FMG API returns a non-zero status code."""

    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f"FMG API error {code}: {message}")


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


def build_list_addrgrp(adom, session):
    return _build("get", f"/pm/config/adom/{adom}/obj/firewall/addrgrp", session=session)


def build_list_service_group(adom, session):
    return _build("get", f"/pm/config/adom/{adom}/obj/firewall/service/group", session=session)


def build_list_schedule_group(adom, session):
    return _build("get", f"/pm/config/adom/{adom}/obj/firewall/schedule/group", session=session)


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


def _normalize_table(data):
    """FMG 'get' returns either a list, or a paged dict with a 'results' key."""
    if isinstance(data, dict):
        if "results" in data:
            return data["results"]
        return []
    return data or []


def _member_names(member):
    """addrgrp / service-group member may be a str or a {'name': ...} dict."""
    names = []
    for m in member or []:
        if isinstance(m, dict):
            n = m.get("name") or m.get("q_origin_key")
            if n:
                names.append(n)
        elif isinstance(m, str):
            names.append(m)
    return names


def build_group_map(groups):
    groups = _normalize_table(groups)
    return {g.get("name"): _member_names(g.get("member")) for g in groups or []}


def resolve_names(names, group_map, _seen=None):
    """Expand a group name into 'group member1 member2 ...'; recursive, cycle-safe."""
    if _seen is None:
        _seen = set()
    out = []
    for n in names or []:
        out.append(n)
        if n in group_map and n not in _seen:
            _seen.add(n)
            out.extend(resolve_names(group_map[n], group_map, _seen))
    return out


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

    def _list_paged(self, build_fn, adom):
        """Page through an object-table 'get' endpoint and return a flat list.

        FMG may return a paged dict ({"results": [...], "total": N}); we loop with
        the 'paging' option and de-duplicate by name so we never loop forever or
        emit duplicate rows if the server ignores paging.
        """
        out = []
        seen = set()
        page = 500
        start = 0
        while True:
            req = build_fn(adom, self.session)
            req["params"][0]["option"] = {"paging": {"start": start, "count": page}}
            data = extract_rows(self._post(req))
            rows = _normalize_table(data)
            if not rows:
                break
            added = 0
            for r in rows:
                name = r.get("name") if isinstance(r, dict) else None
                if name is not None:
                    if name in seen:
                        continue
                    seen.add(name)
                out.append(r)
                added += 1
            if added == 0:
                break
            if isinstance(data, dict) and data.get("total") is not None:
                if start + len(rows) >= data["total"]:
                    break
            if len(rows) < page:
                break
            start += page
        return out

    def list_addrgrps(self, adom):
        return self._list_paged(build_list_addrgrp, adom)

    def list_service_groups(self, adom):
        return self._list_paged(build_list_service_group, adom)

    def list_schedule_groups(self, adom):
        return self._list_paged(build_list_schedule_group, adom)

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
