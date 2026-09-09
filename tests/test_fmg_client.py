import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import fmg_client as c


def test_fmg_error_is_exception():
    e = c.FMGError(-1, "boom")
    assert isinstance(e, Exception)
    assert e.code == -1
    assert "boom" in str(e)


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
