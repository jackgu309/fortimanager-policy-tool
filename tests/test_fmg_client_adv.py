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
