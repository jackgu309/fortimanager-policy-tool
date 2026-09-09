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
