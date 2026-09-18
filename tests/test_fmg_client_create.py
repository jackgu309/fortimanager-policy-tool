import sys, os
from unittest.mock import patch
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import fmg_client as c


def test_build_create_address_url_and_data():
    b = c.build_create_address("FortiProxy", {"name": "x", "type": "fqdn"}, "SESS")
    assert b["method"] == "add"
    assert b["params"][0]["url"].endswith("/obj/firewall/address")
    assert b["params"][0]["data"] == {"name": "x", "type": "fqdn"}


def test_build_create_policy_url_and_data():
    b = c.build_create_policy("FortiProxy", "pkg1", {"policyid": 5}, "SESS")
    assert b["method"] == "add"
    assert b["params"][0]["url"].endswith("/pkg/pkg1/firewall/policy")
    assert b["params"][0]["data"] == {"policyid": 5}


def test_get_address_returns_none_when_missing():
    cl = c.FMGClient("https://fmg.example.com", verify_ssl=False)
    cl.session = "S"
    resp = {"result": [{"status": {"code": -3, "message": "not found"}}]}
    with patch.object(c.FMGClient, "_post", return_value=resp):
        assert cl.get_address("FortiProxy", "nope") is None


def test_next_policy_id_computes_max_plus_one():
    cl = c.FMGClient("https://fmg.example.com", verify_ssl=False)
    cl.session = "S"
    with patch.object(
        c.FMGClient, "list_policies",
        return_value=[{"policyid": 3}, {"policyid": 7}, {"policyid": 1}],
    ):
        assert cl.next_policy_id("FortiProxy", "pkg1") == 8


def test_next_policy_id_empty_returns_one():
    cl = c.FMGClient("https://fmg.example.com", verify_ssl=False)
    cl.session = "S"
    with patch.object(c.FMGClient, "list_policies", return_value=[]):
        assert cl.next_policy_id("FortiProxy", "pkg1") == 1
