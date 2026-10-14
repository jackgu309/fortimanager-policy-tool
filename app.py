import json
import logging
import os
import time
import streamlit as st
import fmg_client as c


def _setup_logging():
    """Configure the policy_manager / fmg_client loggers to print to the terminal.

    Level is controlled by the LOG_LEVEL env var (DEBUG/INFO/WARNING/...),
    defaulting to INFO. This does not affect Streamlit's own server logs.
    """
    level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    for name in ("policy_manager", "fmg_client"):
        lg = logging.getLogger(name)
        lg.setLevel(level)
        lg.propagate = False
        if not lg.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
            )
            lg.addHandler(handler)


_setup_logging()
log = logging.getLogger("policy_manager")

st.set_page_config(page_title="FortiManager Policy Manager", layout="wide")


def show_error(e):
    st.error(str(e))
    log.exception("operation failed")


# Raw FMG policy field name -> FortiManager GUI column label.
COLUMN_LABELS = {
    "policyid": "ID",
    "name": "Name",
    "srcintf": "Source Interface",
    "dstintf": "Destination Interface",
    "srcaddr": "Source",
    "dstaddr": "Destination",
    "service": "Service",
    "schedule": "Schedule",
    "action": "Action",
    "status": "Status",
    "nat": "NAT",
    "logtraffic": "Log",
    "comments": "Comments",
    "users": "Users",
    "groups": "Groups",
    "application": "Application",
    "url-category": "URL Category",
    "fsso": "FSSO",
    "internet-service-id": "Internet Service",
    "ippool": "IP Pool",
    "poolname": "IP Pool Name",
    "profile-group": "Profile Group",
    "av-profile": "AntiVirus",
    "ips-sensor": "IPS",
    "webfilter-profile": "Web Filter",
    "application-list": "Application List",
}

# Preferred column order, matching the FMG GUI layout (extra columns appended after).
COLUMN_ORDER = [
    "ID", "Name", "Source Interface", "Destination Interface",
    "Source", "Destination", "Service", "Schedule", "Action",
    "Status", "NAT", "Log", "Comments",
]

# Raw enum value -> FMG GUI display label.
VALUE_LABELS = {
    "action": {"accept": "Accept", "deny": "Deny", "ipsec": "IPsec"},
    "status": {"enable": "Enabled", "disable": "Disabled"},
    "nat": {"enable": "Enabled", "disable": "Disabled"},
    "logtraffic": {"enable": "Enabled", "disable": "Disabled", "utm": "UTM", "all": "All"},
}


def expand_groups(policies, adom, client):
    """Make the policy table match the FortiManager GUI.

    - Expand address/service groups into 'group member1 member2 ...'
      (FMG's JSON-RPC get returns only the group name, the GUI expands members).
    - Translate enum values (action/status/nat/logtraffic) to GUI labels.
    - Rename raw field names to GUI column labels (srcaddr -> Source, etc.).
    - Stringify list cells and order columns like the GUI.
    """
    try:
        addr_map = c.build_group_map(client.list_addrgrps(adom))
    except Exception:
        addr_map = {}
    try:
        svc_map = c.build_group_map(client.list_service_groups(adom))
    except Exception:
        svc_map = {}
    out = []
    for p in policies or []:
        row = {}
        for k, v in p.items():
            if k in ("srcaddr", "dstaddr"):
                v = " ".join(c.resolve_names(v or [], addr_map))
            elif k == "service":
                v = " ".join(c.resolve_names(v or [], svc_map))
            if isinstance(v, list):
                v = " ".join(str(x) for x in v)
            if k in VALUE_LABELS and isinstance(v, str):
                v = VALUE_LABELS[k].get(v, v)
            row[COLUMN_LABELS.get(k, k)] = v
        ordered = {}
        for label in COLUMN_ORDER:
            if label in row:
                ordered[label] = row[label]
        for label, val in row.items():
            if label not in ordered:
                ordered[label] = val
        out.append(ordered)
    return out


def load_packages(adom, client):
    """Load policy-package names into session_state.packages."""
    try:
        st.session_state.packages = [
            p.get("name") for p in client.list_packages(adom) if p.get("name")
        ]
        return True
    except Exception as e:
        show_error(e)
        return False


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

tab1, tab2 = st.tabs(["Policy List", "Allow IP → URL"])

with tab1:
    st.header("Policy Packages & Policies")
    adom = st.text_input("ADOM", value="FortiProxy", key="adom1")

    if st.button("Load Policy Packages", key="lp1"):
        load_packages(adom, client)

    pkg = st.selectbox("Select Policy Package", st.session_state.get("packages", []), key="pkg1")
    if st.button("Load Policies", key="lpol1") and pkg:
        try:
            rows = client.list_policies(adom, pkg)
            if isinstance(rows, dict) and "results" in rows:
                rows = rows["results"]
            rows = expand_groups(rows, adom, client)
            st.session_state.policies = rows
        except Exception as e:
            show_error(e)

    policies = st.session_state.get("policies", [])
    if policies:
        st.subheader("Policy List")
        st.dataframe(policies)

        st.subheader("Move Policy")
        ids = [str(p.get("ID")) for p in policies]
        src = st.selectbox("Source Policy", ids, key="src")
        tgt = st.selectbox("Target Policy", ids, key="tgt")
        opt = st.radio("Position", ["after", "before"])
        if st.button("Move", key="move"):
            try:
                locked = client.lock_workspace(adom)
                try:
                    client.move_policy(adom, pkg, int(src), int(tgt), opt)
                    st.success(f"Moved {src} to {opt} of {tgt}")
                    rows = client.list_policies(adom, pkg)
                    if isinstance(rows, dict) and "results" in rows:
                        rows = rows["results"]
                    rows = expand_groups(rows, adom, client)
                    st.session_state.policies = rows
                finally:
                    if locked:
                        try:
                            client.commit_workspace(adom)
                        except Exception:
                            pass
                        try:
                            client.unlock_workspace(adom)
                        except Exception:
                            pass
            except Exception as e:
                show_error(e)

        st.subheader("Install to FortiProxy")
        dev = st.text_input("Device name (blank = all bound devices)", key="dev")
        if st.button("Install to FortiProxy", key="install"):
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

        with st.expander("Debug: export raw FMG policy objects (troubleshooting / payload reference)"):
            st.caption(
                "Policy objects exactly as FortiManager returns them from its JSON-RPC `get` "
                "(no group expansion, no enum translation). Use this to verify the exact shape "
                "a `create policy` payload must use."
            )
            if pkg and st.button("Fetch raw policies", key="rawdump"):
                try:
                    raw = client.list_policies(adom, pkg)
                    rows_raw = raw["results"] if isinstance(raw, dict) and "results" in raw else raw
                    st.session_state.raw_policies = rows_raw or []
                except Exception as e:
                    show_error(e)
            raw_rows = st.session_state.get("raw_policies") or []
            if raw_rows:
                st.caption(f"{len(raw_rows)} raw object(s) returned by FMG.")
                idx = st.number_input(
                    "Object index to display", min_value=0,
                    max_value=max(len(raw_rows) - 1, 0), value=0, step=1, key="rawidx",
                )
                st.json(raw_rows[int(idx)])
                st.download_button(
                    "Download all raw policies (JSON)",
                    data=json.dumps(raw_rows, indent=2, ensure_ascii=False),
                    file_name="fmg_raw_policies.json",
                    mime="application/json",
                    key="rawdl",
                )

with tab2:
    st.header("Allow Source IP → Destination URL")
    st.caption(
        "Creates a destination FQDN address object + a source /32 address object, "
        "then adds an 'accept' policy to the chosen package. Install separately when ready."
    )
    adom2 = st.text_input("ADOM", value="FortiProxy", key="adom2")
    if st.button("Load Policy Packages", key="lp2"):
        load_packages(adom2, client)
    pkg2 = st.selectbox("Select Policy Package", st.session_state.get("packages", []), key="pkg2")

    src_ip = st.text_input("Source IP (e.g. 10.1.1.10)", key="src_ip")
    url = st.text_input("Target URL (e.g. https://api.example.com/path)", key="url")

    col_svc, col_opt = st.columns(2)
    with col_svc:
        st.write("Services")
        http = st.checkbox("HTTP", value=True, key="http")
        https = st.checkbox("HTTPS", value=True, key="https")
    with col_opt:
        st.write("Options")
        auto_install = st.checkbox("Install after creating", value=False, key="auto_install")
        dev2 = st.text_input("Device (blank = all bound)", key="dev2")

    if st.button("Create allow policy", key="create"):
        if not pkg2:
            st.warning("Load packages and select a package first.")
        elif not src_ip or not url:
            st.warning("Source IP and Target URL are required.")
        else:
            try:
                from urllib.parse import urlparse
                host = urlparse(url).hostname
                if not host:
                    st.error("Could not parse a hostname from the URL.")
                else:
                    locked = False
                    created = False
                    try:
                        locked = client.lock_workspace(adom2)
                        log.info("allow_ip_url: lock_workspace(%s) -> %s", adom2, locked)
                        dst_name = "fqdn-" + host.replace(".", "-")
                        if not client.get_address(adom2, dst_name):
                            try:
                                client.create_address(
                                    adom2,
                                    {"name": dst_name, "type": 2, "fqdn": host,
                                     "comment": "auto-created by Policy Manager"},
                                )
                                log.info("allow_ip_url: created FQDN address %s", dst_name)
                            except c.FMGError as e:
                                raise c.FMGError(e.code, f"create FQDN address '{dst_name}': {e.message}") from e
                        src_name = "host-" + src_ip.replace(".", "-")
                        if not client.get_address(adom2, src_name):
                            try:
                                client.create_address(
                                    adom2,
                                    {"name": src_name, "type": 0,
                                     "subnet": [src_ip, "255.255.255.255"],
                                     "comment": "auto-created by Policy Manager"},
                                )
                                log.info("allow_ip_url: created source address %s", src_name)
                            except c.FMGError as e:
                                raise c.FMGError(e.code, f"create source address '{src_name}': {e.message}") from e
                        svc = []
                        if http:
                            svc.append("HTTP")
                        if https:
                            svc.append("HTTPS")
                        if not svc:
                            svc = ["HTTP", "HTTPS"]
                        # FMG pm/config encodes enums as integers (action=1 accept,
                        # nat=0 disable). policyid is REQUIRED on add (FMG does not
                        # auto-assign it), so compute the next free id. Name
                        # references (interfaces/addresses/services/schedule) stay
                        # strings. status/logtraffic omitted -> package defaults.
                        pid = client.next_policy_id(adom2, pkg2)
                        policy = {
                            "policyid": pid,
                            "name": f"allow {src_ip} -> {host}",
                            "srcintf": ["any"],
                            "dstintf": ["any"],
                            "srcaddr": [src_name],
                            "dstaddr": [dst_name],
                            "service": svc,
                            "action": 1,
                            "schedule": "always",
                            "nat": 0,
                        }
                        try:
                            client.create_policy(adom2, pkg2, policy)
                            log.info("allow_ip_url: created policy '%s'", policy["name"])
                        except c.FMGError as e:
                            raise c.FMGError(e.code, f"create policy '{policy['name']}': {e.message}") from e
                        created = True
                        # policyid is server-assigned on add; look it up for the message.
                        pid = None
                        try:
                            prows = client.list_policies(adom2, pkg2)
                            if isinstance(prows, dict) and "results" in prows:
                                prows = prows["results"]
                            pid = next(
                                (p.get("policyid") for p in prows or []
                                 if isinstance(p, dict) and p.get("name") == policy["name"]),
                                None,
                            )
                        except Exception:
                            pid = None
                        if pid is not None:
                            st.success(
                                f"Created policy #{pid}: {src_ip} -> {host} in package '{pkg2}'"
                            )
                        else:
                            st.success(
                                f"Created policy: {src_ip} -> {host} in package '{pkg2}'"
                            )
                    finally:
                        # Commit + unlock the ADOM workspace when Workspace Mode is on.
                        # Skipped when lock_workspace returned False (normal mode).
                        if locked:
                            try:
                                client.commit_workspace(adom2)
                            except Exception:
                                pass
                            try:
                                client.unlock_workspace(adom2)
                            except Exception:
                                pass
                    if created and auto_install:
                        tid = client.install_package(adom2, pkg2, device=dev2 or None)
                        with st.spinner(f"Install task {tid} in progress..."):
                            task = client.wait_for_task(tid)
                        if task.get("state") == "done":
                            st.success(f"Install complete (task {tid})")
                        else:
                            st.error(f"Install state: {task.get('state')}")
                        st.json(task)
            except Exception as e:
                show_error(e)
