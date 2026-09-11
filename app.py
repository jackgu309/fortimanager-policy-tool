import time
import streamlit as st
import fmg_client as c

st.set_page_config(page_title="FortiManager Policy Manager", layout="wide")


def show_error(e):
    st.error(str(e))


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
    if st.button("Move"):
        try:
            client.move_policy(adom, pkg, int(src), int(tgt), opt)
            st.success(f"Moved {src} to {opt} of {tgt}")
            rows = client.list_policies(adom, pkg)
            if isinstance(rows, dict) and "results" in rows:
                rows = rows["results"]
            rows = expand_groups(rows, adom, client)
            st.session_state.policies = rows
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
