import time
import streamlit as st
import fmg_client as c

st.set_page_config(page_title="FortiManager Policy Manager", layout="wide")


def show_error(e):
    st.error(str(e))


def _stringify(v):
    if isinstance(v, list):
        return " ".join(str(x) for x in v)
    return v


def expand_groups(policies, adom, client):
    """Resolve address/service groups so source/destination match the FMG GUI.

    FMG's JSON-RPC get returns only object/group *names* (e.g. an address-group
    name), while the GUI expands groups into their members. Here we expand
    srcaddr/dstaddr/service group names into 'group member1 member2 ...' and turn
    every list column into a readable string.
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
        p = dict(p)
        for col in ("srcaddr", "dstaddr"):
            p[col] = " ".join(c.resolve_names(p.get(col) or [], addr_map))
        p["service"] = " ".join(c.resolve_names(p.get("service") or [], svc_map))
        p = {k: _stringify(v) for k, v in p.items()}
        out.append(p)
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
    ids = [str(p.get("policyid")) for p in policies]
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
