import time
import streamlit as st
import fmg_client as c

st.set_page_config(page_title="FortiManager Policy Manager", layout="wide")


def show_error(e):
    st.error(str(e))


with st.sidebar:
    st.title("FMG 连接")
    host = st.text_input("FMG 地址", value="https://", key="host")
    user = st.text_input("用户名", key="user")
    passwd = st.text_input("密码", type="password", key="passwd")
    verify_ssl = st.checkbox("校验 SSL 证书", value=False)
    if not verify_ssl:
        st.warning("未校验 SSL：仅限可信内网使用。")
    if st.button("登录"):
        try:
            cl = c.FMGClient(host, verify_ssl=verify_ssl)
            cl.login(user, passwd)
            st.session_state.client = cl
            st.success("登录成功")
        except Exception as e:
            show_error(e)
    if st.button("登出"):
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
    st.info("请在左侧填写 FMG 地址、用户名、密码后点击「登录」。")
    st.stop()

st.header("策略包与 Policy")
adom = st.text_input("ADOM", value="FortiProxy")

if st.button("加载策略包"):
    try:
        st.session_state.packages = [
            p.get("name") for p in client.list_packages(adom) if p.get("name")
        ]
    except Exception as e:
        show_error(e)

pkg = st.selectbox("选择 Policy Package", st.session_state.get("packages", []))
if st.button("加载 Policy") and pkg:
    try:
        rows = client.list_policies(adom, pkg)
        if isinstance(rows, dict) and "results" in rows:
            rows = rows["results"]
        st.session_state.policies = rows
    except Exception as e:
        show_error(e)

policies = st.session_state.get("policies", [])
if policies:
    st.subheader("Policy 列表")
    st.dataframe(policies)

    st.subheader("移动 Policy")
    ids = [str(p.get("policyid")) for p in policies]
    src = st.selectbox("源 Policy", ids, key="src")
    tgt = st.selectbox("目标 Policy", ids, key="tgt")
    opt = st.radio("位置", ["after", "before"])
    if st.button("移动"):
        try:
            client.move_policy(adom, pkg, int(src), int(tgt), opt)
            st.success(f"已将 {src} 移动到 {tgt} 的 {opt} 位置")
            rows = client.list_policies(adom, pkg)
            if isinstance(rows, dict) and "results" in rows:
                rows = rows["results"]
            st.session_state.policies = rows
        except Exception as e:
            show_error(e)

    st.subheader("安装到 FortiProxy")
    dev = st.text_input("设备名（留空=全部绑定设备）", key="dev")
    if st.button("安装到 FortiProxy"):
        try:
            tid = client.install_package(adom, pkg, device=dev or None)
            with st.spinner(f"安装任务 {tid} 进行中..."):
                task = client.wait_for_task(tid)
            if task.get("state") == "done":
                st.success(f"安装完成（task {tid}）")
            else:
                st.error(f"安装状态：{task.get('state')}")
            st.json(task)
        except Exception as e:
            show_error(e)
