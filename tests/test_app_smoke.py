import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_app_imports():
    # 仅验证模块可被编译/导入（streamlit 在 import 时会初始化，但不渲染）
    import py_compile
    path = os.path.join(os.path.dirname(__file__), "..", "app.py")
    py_compile.compile(path, doraise=True)
