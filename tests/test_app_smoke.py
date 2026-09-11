import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_app_imports():
    # Only verify the module can be compiled/imported (streamlit initializes on
    # import but does not render anything).
    import py_compile
    path = os.path.join(os.path.dirname(__file__), "..", "app.py")
    py_compile.compile(path, doraise=True)
