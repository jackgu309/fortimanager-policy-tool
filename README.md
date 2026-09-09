# FortiManager Policy Manager

A Streamlit web UI for managing FortiManager policy packages and firewall
policies via the FortiManager JSON-RPC API: list policy packages, view/move
policies, and install a package to FortiProxy devices.

## Features
- Login to FortiManager (with optional SSL verification toggle)
- List policy packages and policies for an ADOM
- Move policies (before/after a target)
- Install a package to FortiProxy (single device or all bound devices)
- Task polling with status feedback

## Requirements
- Python 3.10+
- See requirements.txt

## Run
``bash
pip install -r requirements.txt
streamlit run app.py
``
