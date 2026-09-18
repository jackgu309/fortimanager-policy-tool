# FortiManager Policy Manager

A Streamlit web UI for managing FortiManager policy packages and firewall
policies via the FortiManager JSON-RPC API. It is designed to mirror what you
see in the FortiManager GUI: the policy table uses the same column labels and
the same expanded values (address/service groups are expanded into their
members; enum values are translated into GUI labels).

## Features

The UI is split into two tabs.

### Tab 1 — Policy List
- Login to FortiManager (with optional SSL verification toggle)
- List policy packages and policies for an ADOM
- View policies in a table whose columns/labels match the FMG GUI
  (e.g. `Source`, `Destination`, `Destination Interface`, `Action`, ...)
- Move policies (before/after a target)
- Install a package to FortiProxy (single device or all bound devices)
- Task polling with status feedback

### Tab 2 — Allow IP → URL
Quickly create an "allow this source IP to reach this URL" policy:
- Enter a source IP (e.g. `10.1.1.10`) and a target URL
  (e.g. `https://api.example.com/path`)
- The tool parses the hostname, then:
  - creates a destination **FQDN** address object (`type=fqdn`)
  - creates a source **/32 host** address object (`type=ipmask`)
  - adds an `accept` policy (`service` = HTTP/HTTPS, `srcintf`/`dstintf` = `any`,
    `schedule` = `always`, `nat` = `disable`, `logtraffic` = `utm`)
- Address objects are created idempotently (an existing object with the same
  derived name is reused, not duplicated)
- Optional auto-install after creating (off by default — install manually from
  Tab 1 when ready)

## Why the table matches the GUI
FortiManager's JSON-RPC `get` returns the raw stored values: policy columns
like `srcaddr`/`dstaddr` hold **object reference names**, and `action`/`status`
hold raw enums (`accept`, `enable`, ...). The GUI additionally *expands*
address/service groups into their members and *translates* enums into friendly
labels. This tool reproduces that behavior so the table matches the GUI 1:1.

(If a group still shows only its name instead of expanded members, it is most
likely a **dynamic** address object — those members live on the FortiGate, not
in the FMG `addrgrp` table, so they cannot be expanded from the API.)

## Requirements
- Python 3.10+
- See requirements.txt

## Run
```bash
pip install -r requirements.txt
streamlit run app.py
```

## Notes
- Tested against FortiManager VM64 v7.6.4 (Feature). The JSON-RPC behavior
  described above is consistent across FMG versions.
- **Workspace Mode**: if the target ADOM has Workspace Mode enabled, write
  operations (creating the allow policy, moving a policy) require the ADOM
  workspace lock. The tool auto-acquires the lock, commits, and unlocks around
  each write. When Workspace Mode is disabled it falls back to normal-mode
  writes transparently — `FMG API error -10147: no write permission` means the
  ADOM is locked by another session or global Read-Only Mode is on.
- FQDN-based allow lists the whole domain, not a specific URL path. For
  path-level control a web-filter profile would be required (not implemented).
