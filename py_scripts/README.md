# py_scripts

Python helpers for this repo.

## Proxy

- [`generate_ssh_direct_rules.py`](generate_ssh_direct_rules.py) reads `~/.ssh/config` (or `SSH_CONFIG`) via `ssh -G -F` and writes copyable Clash `directRules` lines to `../data/ssh-direct-rules.js`. Paste them into `directRules` after the loopback rules; no `rule-providers` / `RULE-SET` needed. Optional output path: `python3 generate_ssh_direct_rules.py /path/to/ssh-direct-rules.js`.
