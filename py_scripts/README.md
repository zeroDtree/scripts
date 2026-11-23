# py_scripts

Python helpers for this repo.

## Proxy

- [`generate_ssh_direct_rules.py`](generate_ssh_direct_rules.py) reads `~/.ssh/config` (or `SSH_CONFIG`) via `ssh -G -F` and writes copyable Clash rule lines to `../data/ssh-direct-rules.js`. Paste them into `directRules` after the loopback rules, **in order**. Optional output path: `python3 generate_ssh_direct_rules.py /path/to/ssh-direct-rules.js`.

  Order: GitHub TUN SSH → `Ghelper` (override with `SSH_GITHUB_PROXY_GROUP`), then a catch-all TUN TCP 22 → `DIRECT` (ad-hoc `ssh user@ip`), then non-22 Hosts from the config → `DIRECT`.
