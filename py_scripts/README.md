# py_scripts

Python helpers for this repo.

## Proxy

- [`generate_ssh_direct_rules.py`](generate_ssh_direct_rules.py) reads `~/.ssh/config` (or `SSH_CONFIG`) via `ssh -G -F` and writes TUN SSH direct rules to `../data/ssh-direct.yaml` for a Clash `RULE-SET`. Optional output path: `python3 generate_ssh_direct_rules.py /path/to/ssh-direct.yaml`.
