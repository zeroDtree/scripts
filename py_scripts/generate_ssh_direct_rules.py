#!/usr/bin/env python3
"""Write copyable Clash directRules lines for local SSH from ~/.ssh/config."""

from __future__ import annotations

import glob
import os
import subprocess
import sys

SSH_G_TIMEOUT_SEC = float(os.environ.get("SSH_G_TIMEOUT", "5"))


def expand(path: str, base: str) -> str:
    path = os.path.expanduser(path.strip().strip("\"'"))
    if not os.path.isabs(path):
        path = os.path.join(base, path)
    return path


def iter_files(path: str, seen: set[str]):
    path = os.path.abspath(os.path.expanduser(path))
    if path in seen or not os.path.isfile(path):
        return
    seen.add(path)
    yield path
    base = os.path.dirname(path)
    with open(path, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip()
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == "include":
                for hit in sorted(glob.glob(expand(parts[1], base))):
                    yield from iter_files(hit, seen)


def host_tokens(path: str) -> list[str]:
    tokens: list[str] = []
    for file in iter_files(path, set()):
        with open(file, encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                parts = raw.split("#", 1)[0].split()
                if parts and parts[0].lower() == "host":
                    tokens.extend(parts[1:])
    return tokens


def ssh_config_for(host: str, config_path: str) -> dict[str, str]:
    cmd = ["ssh", "-G", "-F", config_path, host]
    result = subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
        timeout=SSH_G_TIMEOUT_SEC,
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        values[key] = value
    return values


def first_jump(value: str | None) -> str | None:
    if not value or value == "none":
        return None
    return value.split(",")[0].strip()


def split_jump(token: str) -> tuple[str, str | None]:
    user_host = token
    if "@" in token:
        _, user_host = token.rsplit("@", 1)
    if user_host.startswith("["):
        host, _, rest = user_host[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else None
        return host, port
    if user_host.count(":") == 1:
        host, port = user_host.split(":", 1)
        return host, port
    return user_host, None


def endpoint_for(token: str, config_path: str) -> tuple[str, str]:
    info = ssh_config_for(token, config_path)
    jump = first_jump(info.get("proxyjump", "none"))
    if jump:
        host, port = split_jump(jump)
        jumped = ssh_config_for(host, config_path)
        host = jumped.get("hostname", host)
        port = port or jumped.get("port", "22")
        return host, port
    return info.get("hostname", token), info.get("port", "22")


def rule_for(host: str, port: str) -> str:
    if ":" in host:
        match = f"(IP-CIDR6,{host}/128,no-resolve)"
    elif host.replace(".", "").isdigit():
        match = f"(IP-CIDR,{host}/32,no-resolve)"
    else:
        match = f"(DOMAIN,{host})"
    return f"AND,((IN-TYPE,TUN),(NETWORK,TCP),{match},(DST-PORT,{port}))"


def default_output_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(here)
    return os.path.join(repo_root, "data", "ssh-direct-rules.js")


def main() -> int:
    config_path = os.path.expanduser(
        os.environ.get("SSH_CONFIG", "~/.ssh/config")
    )
    out = sys.argv[1] if len(sys.argv) > 1 else default_output_path()
    if len(sys.argv) > 2:
        print("usage: generate_ssh_direct_rules.py [output.js]", file=sys.stderr)
        return 2
    if not os.path.isfile(config_path):
        print(f"error: SSH config not found: {config_path}", file=sys.stderr)
        return 1

    rules = ["AND,((IN-TYPE,TUN),(NETWORK,TCP),(DST-PORT,22))"]
    seen = set(rules)

    for token in host_tokens(config_path):
        if token.startswith("!"):
            continue
        suffix = (
            token[2:]
            if token.startswith("*.") and "*" not in token[2:]
            else None
        )
        if token in {"*", "?"} or (
            any(ch in token for ch in "*?") and suffix is None
        ):
            print(f"skip pattern: {token}", file=sys.stderr)
            continue
        probe = token if suffix is None else f"ssh-rule-probe.{suffix}"
        try:
            host, port = endpoint_for(probe, config_path)
        except subprocess.TimeoutExpired:
            print(f"skip {token}: ssh -G timed out", file=sys.stderr)
            continue
        except subprocess.CalledProcessError as exc:
            err = (exc.stderr or "").strip() or str(exc)
            print(f"skip {token}: ssh -G failed: {err}", file=sys.stderr)
            continue
        if port == "22":
            continue
        if suffix and host == probe:
            item = (
                "AND,((IN-TYPE,TUN),(NETWORK,TCP),"
                f"(DOMAIN-SUFFIX,{suffix}),(DST-PORT,{port}))"
            )
        else:
            item = rule_for(host, port)
        if item not in seen:
            seen.add(item)
            rules.append(item)

    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(
            "// Paste into Clash Verge directRules (after loopback rules).\n"
            "// No rule-providers / RULE-SET needed.\n"
        )
        for item in rules:
            handle.write(f'"{item},DIRECT",\n')

    print(f"wrote {len(rules)} rules to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
