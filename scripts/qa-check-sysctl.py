#!/usr/bin/env python3
"""Compare every sysctl rendered by netOS with the live kernel."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def normalize(value: str) -> str:
    return " ".join(value.split())


def proc_path(key: str) -> Path:
    return Path("/proc/sys").joinpath(*key.split("."))


def check(key: str, want: str) -> bool:
    path = proc_path(key)
    if not path.exists():
        print(f"SKIP missing {key}")
        return True
    got = normalize(path.read_text(encoding="utf-8"))
    want = normalize(want)
    if got != want:
        print(f"MISMATCH {key}: got={got!r} want={want!r}")
        return False
    print(f"PASS {key}={got}")
    return True


def main() -> int:
    rendered = subprocess.run(
        ["netos", "render", "sysctl"], check=True, text=True, capture_output=True
    ).stdout
    expected: dict[str, str] = {}
    for line in rendered.splitlines():
        if line.startswith("net.") and " = " in line:
            key, value = line.split(" = ", 1)
            expected[key] = value

    ok = all(check(key, value) for key, value in sorted(expected.items()))
    ipv6_off = expected.get("net.ipv6.conf.all.disable_ipv6") == "1"
    interface_values = {
        "disable_ipv6": "1" if ipv6_off else "0",
        "accept_ra": "0" if ipv6_off else "1",
        "autoconf": "0" if ipv6_off else "1",
    }
    for interface in sorted(Path("/sys/class/net").iterdir()):
        if interface.name == "lo":
            continue
        for field, value in interface_values.items():
            ok = check(f"net.ipv6.conf.{interface.name}.{field}", value) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
