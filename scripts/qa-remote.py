#!/usr/bin/env python3
"""Run a QA command on the development appliance without exposing credentials."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import paramiko


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command")
    parser.add_argument(
        "--credentials",
        default=str(Path(__file__).resolve().parent.parent / "dev_server_creds.txt"),
    )
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument(
        "--upload",
        action="append",
        default=[],
        metavar="LOCAL:REMOTE",
        help="upload a file with SFTP before running the command",
    )
    parser.add_argument(
        "--download",
        action="append",
        default=[],
        metavar="REMOTE:LOCAL",
        help="download a file with SFTP before running the command",
    )
    args = parser.parse_args()

    values = Path(args.credentials).read_text(encoding="utf-8-sig").splitlines()
    if len(values) < 3 or not all(values[:3]):
        raise SystemExit("credentials file must contain host, SSH user, and password")
    host, username, password = values[:3]

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    # QA получает production binary и root-команды. Неизвестный либо
    # изменившийся host key должен остановить запуск до передачи пароля/файла,
    # а не молча добавляться как доверенный.
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(
        host,
        username=username,
        password=password,
        timeout=15,
        banner_timeout=15,
        auth_timeout=15,
    )
    try:
        if args.upload or args.download:
            sftp = client.open_sftp()
            try:
                for spec in args.upload:
                    local, separator, remote = spec.partition(":")
                    if not separator or not local or not remote:
                        raise SystemExit("--upload must be LOCAL:REMOTE")
                    sftp.put(local, remote)
                for spec in args.download:
                    remote, separator, local = spec.partition(":")
                    if not separator or not local or not remote:
                        raise SystemExit("--download must be REMOTE:LOCAL")
                    sftp.get(remote, local)
            finally:
                sftp.close()
        stdin, stdout, stderr = client.exec_command(args.command, timeout=args.timeout)
        stdin.close()
        out = stdout.read()
        err = stderr.read()
        sys.stdout.buffer.write(out)
        sys.stderr.buffer.write(err)
        return stdout.channel.recv_exit_status()
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
