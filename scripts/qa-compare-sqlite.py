#!/usr/bin/env python3
"""Read-only per-table comparison for two SQLite state snapshots."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys


def normalize(value):
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    return value


def normalize_record(table: str, record: dict) -> dict:
    normalized = {name: normalize(value) for name, value in record.items()}
    if table == "revisions" and "applied_at" in normalized:
        normalized["applied_at"] = "<apply-timestamp>"
    return normalized


def tables(connection: sqlite3.Connection) -> list[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    return [row[0] for row in rows]


def digest(connection: sqlite3.Connection, table: str) -> tuple[int, str]:
    quoted = '"' + table.replace('"', '""') + '"'
    names = [column[1] for column in connection.execute(f"PRAGMA table_info({quoted})")]
    rows = [
        normalize_record(table, dict(zip(names, row)))
        for row in connection.execute(f"SELECT * FROM {quoted}")
    ]
    encoded = [json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows]
    encoded.sort()
    payload = "\n".join(encoded).encode("utf-8")
    return len(rows), hashlib.sha256(payload).hexdigest()


def changed_rows(
    before: sqlite3.Connection, after: sqlite3.Connection, table: str
) -> list[str]:
    quoted = '"' + table.replace('"', '""') + '"'
    columns = list(before.execute(f"PRAGMA table_info({quoted})"))
    names = [column[1] for column in columns]
    primary = [column[1] for column in columns if column[5]]
    key_names = primary or names[:1]

    def keyed(connection: sqlite3.Connection):
        result = {}
        for row in connection.execute(f"SELECT * FROM {quoted}"):
            record = normalize_record(table, dict(zip(names, row)))
            key = tuple(normalize(record[name]) for name in key_names)
            result[json.dumps(key, ensure_ascii=False, sort_keys=True)] = record
        return result

    left = keyed(before)
    right = keyed(after)
    changes = []
    for key in sorted(set(left) | set(right)):
        if key not in left:
            changes.append(f"key={key} added")
        elif key not in right:
            changes.append(f"key={key} removed")
        else:
            different = [name for name in names if left[key][name] != right[key][name]]
            if different:
                changes.append(f"key={key} columns={','.join(different)}")
    return changes


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: qa-compare-sqlite.py BEFORE.db AFTER.db")
    before = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    after = sqlite3.connect(f"file:{sys.argv[2]}?mode=ro", uri=True)
    try:
        names = sorted(set(tables(before)) | set(tables(after)))
        mismatch = False
        for name in names:
            if name not in tables(before) or name not in tables(after):
                print(f"DIFF {name}: table missing")
                mismatch = True
                continue
            left = digest(before, name)
            right = digest(after, name)
            status = "SAME" if left == right else "DIFF"
            print(f"{status} {name}: before={left[0]}:{left[1]} after={right[0]}:{right[1]}")
            if left != right:
                for change in changed_rows(before, after, name):
                    print(f"  {change}")
            mismatch |= left != right
        return int(mismatch)
    finally:
        before.close()
        after.close()


if __name__ == "__main__":
    raise SystemExit(main())
