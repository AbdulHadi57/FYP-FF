#!/usr/bin/env python3
"""Clear runtime data from the AegisNet SQLite database.

Default behavior keeps only agent/DC registration tables and clears everything else.

Usage examples:
  python scripts/clear_runtime_data.py
  python scripts/clear_runtime_data.py --yes
  python scripts/clear_runtime_data.py --yes --vacuum
  python scripts/clear_runtime_data.py --keep agents domain_controllers agent_dc_bindings response_templates --yes
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Iterable


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Clear runtime data while keeping agent/DC tables")
    parser.add_argument(
        "--db",
        default="data/aegisnet_live.db",
        help="Path to SQLite database (default: data/aegisnet_live.db)",
    )
    parser.add_argument(
        "--keep",
        nargs="+",
        default=["agents", "domain_controllers", "agent_dc_bindings"],
        help=(
            "Tables to keep. "
            "Default keeps agent/DC state: agents domain_controllers agent_dc_bindings"
        ),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Actually execute deletes. Without this flag, the script only prints a dry run.",
    )
    parser.add_argument(
        "--vacuum",
        action="store_true",
        help="Run VACUUM after cleanup to reclaim space.",
    )
    return parser.parse_args()


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def list_user_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type='table' AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    ).fetchall()
    return [row[0] for row in rows]


def row_count(conn: sqlite3.Connection, table: str) -> int:
    sql = f"SELECT COUNT(*) FROM {quote_ident(table)}"
    return int(conn.execute(sql).fetchone()[0])


def describe_tables(conn: sqlite3.Connection, tables: Iterable[str]) -> list[tuple[str, int]]:
    return [(table, row_count(conn, table)) for table in tables]


def clear_tables(conn: sqlite3.Connection, tables: list[str]) -> None:
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        conn.execute("BEGIN")
        for table in tables:
            conn.execute(f"DELETE FROM {quote_ident(table)}")

        # Reset AUTOINCREMENT counters for cleared tables.
        has_sqlite_sequence = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'"
        ).fetchone()
        if has_sqlite_sequence:
            placeholders = ",".join("?" for _ in tables)
            conn.execute(
                f"DELETE FROM sqlite_sequence WHERE name IN ({placeholders})",
                tables,
            )

        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON")


def main() -> None:
    args = parse_args()
    db_path = Path(args.db)

    if not db_path.exists():
        raise SystemExit(f"Database not found: {db_path}")

    keep = set(args.keep)

    conn = sqlite3.connect(db_path)
    try:
        all_tables = list_user_tables(conn)
        missing_keep = sorted(keep - set(all_tables))
        if missing_keep:
            print("Warning: keep tables not found:", ", ".join(missing_keep))

        to_clear = [t for t in all_tables if t not in keep]
        if not to_clear:
            print("Nothing to clear. No tables matched deletion criteria.")
            return

        print("Database:", db_path)
        print("Keeping tables:", ", ".join(sorted(keep)))
        print("Tables to clear:", ", ".join(to_clear))
        print()

        before = describe_tables(conn, to_clear)
        print("Row counts before clear:")
        for table, count in before:
            print(f"  - {table}: {count}")

        if not args.yes:
            print()
            print("Dry run only. Re-run with --yes to execute.")
            return

        clear_tables(conn, to_clear)

        if args.vacuum:
            conn.execute("VACUUM")

        after = describe_tables(conn, to_clear)
        print()
        print("Row counts after clear:")
        for table, count in after:
            print(f"  - {table}: {count}")

        print()
        print("Cleanup complete.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
