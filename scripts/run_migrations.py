from __future__ import annotations

import os
import sqlite3
from pathlib import Path


def _migration_files_sqlite() -> list[Path]:
    """SQLite migrations: all .sql files except .postgres.sql variants."""
    return sorted(
        p for p in Path("migrations").glob("*.sql")
        if not p.name.endswith(".postgres.sql")
    )


def _migration_files_postgres() -> list[Path]:
    """Postgres migrations: prefer .postgres.sql variants, fall back to generic .sql.

    E.g. 0003_persistence.postgres.sql is preferred over 0003_persistence.sql.
    """
    result: dict[str, Path] = {}
    for p in Path("migrations").glob("*.sql"):
        if p.suffix == ".sql" and p.name.endswith(".postgres.sql"):
            # e.g. 0003_persistence.postgres.sql → base=0003_persistence
            base = p.name.rsplit(".postgres", 1)[0]
            result[base] = p
        elif not p.name.endswith(".postgres.sql"):
            base = p.stem  # e.g. 0001_initial
            if base not in result:
                result[base] = p
    return [result[k] for k in sorted(result)]


def run_sqlite(database_path: str) -> None:
    conn = sqlite3.connect(database_path)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
        applied = {row[0] for row in conn.execute("SELECT version FROM schema_migrations").fetchall()}
        for path in _migration_files_sqlite():
            if path.name in applied:
                continue
            sql = path.read_text(encoding="utf-8")
            try:
                conn.executescript(sql)
            except sqlite3.OperationalError as exc:
                try:
                    conn.executescript(sql.replace(" IF NOT EXISTS", ""))
                except sqlite3.OperationalError as fallback_exc:
                    if "duplicate column name" not in str(fallback_exc).lower():
                        raise fallback_exc from exc
            conn.execute("INSERT INTO schema_migrations (version) VALUES (?)", (path.name,))
        conn.commit()
    finally:
        conn.close()


def run_postgres(database_url: str) -> None:
    import psycopg

    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"
            )
            cur.execute("SELECT version FROM schema_migrations")
            applied = {row[0] for row in cur.fetchall()}
            for path in _migration_files_postgres():
                if path.name in applied:
                    continue
                sql = path.read_text(encoding="utf-8")
                cur.execute(sql)
                cur.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (path.name,))
            conn.commit()


if __name__ == "__main__":
    database_url = os.getenv("AI_GUARDIAN_DATABASE_URL")
    database_path = os.getenv("AI_GUARDIAN_DB_PATH", "ai_guardian.db")
    if database_url:
        run_postgres(database_url)
    else:
        run_sqlite(database_path)
