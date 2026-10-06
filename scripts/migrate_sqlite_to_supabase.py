"""One-time copy of a local SecureSight SQLite database into an empty Supabase database.

Usage: set DATABASE_URL to the Supabase PostgreSQL URI, then run
    python scripts/migrate_sqlite_to_supabase.py securesight.db
The source file is read-only and is never deleted.
"""

import argparse
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

from sqlalchemy import DateTime, create_engine, func, select, text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.database import Base
from backend.app import models  # noqa: F401 - registers ORM tables


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Path to the existing SQLite database")
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    url = os.getenv("DATABASE_URL", "")
    if not url.startswith(("postgresql://", "postgresql+psycopg://", "postgres://")):
        parser.error("DATABASE_URL must point to your Supabase PostgreSQL database")
    if url.startswith("postgres://"):
        url = "postgresql+psycopg://" + url[len("postgres://"):]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]

    db = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    target = create_engine(url, connect_args={"sslmode": "require"}, pool_pre_ping=True)
    try:
        Base.metadata.create_all(target)
        # Abort before copying if any destination table already contains data.
        with target.connect() as connection:
            for table in Base.metadata.sorted_tables:
                if connection.scalar(select(func.count()).select_from(table)):
                    raise RuntimeError(f"Destination table {table.name} is not empty; no data copied.")

        counts = {}
        with target.begin() as connection:
            for table in Base.metadata.sorted_tables:
                source_columns = {row[1] for row in db.execute(f'PRAGMA table_info("{table.name}")')}
                if not source_columns:
                    counts[table.name] = 0
                    continue
                columns = [column.name for column in table.columns if column.name in source_columns]
                datetime_columns = {column.name for column in table.columns if isinstance(column.type, DateTime)}
                cursor = db.execute(f'SELECT {", ".join(chr(34) + col + chr(34) for col in columns)} FROM "{table.name}"')
                count = 0
                while batch := cursor.fetchmany(500):
                    records = []
                    for row in batch:
                        record = dict(zip(columns, row))
                        for name in datetime_columns & record.keys():
                            if record[name] is not None:
                                record[name] = datetime.fromisoformat(record[name])
                        records.append(record)
                    connection.execute(table.insert(), records)
                    count += len(batch)
                counts[table.name] = count
                if count and "id" in columns:
                    max_id = connection.scalar(select(func.max(table.c.id)))
                    connection.execute(
                        text("SELECT setval(pg_get_serial_sequence(:table_name, 'id'), :max_id, true)"),
                        {"table_name": table.name, "max_id": max_id},
                    )
        for name, count in counts.items():
            print(f"{name}: {count} rows copied")
    finally:
        db.close()
        target.dispose()


if __name__ == "__main__":
    main()
