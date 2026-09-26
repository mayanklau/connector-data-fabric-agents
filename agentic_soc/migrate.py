from __future__ import annotations

import os
import subprocess

from sqlalchemy import create_engine, inspect


def run() -> None:
    engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
    schema = inspect(engine)
    if schema.has_table("objects") and not schema.has_table("alembic_version"):
        subprocess.run(["alembic", "stamp", "head"], check=True)
    else:
        subprocess.run(["alembic", "upgrade", "head"], check=True)


if __name__ == "__main__":
    run()
