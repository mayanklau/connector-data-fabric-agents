from __future__ import annotations

import os
import tempfile
from pathlib import Path


TEST_DATABASE = Path(tempfile.gettempdir()) / f"agentic-soc-tests-{os.getpid()}.sqlite3"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DATABASE}"
os.environ["APP_ENV"] = "test"
