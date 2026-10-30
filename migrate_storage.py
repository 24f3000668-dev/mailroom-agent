from pathlib import Path

path = Path("mailroom_agent.py")
source = path.read_text()

if "import psycopg" in source or "DATABASE_URL" in source:
    raise SystemExit(
        "Migration marker already found. No changes made; inspect the file first."
    )

print("Source file found:", path.resolve())
print("SQLite connection found:", "sqlite3.connect(DB_PATH" in source)
print("Decision cache SQL found:", "INSERT OR REPLACE INTO decisions" in source)
print("Receipt insert SQL found:", "INSERT OR IGNORE INTO receipts" in source)
print("Evaluation insert found:", "INSERT INTO evaluations" in source)

if not all([
    "sqlite3.connect(DB_PATH" in source,
    "INSERT OR REPLACE INTO decisions" in source,
    "INSERT OR IGNORE INTO receipts" in source,
    "INSERT INTO evaluations" in source,
]):
    raise SystemExit("Unexpected source layout. No changes made.")

print("Preflight passed. No source code was changed.")
