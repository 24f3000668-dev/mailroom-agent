from pathlib import Path

src = Path("mailroom_agent.py").read_text()

if "DATABASE_URL" in src or "class CompatDB" in src:
    raise SystemExit("Migration markers already exist; stopping safely.")

old_import = "import base64, hashlib, json, os, re, sqlite3, threading, time"
new_import = "import base64, hashlib, json, os, re, sqlite3, threading, time\nimport psycopg"

old_storage_start = "# ------------------------------------------------------------------ storage"
old_storage_end = "_locks, _guard = {}, threading.Lock()"

if old_import not in src:
    raise SystemExit("Import line not found; no file created.")

start = src.find(old_storage_start)
end = src.find(old_storage_end, start)

if start < 0 or end < 0:
    raise SystemExit("Storage block not found; no file created.")

storage = r'''# ------------------------------------------------------------------ storage
DB_LOCK = threading.RLock()

class CompatDB:
    """Small SQLite/PostgreSQL adapter for this agent's existing SQL."""
    def __init__(self):
        self.url = os.environ.get("DATABASE_URL", "").strip()
        self.pg = bool(self.url)
        if self.pg:
            url = self.url
            if url.startswith("postgres://"):
                url = "postgresql://" + url[len("postgres://"):]
            self.conn = psycopg.connect(url)
            schema = """
            CREATE TABLE IF NOT EXISTS evaluations(
              eval_id TEXT PRIMARY KEY, req_hash TEXT, verifier TEXT, input_digest TEXT,
              req_body TEXT, propose_resp TEXT, proposals TEXT,
              commit_hash TEXT, commit_resp TEXT);
            CREATE TABLE IF NOT EXISTS decisions(fp TEXT PRIMARY KEY, data TEXT);
            CREATE TABLE IF NOT EXISTS receipts(
              eval_id TEXT, call_id TEXT, receipt_id TEXT, accepted INTEGER, status TEXT,
              PRIMARY KEY(eval_id, call_id));
            """
            for statement in schema.strip().split(";"):
                if statement.strip():
                    self.conn.execute(statement)
            self.conn.commit()
        else:
            path = os.environ.get("DB_PATH", "mailroom.db")
            self.conn = sqlite3.connect(path, check_same_thread=False)
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS evaluations(
              eval_id TEXT PRIMARY KEY, req_hash TEXT, verifier TEXT, input_digest TEXT,
              req_body TEXT, propose_resp TEXT, proposals TEXT,
              commit_hash TEXT, commit_resp TEXT);
            CREATE TABLE IF NOT EXISTS decisions(fp TEXT PRIMARY KEY, data TEXT);
            CREATE TABLE IF NOT EXISTS receipts(
              eval_id TEXT, call_id TEXT, receipt_id TEXT, accepted INTEGER, status TEXT,
              PRIMARY KEY(eval_id, call_id));
            """)
            self.conn.commit()

    def execute(self, sql, params=()):
        if not self.pg:
            return self.conn.execute(sql, params)

        sql = sql.replace("INSERT OR REPLACE INTO decisions VALUES(?,?)",
            "INSERT INTO decisions(fp,data) VALUES(%s,%s) "
            "ON CONFLICT(fp) DO UPDATE SET data=EXCLUDED.data")
        sql = sql.replace("INSERT OR IGNORE INTO receipts VALUES(?,?,?,?,?)",
            "INSERT INTO receipts(eval_id,call_id,receipt_id,accepted,status) "
            "VALUES(%s,%s,%s,%s,%s) ON CONFLICT(eval_id,call_id) DO NOTHING")
        sql = sql.replace("?", "%s")
        return self.conn.execute(sql, params)

    def executescript(self, sql):
        if not self.pg:
            return self.conn.executescript(sql)
        for statement in sql.strip().split(";"):
            if statement.strip():
                self.conn.execute(statement)
        return None

    def commit(self):
        return self.conn.commit()

db = CompatDB()
'''

patched = src.replace(old_import, new_import, 1)
start = patched.find(old_storage_start)
end = patched.find(old_storage_end, start)
patched = patched[:start] + storage + patched[end:]
patched = patched.replace(
    'DB_PATH = os.environ.get("DB_PATH", "mailroom.db")\n', '', 1
)

Path("mailroom_agent_postgres.py").write_text(patched)
print("Created mailroom_agent_postgres.py; original file unchanged.")
