"""A small CLI-backed runner for setup, offline labs and CI without Python wheels."""

import json
import os
from pathlib import Path
import shutil
import subprocess


class Database:
    def __init__(self, path, executable=None):
        self.path = Path(path)
        self.executable = executable or os.environ.get("WORKSHOP_DUCKDB") or shutil.which("duckdb")
        if not self.executable:
            try:
                import duckdb
                self.python_engine = duckdb
            except ImportError as exc:
                raise RuntimeError("Install DuckDB with ./setup.sh, or set WORKSHOP_DUCKDB to its executable.") from exc

    def python_query(self, sql, restricted=False):
        import threading

        with self.python_engine.connect(str(self.path), read_only=restricted) as con:
            if restricted:
                con.execute("SET enable_external_access=false")
                con.execute("SET lock_configuration=true")
            timer = threading.Timer(20 if restricted else 120, con.interrupt)
            timer.start()
            try:
                result = con.execute(sql)
                names = [d[0] for d in result.description] if result.description else []
                rows = [dict(zip(names, row)) for row in result.fetchall()]
                return json.loads(json.dumps(rows, default=str))
            finally:
                timer.cancel()

    def script(self, sql):
        if not self.executable:
            self.python_query(sql)
            return ""
        result = subprocess.run([self.executable, "-batch", "-bail", "-json", str(self.path)],
                                input=sql, text=True, capture_output=True, timeout=120)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        return result.stdout

    def query(self, sql, restricted=False):
        if not self.executable:
            return self.python_query(sql, restricted)
        prefix = "SET enable_external_access=false; SET lock_configuration=true;\n" if restricted else ""
        command = [self.executable, "-batch", "-bail", "-json"]
        if restricted:
            command.append("-readonly")
        result = subprocess.run(command + [str(self.path)], input=prefix + sql,
                                text=True, capture_output=True, timeout=20 if restricted else 120)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        return json.loads(result.stdout) if result.stdout.strip() else []
