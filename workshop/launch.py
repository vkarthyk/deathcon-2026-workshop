"""CLI-first launcher: no pip dependency needed when DuckDB is already installed."""

import argparse
from pathlib import Path
import re
import socket
import subprocess
import tempfile

from workshop.behavioral import ROOT, enterprise_statements
from workshop.db import initialize
from workshop.engine import Database
from workshop.notebooks import seed_sql


class SQLCollector:
    def __init__(self):
        self.statements = []

    def sql(self, value):
        self.statements.append(value)


def setup_statements(participant_mappers=False):
    collector = SQLCollector()
    initialize(collector, mapper_path=ROOT / "labs" / "lab2_ocsf" if participant_mappers else ROOT / "workshop" / "ingestion")
    sql = collector.statements + enterprise_statements()
    return sql


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=ROOT / "workshop-ui.duckdb")
    parser.add_argument("--port", type=int, default=4213)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--participant-mappers", action="store_true")
    parser.add_argument("--solutions", action="store_true", help="Reference mappings are now the default")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not args.prepare_only:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", args.port))
            except OSError:
                parser.error(f"Port {args.port} is unavailable. Stop the old UI or choose --port 4214.")
    db = Database(args.database)
    if not db.executable:
        parser.error("This launcher needs the DuckDB CLI; use python -m workshop.ui with the Python engine instead.")
    version = db.query("SELECT version() AS version")[0]["version"]
    numbers = tuple(int(n) for n in re.findall(r"\d+", version)[:3])
    if numbers < (2, 0, 0):
        parser.error(f"Found DuckDB {version}; this workshop targets 2.0.0+. Upgrade the CLI or set WORKSHOP_DUCKDB to a compatible executable.")
    print("Preparing enterprise logs, enrichment, and the shared detection rule...", flush=True)
    db.script("BEGIN;\n" + ";\n".join(setup_statements(args.participant_mappers)) + ";\nCOMMIT;")
    print(db.query("SELECT provider, severity, count(*) AS alerts FROM enterprise.behavioral_alerts GROUP BY provider, severity"), flush=True)
    if args.prepare_only:
        return
    # Keep the UI metadata in the checkout, not in the participant's existing global notebook store.
    startup = seed_sql(args.database.stem) + ["INSTALL ui", "LOAD ui", f"SET ui_local_port={args.port}", "CALL start_ui()"]
    with tempfile.TemporaryDirectory(prefix="workshop-start-") as directory:
        path = Path(directory) / "start.sql"
        path.write_text(";\n".join(startup) + ";\n")
        print(f"Open http://localhost:{args.port}/. Select a numbered workshop SQL notebook.", flush=True)
        print("Keep this terminal open. Exit DuckDB with .quit or Ctrl+D when finished.", flush=True)
        command = [db.executable, "-interactive", "-dark-mode", "-init", str(path), str(args.database)]
        # Only v2 CLI has agent-mode flags; the environment override is harmless on older versions.
        import os
        env = dict(os.environ, DUCKDB_AGENT_MODE="0")
        try:
            import sys
            if sys.stdin.isatty():
                subprocess.run(command, env=env, check=True)
            else:
                # A scripted launch must not exit on stdin EOF and take the UI down.
                process = subprocess.Popen(command, env=env, stdin=subprocess.PIPE)
                try:
                    process.wait()
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=10)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"Workshop setup failed: {exc}") from exc
