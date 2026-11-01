"""Build the participant database and keep DuckDB's local UI alive."""

import argparse
from pathlib import Path
import socket
import threading

import duckdb

from workshop.db import CLOUDS, DATA, FIXTURES, ROOT, initialize, mapper_dir
from workshop.behavioral import enterprise_statements
from workshop.notebooks import seed_sql


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=4213, help="UI port (default: 4213)")
    parser.add_argument("--database", type=Path, default=ROOT / "workshop-ui.duckdb")
    parser.add_argument("--solutions", action="store_true", help="Use completed Lab 2 mappings")
    parser.add_argument("--participant-mappers", action="store_true", help="Use unfinished mapping exercises")
    parser.add_argument("--prepare-only", action="store_true", help="Build and validate without starting the UI")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    missing = [DATA / "raw" / cloud / f"{cloud}_audit.jsonl.gz" for cloud in CLOUDS]
    missing += [FIXTURES / f"{name}.csv" for name in (
        "approved_registries", "clusters", "identities", "identity_links",
        "ip_reputation", "privileged_allowlist", "service_accounts",
    )]
    missing = [path for path in missing if not path.is_file()]
    if missing:
        parser.error("Workshop data is missing; use a complete repository checkout:\n" +
                     "\n".join(str(path) for path in missing))

    if not args.prepare_only:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", args.port))
            except OSError as exc:
                parser.error(f"Cannot listen on port {args.port}: {exc}. Stop the existing UI or use --port 4214.")

    mappings = mapper_dir() if args.participant_mappers else ROOT / "workshop" / "ingestion"
    print(f"Preparing {args.database.resolve()} using {mappings}...", flush=True)
    try:
        with duckdb.connect(str(args.database)) as con:
            # Refresh edited mapper files atomically; retain participants' own tables.
            con.execute("BEGIN")
            initialize(con, mapper_path=mappings)
            for statement in enterprise_statements():
                con.execute(statement)
            con.execute("COMMIT")
            counts = con.execute(
                "SELECT cloud.provider, count(*) FROM ocsf_api_activity GROUP BY ALL ORDER BY 1"
            ).fetchall()
            for provider, count in counts:
                print(f"  {provider}: {count:,} events", flush=True)
            con.execute("CHECKPOINT")
            if args.prepare_only:
                return
            for statement in seed_sql(args.database.stem):
                con.execute(statement)
            print("Installing/loading DuckDB's UI extension (internet required on first launch)...", flush=True)
            con.execute("INSTALL ui")
            con.execute("LOAD ui")
            con.execute(f"SET ui_local_port = {args.port}")
            con.execute("CALL start_ui()")
            print(f"\nOpen http://localhost:{args.port}/ and select {args.database.stem}.", flush=True)
            print("Keep this terminal open. Press Ctrl+C to stop. Rerun ./setup.sh after editing mapper SQL.", flush=True)
            try:
                threading.Event().wait()
            except KeyboardInterrupt:
                print("\nStopping the workshop UI.", flush=True)
    except duckdb.Error as exc:
        parser.exit(1, f"DuckDB setup failed: {exc}\n")


if __name__ == "__main__":
    main()
