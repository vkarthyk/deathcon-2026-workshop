"""Check a sanitized source export against the actual mapper; never certify authenticity automatically."""

import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from workshop.db import MACROS, RAW, RAW_VIEWS, ROOT
from workshop.engine import Database


def validate(kind, path, provenance="modeled", logging_configuration="not supplied", reviewer=""):
    path = Path(path).resolve()
    cloud = {"eks": "AWS", "gke": "GCP", "aks": "Azure"}[kind]
    mapper = ROOT / "solutions" / "lab2_ocsf" / f"{kind}.sql"
    raw = RAW_VIEWS[f"raw_{kind}"].replace(str(RAW / kind / f"{kind}_audit.jsonl.gz"), str(path).replace("'", "''"))
    body = mapper.read_text().strip().rstrip(";")
    sql = [*MACROS, f"CREATE VIEW raw_{kind} AS {raw}", f"CREATE VIEW normalized AS {body}"]
    with tempfile.TemporaryDirectory(prefix="export-check-") as directory:
        db = Database(Path(directory) / "validation.duckdb")
        db.script(";\n".join(sql) + ";")
        counts = db.query("""SELECT count(*) AS rows,
          count(*) FILTER (WHERE metadata.uid IS NULL OR metadata.uid='') AS missing_event_id,
          count(*) FILTER (WHERE time IS NULL) AS missing_time,
          count(*) FILTER (WHERE actor.user.name IS NULL) AS missing_principal,
          count(*) FILTER (WHERE cloud.account.uid IS NULL) AS missing_account,
          count(*) FILTER (WHERE cloud.account.labels['cluster_name'] IS NULL) AS missing_cluster
          FROM normalized""")[0]
        shape = db.query("DESCRIBE normalized")
    return {"provider": cloud, "provenance": provenance, "reviewer": reviewer,
            "status": "structural_check_only", "logging_configuration": logging_configuration,
            "sample_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mapper_sha256": hashlib.sha256(mapper.read_bytes()).hexdigest(),
            "counts": counts, "columns": [{"name": r["column_name"], "type": r["column_type"]} for r in shape],
            "limitations": ["Parsing does not prove a modeled format matches a real provider export.",
                            "Review status, timestamps, payload preservation, identifiers and log-category coverage manually.",
                            "This report contains no raw event payloads."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("eks", "gke", "aks"), required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--provenance", choices=("modeled", "sanitized-real-export"), default="modeled")
    parser.add_argument("--logging-configuration", default="not supplied")
    parser.add_argument("--reviewer", default="")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = validate(args.kind, args.input, args.provenance, args.logging_configuration, args.reviewer)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(args.out)
    if report["counts"]["rows"] == 0 or any(v for k, v in report["counts"].items() if k.startswith("missing_")):
        raise SystemExit("Source parsed but required field coverage failed; inspect the report.")


if __name__ == "__main__":
    main()
