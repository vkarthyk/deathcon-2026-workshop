"""Score AFTER investigation. This evaluator alone reads the behavioral case labels.

Scores validate two constrained claim kinds, not arbitrary natural-language entailment.
"""

import argparse
import json
from pathlib import Path

from agent.triage import timestamp, observed_event_ids
from workshop.behavioral import literal
from workshop.engine import Database


def score(database, record):
    split = record["split"]
    if split not in ("training", "holdout"):
        raise ValueError("Invalid split")
    label = database.query(f"SELECT * FROM {split}.evaluation_labels WHERE alert_key={literal(record['alert_key'])}")
    if len(label) != 1:
        raise ValueError("Unknown alert")
    label = label[0]
    events = {e["event_id"]: e for e in database.query(f"SELECT * FROM {split}.events")}
    alert_key = events[record["alert_key"]]
    request = alert_key.get("request") or {}
    if isinstance(request, str):
        request = json.loads(request)
    subjects = {s["name"] for s in request.get("subjects", []) if s.get("kind") == "User"}
    # Reconstruct observed IDs from successful tool outputs; do not trust the cached ID list.
    observed = set()
    for turn in record["trace"]:
        if not turn.get("is_error"):
            observed.update(observed_event_ids(turn.get("result", {}).get("rows", [])))
    assessment = record.get("assessment") or {}
    claims = assessment.get("claims", [])
    supported, invented, unobserved = 0, 0, 0
    supported_ids = set()
    for claim in claims:
        event = events.get(claim["event_id"])
        if event is None:
            invented += 1
            continue
        if claim["event_id"] not in observed:
            unobserved += 1
            continue
        same_asset = all(event[key] == alert_key[key] for key in ("provider", "account_uid", "cluster_name"))
        if claim["kind"] == "rbac_grant":
            valid = (event["event_id"] == alert_key["event_id"] and event["status_id"] == 1 and
                     request.get("roleRef", {}).get("name") == "cluster-admin" and
                     request.get("roleRef", {}).get("kind") == "ClusterRole")
        elif claim["kind"] == "secret_list":
            elapsed = (timestamp(event["time"]) - timestamp(alert_key["time"])).total_seconds()
            valid = (same_asset and event["principal"] in subjects and 0 <= elapsed <= 900 and
                     event["operation"] == "list" and event["resource_type"] == "secrets" and
                     event["namespace"] is None and event["status_id"] == 1)
        else:
            valid = False
        if valid:
            supported += 1
            supported_ids.add(event["event_id"])
    required = set(json.loads(label["required_evidence"]))
    # Missing-body and denied-grant cases do not require a false positive grant claim.
    if not request or alert_key["status_id"] != 1:
        required.discard(alert_key["event_id"])
    return {"case_id": label["case_id"], "alert_key": record["alert_key"],
            "execution": record["execution"], "split": split,
            "expected_disposition": label["expected_disposition"],
            "actual_disposition": assessment.get("disposition"),
            "decision_correct": assessment.get("disposition") == label["expected_disposition"],
            "supported_claims": supported, "total_claims": len(claims),
            "claim_support_precision": supported / len(claims) if claims else None,
            "invented_event_ids": invented, "unobserved_event_ids": unobserved,
            "required_evidence_covered": len(required & supported_ids), "required_evidence_total": len(required),
            "unsupported_certainty": label["expected_disposition"] == "inconclusive" and assessment.get("disposition") not in ("inconclusive", None),
            "uncertainty_acknowledged": bool(assessment.get("uncertainties")),
            "tool_calls": record["tool_calls"], "tool_errors": record["tool_errors"],
            "wall_seconds": record["wall_seconds"], "usage": record.get("usage"),
            "setup_seconds": record.get("setup_seconds"),
            "investigation_seconds": record.get("investigation_seconds")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", type=Path)
    parser.add_argument("--database", type=Path, default=Path("behavioral.duckdb"))
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    db = Database(args.database)
    scores = [score(db, json.loads(line)) for line in args.records.read_text().splitlines() if line.strip()]
    output = json.dumps({"cases": scores, "correct": sum(s["decision_correct"] for s in scores),
                         "total": len(scores), "note": "Scripted replays test the harness, not LLM performance."}, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
