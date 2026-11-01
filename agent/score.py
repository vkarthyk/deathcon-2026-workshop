"""Score agent transcripts against ground truth and print them side by side.

    python3.11 -m agent.score transcripts/raw.json transcripts/ocsf.json
"""

import csv
import json
import sys
from pathlib import Path

from workshop.db import RAW, connect

PROVIDER = {"eks": "AWS", "gke": "GCP", "aks": "Azure"}
EXPECTED_PRINCIPALS = {
    "arn:aws:sts::111122223333:assumed-role/eks-developer/jdoe@example.com",
    "jdoe@example.com",
    "system:serviceaccount:argocd:argocd-application-controller",
}
ATTACKER_IP = "198.51.100.23"


def load_truth():
    with open(RAW / "ground_truth.csv") as f:
        rows = list(csv.DictReader(f))
    return {r["auditID"]: (PROVIDER[r["cloud"]], int(r["step"])) for r in rows}


def hard_fp_id():
    """The SRE's privileged `kubectl debug node` pod: the lookalike only context can clear."""
    con = connect(mappers=False, fixtures=False)
    row = con.sql("""SELECT json_extract_string(event, '$.auditID') FROM raw_eks
                     WHERE json_extract_string(event, '$.requestObject.metadata.name') LIKE 'node-debugger-%'""").fetchone()
    return row[0] if row else None


def all_event_ids():
    con = connect(mappers=False, fixtures=False)
    ids = set()
    for sql in ("SELECT event->>'$.auditID' FROM raw_eks", "SELECT event->>'$.auditID' FROM raw_aks",
                "SELECT entry->>'$.operation.id' FROM raw_gke"):
        ids |= {r[0] for r in con.sql(sql).fetchall()}
    return ids


def score(record, truth, known_ids, hard_fp=None):
    v = record.get("verdict") or {}
    cited = {e["event_id"] for e in v.get("evidence", [])}
    tp = cited & truth.keys()
    fp = (cited & known_ids) - truth.keys()
    hallucinated = cited - known_ids
    steps_total = {(c, s) for c, s in truth.values()}
    steps_found = {truth[i] for i in tp}
    principals = {p.strip() for p in v.get("compromised_principals", [])}
    clouds = set(v.get("affected_clouds", []))

    s = {
        "outcome": record.get("outcome"),
        "verdict": v.get("verdict"),
        "clouds_found": f"{len(clouds & set(PROVIDER.values()))}/3",
        "attack_steps_cited": f"{len(steps_found)}/{len(steps_total)}",
        "attack_events_cited": f"{len(tp)}/{len(truth)}",
        "benign_events_cited": len(fp),
        "invented_event_ids": len(hallucinated),
        "attacker_ip_found": ATTACKER_IP in v.get("attacker_ips", []),
        "principals_found": f"{len(principals & EXPECTED_PRINCIPALS)}/{len(EXPECTED_PRINCIPALS)}",
        # Cleared = examined and explicitly ruled benign, not merely left out.
        "hard_lookalike_cleared": bool(hard_fp) and hard_fp not in cited and any(
            k in " ".join(v.get("benign_lookalikes", [])).lower() for k in ("node-debugger", hard_fp)),
    }
    # 0-100: correctness first, then coverage, minus penalties for wrong or invented evidence.
    points = (25 * (v.get("verdict") == "malicious") + 10 * (v.get("verdict") == "suspicious")
              + 15 * len(clouds & set(PROVIDER.values())) / 3
              + 35 * len(steps_found) / len(steps_total)
              + 10 * s["attacker_ip_found"]
              + 15 * len(principals & EXPECTED_PRINCIPALS) / len(EXPECTED_PRINCIPALS)
              - 2 * len(fp) - 5 * len(hallucinated))
    s["score"] = max(0, round(points))
    t = record.get("totals", {})
    turns = record.get("turns", [])
    s.update({"turns": t.get("turns"), "tool_calls": t.get("tool_calls"), "tool_errors": t.get("tool_errors"),
              "wall_s": t.get("wall_s"),
              "model_s": round(sum(x.get("latency_s", 0) for x in turns), 1),
              "tool_s": round(sum(c.get("ms", 0) for x in turns for c in x["tool_calls"]) / 1000, 1)})
    return s


def main(paths):
    truth, known, fp = load_truth(), all_event_ids(), hard_fp_id()
    runs = [(Path(p).stem, score(json.loads(Path(p).read_text()), truth, known, fp)) for p in paths]
    keys = list(runs[0][1])
    width = max(len(k) for k in keys) + 2
    print("".ljust(width) + "".join(name[:22].ljust(24) for name, _ in runs))
    for k in keys:
        print(k.ljust(width) + "".join(str(s[k])[:22].ljust(24) for _, s in runs))


if __name__ == "__main__":
    main(sys.argv[1:])
