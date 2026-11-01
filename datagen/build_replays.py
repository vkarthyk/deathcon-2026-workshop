"""Bundle real offline tool executions, explicitly labeled scripted rather than LLM results."""

import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent.evaluate_triage import score  # noqa: E402
from agent.triage import run  # noqa: E402
from workshop.behavioral import statements  # noqa: E402
from workshop.engine import Database  # noqa: E402


def main():
    output = ROOT / "data" / "behavioral" / "replays"
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="replay-build-") as directory:
        database = Database(Path(directory) / "lab.duckdb")
        database.script(";\n".join(statements()) + ";")
        for split in ("training", "holdout"):
            records, scores = [], []
            for row in database.query(f"SELECT min(alert_key) AS alert_key FROM {split}.evaluation_labels GROUP BY case_id ORDER BY case_id"):
                record = run(database, row["alert_key"], split=split)
                records.append(record)
                scores.append(score(database, record))
            (output / f"{split}.jsonl").write_text("".join(json.dumps(record, default=str) + "\n" for record in records))
            (output / f"{split}-scores.json").write_text(json.dumps({
                "execution": "scripted_replay", "not_a_model_benchmark": True,
                "correct": sum(s["decision_correct"] for s in scores), "total": len(scores), "cases": scores,
            }, indent=2) + "\n")
            print(f"{split}: {len(records)} scripted replays; {sum(s['decision_correct'] for s in scores)} matching fixture dispositions", flush=True)


if __name__ == "__main__":
    main()
