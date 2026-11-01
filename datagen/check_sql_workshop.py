"""Check tutorials, using facilitator answers for deliberately unfinished detection cells."""

from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from workshop.engine import Database  # noqa: E402
from workshop.launch import setup_statements  # noqa: E402
from workshop.normalization import normalize_bindings, check_detection  # noqa: E402
from workshop.notebooks import split_statements  # noqa: E402
from solutions.binding_exercise.mappings import MAPPINGS  # noqa: E402
from solutions.binding_exercise.queries import detection  # noqa: E402
from types import SimpleNamespace


def main():
    with tempfile.TemporaryDirectory(prefix="sql-workshop-check-") as directory:
        database = Database(Path(directory) / "workshop.duckdb")
        database.script(";\n".join(setup_statements()) + ";")
        for notebook in sorted((ROOT / "notebooks" / "sql").glob("*.sql")):
            clouds = iter(('eks', 'gke', 'aks'))
            if notebook.stem == '02_Normalize_the_logs':
                normalize_bindings(SimpleNamespace(engine=database), MAPPINGS)
            for statement in split_statements(notebook.read_text()):
                if '__TODO_' in statement:
                    cloud = ('normalized-success' if '__TODO_SUCCESS_FILTER__' in statement else 'normalized') if notebook.stem == '02_Normalize_the_logs' else next(clouds)
                    check_detection(database, cloud, detection(cloud))
                else:
                    database.query(statement)
            print(f"PASS {notebook.name}", flush=True)
        alerts = database.query("SELECT provider, count(*) AS n FROM enterprise.behavioral_alerts GROUP BY provider ORDER BY provider")
        assert len(alerts) == 3 and all(row["n"] == 1 for row in alerts), alerts
        print("PASS same rule on enterprise log day: 3 provider alerts", flush=True)


if __name__ == "__main__":
    main()
