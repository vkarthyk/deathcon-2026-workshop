"""Execute tutorials with facilitator answers in memory; never overwrite participant work.

    .workshop-venv/bin/python datagen/check_tutorials.py
"""

from pathlib import Path
import os
import tempfile
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def with_facilitator_answers(notebook):
    """Resolve deliberate TODOs only in the validator's in-memory notebook copy."""
    from solutions.binding_exercise.mappings import MAPPINGS
    from solutions.binding_exercise.queries import detection
    import pprint
    for cell in notebook['cells']:
        if cell['cell_type'] != 'code':
            continue
        source = cell['source'] if isinstance(cell['source'], str) else ''.join(cell['source'])
        for cloud in MAPPINGS:
            if source.startswith(cloud + '_mapping ='):
                source = cloud + '_mapping = ' + pprint.pformat(MAPPINGS[cloud])
        if source.startswith('%%sql --check-binding ') and '__TODO_' in source:
            header = source.split('\n', 1)[0]
            source = header + '\n' + detection(header.split()[-1])
        cell['source'] = source
    return notebook


def check():
    import nbformat
    from nbclient import NotebookClient

    for path in sorted((ROOT / "notebooks").glob("*.ipynb")):
        notebook = with_facilitator_answers(nbformat.read(path, as_version=4))
        nbformat.validate(notebook)
        NotebookClient(notebook, timeout=600, kernel_name="python3",
                       resources={"metadata": {"path": str(ROOT)}}).execute()
        print(f"PASS {path.relative_to(ROOT)}", flush=True)


def check_sql(rule_file):
    """Execute notebook SQL through the same session helper, without a Jupyter kernel."""
    from workshop.jupyter import NotebookSession
    from workshop.normalization import normalize_bindings
    from solutions.binding_exercise.mappings import MAPPINGS

    for path in sorted((ROOT / "notebooks").glob("*.ipynb")):
        session = NotebookSession(rule_file)
        try:
            if path.stem == '02_Normalize_the_logs':
                normalize_bindings(session, MAPPINGS)
            for cell in with_facilitator_answers(json.loads(path.read_text()))["cells"]:
                source = cell['source']
                if cell["cell_type"] == "code" and source.startswith("%%sql"):
                    header, sql = source.split("\n", 1)
                    session.execute(sql, save_rule="--save-rule" in header,
                                    check_binding=header.split()[-1] if '--check-binding' in header else None)
            print(f"PASS SQL {path.name}", flush=True)
        finally:
            session.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sql-only", action="store_true", help="Check SQL through NotebookSession; does not validate a Jupyter kernel")
    args = parser.parse_args()
    # One shared rule artifact across independent notebook kernels, isolated from participants.
    with tempfile.TemporaryDirectory(prefix="workshop-notebook-check-") as directory:
        os.environ["WORKSHOP_RULE_FILE"] = str(Path(directory) / "participant_rule.sql")
        os.environ["WORKSHOP_ARTIFACT_DIR"] = str(Path(directory) / "artifacts")
        if args.sql_only:
            check_sql(Path(directory) / "participant_rule.sql")
        else:
            check()


if __name__ == "__main__":
    main()
