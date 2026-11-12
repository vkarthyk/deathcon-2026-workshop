"""Generate the advanced Markdown + SQL Jupyter workshop without notebook dependencies."""
import json
from make_sql_notebooks import ROOT, notebooks, explained_statements
from jupyter_exercises import EXERCISES, EVIDENCE_REVIEW
from datagen.notebook_hints import SQL_REFERENCE, optional_hint
from datagen.binding_exercise import RAW_HEADINGS, NORMALIZED_HEADINGS, raw_hints, normalization_cells

DATASET_OVERVIEW = """## Know the datasets before querying

The workshop separates **observed activity** and **context about that activity**. A schema gives them consistent field names; it does not
invent missing logs, resolve identities automatically, or prove malicious intent.

| Dataset | What it provides | How you will use it |
|---|---|---|
| `enterprise.raw_eks`, `enterprise.raw_gke`, `enterprise.raw_aks` | Modeled provider-specific audit records, with different JSON layouts and identity formats. | Inspect source evidence and understand what each mapping must preserve. |
| `enterprise.k8s_ocsf` | All Kubernetes activity in an OCSF-derived relational table: event ID, event time, provider/account/cluster, principal, operation, resource, success status and request data. One row represents an audit event, not an incident. | Write one behavioral sequence across clouds, retaining asset scope and event order. |
| `enterprise.k8s_subjects` | Child relation with one row per request subject, keyed by provider/account/cluster/event ID. | Follow every granted subject without duplicating rows in the event table. |
| `enterprise.identities` | Curated mappings from a native `principal_name` within its `cloud_provider` and `account_uid` to a shared `person_id`. | Connect differently formatted principals belonging to the same person. A LEFT JOIN retains unmapped activity; a missing person ID limits attribution, not detection. These links are supplied enrichment, not inferred by normalization. |
| `enterprise.approvals` | Maintenance tickets scoped to the grant actor, granted subject, role, provider/account/cluster and validity interval. | Suppress an otherwise matching sequence only when the exact change is approved at the grant time. A matching identity alone is not authorization. |

**SQL relations and workflow:**

| Relation or step | What it provides | How you will use it |
|---|---|---|
| `main.workshop_alerts` | Your editable detection query, defined as a SQL view. | Modify the behavioral rule and inspect its alerts. |
| `main.alert_evidence` | Supporting event IDs as individual rows. | Retrieve the source evidence for each alert. |
| `enterprise.k8s_ocsf` | All normalized Kubernetes event types, with one row per source event and asset. Role references are projected into columns when present. | Query normalized fields without repeating provider-specific JSON extraction. |
| `enterprise.k8s_subjects` | Repeated request subjects stored separately, preserving the event table's row count. | Join subjects to their source event to follow each granted subject. |
| Ingestion preparation | Relational fields prepared through engine-specific JSON extraction and file loading. | Keep preparation separate from the normalized detection SQL. |
| Notebook 01 | Three incomplete cloud-specific binding detections. | Write the predicates and check the matching source events. |
| Notebook 02 | A ten-field contract and participant-authored SQL mappings. | Build and validate your own binding table, then write one unified detection. |
| Notebook 03 | An advanced sequence over the fuller prepared schema. | Correlate grants with subsequent secret-list activity. |

**Workshop dataset:** `enterprise.*` uses the larger synthetic enterprise day:
routine controller and service-account traffic, deployments, human operations,
failed requests and suspicious activity in modeled EKS/GKE/AKS delivery formats.
Use provider, cluster and time filters to keep investigations manageable.
The cloud envelopes are modeled, not verified against real enterprise exports.
"""

SETUP = '''from pathlib import Path
import sys
import os

root = Path.cwd().resolve()
while not (root / "workshop" / "jupyter.py").exists():
    if root == root.parent:
        raise RuntimeError("Open this notebook from the workshop checkout.")
    root = root.parent
sys.path.insert(0, str(root))
os.chdir(root)
from workshop.jupyter import NotebookSession
if "session" in globals():
    session.close()
session = NotebookSession()
get_ipython().run_line_magic("load_ext", "workshop.jupyter")
print("Ready. Run the SQL cells below with Shift+Enter.")'''


def main():
    names = list(notebooks())
    for index, (name, queries) in enumerate(notebooks().items()):
        cells = []
        def add(kind, source):
            cell = dict(cell_type=kind, id=f"cell-{len(cells):03d}", metadata={}, source=source.splitlines(True))
            if kind == "code":
                cell.update(execution_count=None, outputs=[])
            cells.append(cell)
        add("markdown", f"# {name.replace('_', ' ')}\n\nRead each explanation, then run the next cell with **Shift+Enter**. Add a code cell starting with `%%sql` for your own query. Save edits with **Ctrl+S / Cmd+S**. Tabular SQL results support sorting, search and pagination, with all returned rows available. Single-column nested results render as an expandable JSON tree. Use `%%sql --json` to inspect an entire result as JSON.\n\nSee [the participant guide](../WORKSHOP.md) for the full workshop.")
        add("markdown", "## Connect to DuckDB\n\nRun this setup once per kernel. It prepares an isolated DuckDB database with raw logs and reference relations for checking, sequence detection and investigation. Notebook 02 builds a separate participant-owned binding relation; reference ingestion does not complete that exercise for you. It also loads your saved participant rule, if present. SQL cells below run against this session; no cloud credentials or model key are required.")
        add("code", SETUP)
        add("markdown", DATASET_OVERVIEW)
        add("markdown", SQL_REFERENCE)
        if name == '03_Write_the_behavioral_rule':
            add("markdown", "## Continue with the full event schema\n\nYour notebook 02 mapping normalized binding events into `main.binding_events`. The sequence exercise also needs secret-list events, event time, request subjects and source evidence, so it uses the fuller prepared `enterprise.k8s_ocsf` and `enterprise.k8s_subjects` relations. The same mapping principles apply; your binding exercise is not a complete ingestion pipeline.")
        if name == '02_Normalize_the_logs':
            for kind, source in normalization_cells():
                add(kind, source)
        for (heading, purpose, expected, action), statement in explained_statements(name, queries):
            save = heading == "Define your SQL detection"
            note = f"## {heading}\n\n{purpose}\n\n**What to look for:** {expected}\n\n**Try this:** {action}"
            if save:
                note += "\n\nRunning this cell saves the rule to `artifacts/participant_rule.sql`. Later notebooks automatically reload that file, including when their kernels are already open. Preserve the alert key, provider/account/cluster, subject and time columns so related evidence views continue to work. Copy your rule before experiments; rerunning this original definition restores the reference."
            note += raw_hints(RAW_HEADINGS[heading]) if heading in RAW_HEADINGS else optional_hint(heading)
            add("markdown", note)
            option = '--save-rule' if save else ('--check-binding ' + RAW_HEADINGS[heading] if heading in RAW_HEADINGS else '--check-binding ' + NORMALIZED_HEADINGS[heading] if heading in NORMALIZED_HEADINGS else '')
            add("code", ("%%sql " + option).rstrip() + "\n" + statement)
        if name == '04_Investigate_alerts':
            add('markdown', EVIDENCE_REVIEW)
        for heading, explanation, code in EXERCISES.get(name, []):
            add("markdown", f"## {heading}\n\n{explanation}")
            add("code", code)
        if index + 1 < len(names):
            following = names[index + 1]
            add("markdown", f"Continue to [{following.replace('_', ' ')}]({following}.ipynb). Run its setup cell first; saved rule edits carry across notebooks.")
        else:
            add("markdown", "You have completed the core notebook workflow. Continue with the optional extra lab [05 Run the detection in batches](05_Run_the_detection_in_batches.ipynb), or review your artifacts and record the rule specification, source evidence and remaining uncertainty. See [the agent guide](../docs/agent-lab.md) for additional background.")
        document = dict(cells=cells, metadata={"kernelspec": {"display_name": "Python 3 (ipykernel)", "language": "python", "name": "python3"}, "language_info": {"name": "python", "version": "3.11"}}, nbformat=4, nbformat_minor=5)
        (ROOT / "notebooks" / f"{name}.ipynb").write_text(json.dumps(document, indent=1) + "\n")
        print(name)
    from datagen.make_scheduled_detection import main as extra_lab
    extra_lab(ROOT)


if __name__ == "__main__":
    main()
