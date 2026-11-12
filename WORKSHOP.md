# One Schema to Rule Them All: participant guide

Read enterprise-style Kubernetes logs, write one behavioral detection across
EKS/GKE/AKS, enrich its alerts, and investigate the evidence. OCSF is the example
schema; the same approach applies to ECS, ASIM, UDM or an internal event contract.

The behavior is a successful **cluster-admin grant followed within 15 minutes by
cluster-wide secret listing by the granted subject**. The actor granting access
can be different from its subject. Preserve provider, account, cluster, outcome,
event time and request details. A secret-list request does not prove exfiltration.

## Start

```bash
./setup.sh
```

Setup installs dependencies into `.workshop-venv` and opens
`notebooks/00_Start_here.ipynb` in JupyterLab. Use the printed token URL and keep
the terminal open. Python 3.10+, macOS/Linux or Windows (PowerShell/WSL2), and package-index
access for initial installation are required. Use `./setup.sh --port 8889` if needed.
The optional native SQL UI uses `./setup.sh --duckdb-ui` on port 4213.

Windows users: follow [Windows setup](docs/windows-setup.md). Use `setup.ps1` in PowerShell inside an existing Windows VM; WSL2 is an alternative on your host.

Run each notebook's setup cell, then read the explanation and run the following
SQL cell with **Shift+Enter**. Each setup prepares an isolated database; initial
normalization of the larger log day can take tens of seconds. Use `%%sql` for your
own query, one statement per cell. Nested source JSON renders as an expandable
tree; `%%sql --json` requests JSON for other results. Tabular SQL results support
sorting, search and pagination, with 25 rows per page and all returned rows available.
Use SQL filters or LIMIT to keep large results manageable. Table assets are bundled
for offline use; trust notebooks you created here if Jupyter blocks interactive output.
Save notebook edits with Ctrl+S / Cmd+S.

Each section keeps one query, with a short `TODO` comment tied to its **Try this**
task. Modify the query when asked, or record an observation for discussion tasks.
The SQL quick reference explains single-quoted strings and JSON extraction;
collapsed **Need a hint?** sections offer a syntax clue without a completed query.
Raw detection and mapping edits are saved in their notebooks. Only the `--save-rule` cell persists the later behavioral detection across kernels; notebook 02 mapping tables are session-local.

Notebook 03's `%%sql --save-rule` cell saves `artifacts/participant_rule.sql`.
Later notebooks reload it automatically. Other SQL objects are session-local.
Rerun setup after restarting a kernel. Keep an unmodified rule copy before editing.
If a saved artifact still defines the retired table macro, rename it to keep a copy,
rerun notebook 03 setup, and save the new view definition.

## Workshop flow

| Notebook | Activity | Approximate time |
|---|---|---|
| 00 Start here | Explore the log day and alert evidence | 5 minutes |
| 01 Cloud specific detections | Complete and check cluster-admin binding-attempt detections in EKS, GKE and AKS | 15 minutes |
| 02 Normalize the logs | Map and validate four fields per cloud, write one unified rule, then update it to success-only | 20 minutes |
| 03 Write the behavioral rule | Follow the granted subject using exact asset scope and event order | 10 minutes |
| 04 Investigate alerts | Verify source evidence and record uncertainty | 10 minutes |
| 05 Detect service account deviations (extra) | Map three cloud control-plane logs and flag new service-account behavior | 60 minutes |

This core path totals one hour. Open the collapsed hints early if a TODO takes
more than a minute. Leave deeper investigations and the optional local model for
after the timed workshop. Keep queries scoped to an asset and a short time window.

## Dataset and enrichment

The `enterprise` schema uses the bundled larger synthetic enterprise day, with
routine controller and service-account traffic, deployments, human operations,
failed requests and suspicious activity mixed together. Use provider, cluster and
time filters to keep queries easy to follow. This replaces the small controlled
cases in the participant workflow; it does not generate a new production log export.

The provider envelopes are **modeled, not independently validated against real
exports**. Identities, addresses, organization names and enrichment are synthetic.
See [source-validation.md](docs/source-validation.md) for the validation limits.

| Dataset | Use |
|---|---|
| `enterprise.raw_eks`, `raw_gke`, `raw_aks` | Provider-specific source evidence |
| `enterprise.k8s_ocsf` | All normalized Kubernetes events, one row per source event and asset, with role fields when present |
| `enterprise.k8s_subjects` | Repeated request subjects keyed to their source event and asset |
| `enterprise.identities` | Scoped native-principal-to-person links |
| `enterprise.ip_enrichment` | ASN, location, risk, threats and infrastructure context |
| `enterprise.user_enrichment` | HR/IdP user, department, employment and administrative context |
| `enterprise.k8s_cluster_enrichment` | Cluster environment, sensitivity and owner |
| `enterprise.approvals` | Exact actor/subject/role/asset/time-scoped change evidence |

Inventory is incomplete. City/region or an IP lookup can be missing; a missing
lookup is not a safe address. No validated change records were supplied for this
log day, so `approvals` starts empty rather than inventing authorization.
The participant database does not load regression case suites or evaluation labels.

`main.workshop_alerts` is your editable detection view. Select from it with
ordinary SQL. `main.alert_evidence` represents supporting events as rows.
Supporting inventory remains available to the scripted evidence checker; there is no separate enrichment module.

The teaching queries use regular SQL views, CTEs, joins, CASE expressions, explicit
GROUP BY columns and standard interval/cast syntax. DuckDB remains the local runner;
file readers, nested OCSF extraction and JSON subject expansion live in ingestion.
Notebook 01 ends with three participant-authored raw detections. Notebook 02 exposes
provider-specific extraction in SQL expressions inside Python dictionaries, then
compiles those into a shared relation. Its final detection uses only shared columns.
Other engines need an equivalent ingestion adapter and may differ in view DDL or
timestamp handling. No table-name strings, table macros or list/lambda functions
are needed in the workshop queries.

## Read logs and write the rule

In notebook 01, inspect three source envelopes and replace the `__TODO_...__`
predicate tokens in the raw detections. `%%sql --check-binding eks` (or `gke`/`aks`)
checks the matching event IDs, full asset keys, actor and role, plus visible
practice records for failed requests and other edge cases. Incomplete queries
fail with a clear message; empty results do not pass. Field-by-field hints cover
JSON extraction and exact role kind/name. These raw rules deliberately include
failed and unknown-outcome attempts; a match does not prove access was granted.
Notebook 01 ends here.

In notebook 02, first propose the fields needed for the same detection. Then fill
four SQL expressions per provider in a supplied ten-field mapping contract:
operation, resource, normalized outcome and referenced role. Event/asset identity,
actor and role kind are supplied to keep the exercise short. EKS expressions can
be reused for AKS; the Azure asset keys still need their supplied canonicalization.
The helper normalizes all binding events (including failures and other roles),
shows the generated SQL and validates source-key coverage and field values.
The separate `main.binding_probe_*` practice records exercise missing bodies/status,
failed requests, wrong role kinds/names and other operations/resources. They are not
added to the log-day output table.
It publishes `main.binding_events` only after all providers pass. There is no
reference-data fallback when a mapping fails. Rerun the mapping cells and helper
after restarting this notebook's kernel.

End notebook 02 by filling the four target values in one simple normalized rule.
`%%sql --check-binding normalized` checks the same raw attempts using your relation. Neither exercise filters by
outcome, so a match does not prove that access was granted.

Finish notebook 02 with a small requirements change: now keep successful attempts
only. Add one `status_id = 1` predicate to the unified rule and run
`%%sql --check-binding normalized-success`. Its hints contrast this one change
with separate HTTP-code conditions in EKS/AKS and a gRPC-status condition in GKE.
The visible practice-match count drops from 9 to 4 even if the log-day count is
unchanged. Provider mappings stay the same; their normalized outcomes make the
rule update shared across clouds.
This flags a powerful access change for review; it does not prove compromise.

The minimal binding contract is separate from the full prepared ingestion used
in notebook 03 for sequence detection. That later exercise also needs event time,
secret-list events, repeated subjects and source evidence. This boundary keeps
normalization hands-on without requiring a complete production ingestion adapter.
Facilitator answers live in `solutions/binding_exercise/` and
`detection/simple_cluster_admin/`; they are not loaded into participant TODO cells.
The Python mapping exercise runs in Jupyter; SQL companion files alone cannot run
its Python steps.

Ingestion keeps all event types in `enterprise.k8s_ocsf` and expands repeated
request subjects into `enterprise.k8s_subjects`. The
advanced rule in notebook 03 uses only normalized fields: it selects supported User subjects in successful cluster-admin grants, follows
that subject's subsequent successful cluster-wide secret listing, and requires
the same provider/account/cluster within an inclusive 15-minute window.

```sql
-- Inspect the detected grant-to-secret-list sequences, one row per grant and subject.
-- The times and source grant key connect each match to its supporting evidence.
SELECT * FROM main.workshop_alerts;
```

The `alert_key` is the source grant event ID. A grant can have multiple subjects,
so it is not a unique primary key for an alert row; use the asset scope and subject
alongside it.

Inspect a match's `alert_key`, `grant_actor`, `subject`, `grant_time`, `first_read`
and `read_events`. Retrieve the supporting source events as rows:

```sql
-- Retrieve the grant and secret-list events supporting the selected source grant key.
-- Sort by event time to review the sequence; asset and subject columns retain scope.
SELECT * FROM main.alert_evidence
WHERE alert_key = 'COPIED_EVENT_ID'
ORDER BY time;
```

Keep the `alert_key`, provider/account/cluster, subject, role, grant actor and sequence
times in custom rule output so evidence views can join correctly.

## Investigate evidence

Notebook 04 shows a bounded actor/subject timeline around an alert. Select an alert
from your rule and run the scripted evidence checker (no LLM calls), then inspect every tool request,
returned row and claimed event ID. Its verdict is a hypothesis, not a scored answer.

Record the observed behavior, identity attribution, severity reasons, plausible
benign explanations, remaining uncertainty and next evidence to retrieve. Missing
identity limits attribution; missing logs prevent strong negative conclusions.

Optional local inference uses Ollama with `qwen3:8b`. Install/download separately,
then set `RUN_LOCAL_MODEL=True`; no paid provider or model is started by setup.
See [agent-lab.md](docs/agent-lab.md). Save transcripts and notes in `artifacts/`.

Notebook 04 also includes a self-guided raw-versus-normalized AI comparison. After
installing Ollama, enable `RUN_SCHEMA_COMPARISON` to run one matched pair with
identical SQL-only tools, model, prompt and turn limit. Inspect query traces and
reference-event coverage before comparing effort. Use `COMPARE_ALL_CLOUDS` for
one pair per provider, or `NORMALIZED_FIRST` to reverse the order. This optional
extension can exceed the one-hour core path; its measured results are not a
guaranteed normalization speedup.

## Take home

Save your SQL, its intended behavior and supported operations, entity/time keys,
required evidence, approval criteria and one evidence-backed
investigation. Note incomplete inventory and unsupported operations such as
Group/ServiceAccount subjects and namespaced RoleBindings.

Production use requires validation against real exports, freshness/history handling,
a scheduler and operational review. The older `tutorials/` notebooks remain optional.

## Facilitator checks

```bash
.workshop-venv/bin/python -m unittest discover -s tests -v
.workshop-venv/bin/python datagen/check_sql_workshop.py
.workshop-venv/bin/python datagen/check_tutorials.py
```

Automated software tests keep their small controlled inputs internal. They are not
loaded into the participant database or assigned as workshop tasks.
To regenerate notebook sources, run `datagen/make_sql_notebooks.py` and
`datagen/make_jupyter_notebooks.py`. Regeneration replaces notebook files; copy
participant edits first. Saved rule artifacts remain separate.

## Troubleshooting

Use the printed Jupyter token URL if the browser is blank. Keep the launcher alive.
For missing dependencies, check your approved package index/proxy. For a locked
DuckDB file, stop the process using it or choose another database path. If an edited
rule is missing, run notebook 03's save-rule cell and check the saved artifact.


For a 60-minute extension after notebooks 01–04, open
[`notebooks/05_Detect_service_account_deviations.ipynb`](notebooks/05_Detect_service_account_deviations.ipynb). Its Markdown cells contain the brief, steps and hints. Map AWS CloudTrail, GCP Cloud Audit
and Azure Activity logs to one contract, build a per-service-account baseline and
flag new actions, networks and clients. This extension is separate from the one-hour core path.

## Practice with the CTF

Try [Find the admin grant](ctf/easy/README.md) after notebooks 01–02, and
[Follow the recipient](ctf/hard/README.md) after notebooks 03–04. Both can also be
attempted before the workshop; progressive hints point back to the relevant
lessons. These are separate synthetic cases, not copies of the workshop answers.
See [ctf/README.md](ctf/README.md) to build and open the standalone challenges.
