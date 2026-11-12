# Investigate an alert with source evidence

The participant workflow is in `notebooks/05_Investigate_alerts.ipynb`. Select an
alert from `main.workshop_alerts`, inspect a bounded actor/subject timeline, and run the scripted
evidence checker (no LLM calls), then verify its evidence and explain any uncertainty.

Both the scripted checker and optional AI investigator get a read-only snapshot of `enterprise.k8s_ocsf` (or raw source
tables), identity links, IP/user/cluster enrichment and approvals. It does not get
detection outputs or ground-truth labels. Guided tools scope lookups by exact
provider/account/cluster and time. Generic SQL is read-only, with bounded results.
Log contents are evidence, never instructions.

## Scripted evidence checker

Run the notebook cells, or use an installed workshop environment:

```bash
.workshop-venv/bin/python -m agent.triage \
  --split enterprise --suite --out artifacts/investigations.jsonl
```

This investigates the reference alerts in the enterprise log day. To investigate
your rule instead, copy one of its alert keys and replace `--suite` with
`--alert-key COPIED_EVENT_ID`. Choose a fresh database path with `--database` if an
older local database contains only the retired training schemas.

The default is a fixed Python sequence executing the actual tools, with no LLM calls.
`agent.triage` is the shared module: `run` without `model` selects the scripted
checker; passing `model` selects the AI investigator. Use `main.alert_evidence` to retrieve source event IDs as rows. Inspect the saved transcript's tool arguments, returned rows, claims,
severity reasons, uncertainty and follow-up queries. Do not treat a disposition
as proof of compromise, secret contents being returned, or exfiltration.

## Optional AI investigator with a local model

Install Ollama, start its server and download the model once:

```bash
ollama pull qwen3:8b
```

Set `RUN_LOCAL_MODEL=True` in the notebook, or run:

```bash
.workshop-venv/bin/python -m agent.triage --split enterprise \
  --alert-key COPIED_EVENT_ID --model qwen3:8b --provider ollama \
  --out artifacts/local-investigation.jsonl
```

Model execution can take minutes. No model is started automatically, and no paid
provider is used by these commands. Missing/invalid submissions remain incomplete.

## Compare raw and normalized evidence yourself

Notebook 05 includes a complete optional comparison after the Ollama instructions.
Set `RUN_SCHEMA_COMPARISON=True` to investigate the same grant twice with fresh
conversations, identical SQL-only tools, prompt, model and turn limit. The raw run
gets provider tables; the normalized run gets one consistent event table. Both
receive the same inventory and approvals. Guided tools are excluded because they
would hide the field translation this exercise is meant to expose.

Each run is saved to `artifacts/raw-vs-normalized.jsonl`. Compare queries, errors,
tokens and investigation time, and verify event citations yourself. The displayed
reference-event coverage is computed after the model runs, never included in the
prompt, and does not validate the assessment's reasoning. Incomplete runs and
transport failures are displayed explicitly. All-cloud and reverse-order options
are provided; allow additional time beyond the core workshop. Model loading and
run order can affect timings. Record observed differences even if neither run
succeeds or the normalized run does not perform better.

## Review the evidence

Follow the user granted access, not necessarily the actor who created the grant.
Check successful cluster-wide secret listing after the grant on the same asset
within 15 minutes. Inspect roleRef and every supported User subject in the request.

Use identity links for attribution. Use IP, user and cluster context for severity,
with explicit reasons. Only exactly scoped and valid change records authorize
suppression. The bundled enterprise day has no supplied validated change records.

For each claim, verify the cited event ID, provider/account/cluster, principal,
operation, outcome and event time. Read nearby routine activity and consider
legitimate explanations. Record uncertainties and the next query that could resolve
them. A missing read is not evidence of no access; a missing person mapping is not
a reason to drop a native-principal alert.

Internal evaluator/test modules remain available for software maintenance. They
are separate from this evidence-based participant workflow.
