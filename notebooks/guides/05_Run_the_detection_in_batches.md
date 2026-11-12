# 05 Run the detection in batches

**Advanced · 60–90 minutes · after notebooks 03–04**

Your cluster-admin → secret-list rule works against a complete log day. In scheduled
execution it misses sequences and repeatedly notifies on others. Repair the pipeline
without weakening the detection. Everything runs locally on synthetic audit data;
no cloud access, credentials, LLM or offensive activity is required.

Use the workshop environment created by `./setup.sh` (Windows: `setup.ps1`). Open
[`05_Run_the_detection_in_batches.ipynb`](../05_Run_the_detection_in_batches.ipynb) in the existing JupyterLab session, or run the commands
below **from the repository root**. On Windows replace
`.workshop-venv/bin/python` with `.\.workshop-venv\Scripts\python.exe`.

For CLI-only use, an installed `duckdb` executable on PATH is sufficient alongside
Python's standard library: replace `.workshop-venv/bin/python` with `python3`.
The notebook interface still requires Jupyter. The runner uses the repository's
existing adapter and supports either the native CLI or the Python DuckDB engine.

## The incident brief

A grant occurs at 10:00. Its recipient lists secrets at 10:07. The grant arrives at
10:22. When the scheduler next runs at 10:25, a query restricted to the last
15 minutes of event time misses the grant. Widening the behavioral window would
change what the rule means; fix how evidence is reconsidered instead.

The scheduler runs every five simulated minutes. You must detect the original
behavior: a successful cluster-admin ClusterRoleBinding create for a User, then a
successful cluster-wide secret list by that recipient within 15 minutes inclusive,
on the same provider/account/cluster, without an exactly scoped valid approval.
The runner inserts the existing rule at `{{DETECTION_SQL}}`; keep that marker.
Only edit `pipeline.sql`. Do not change the rule, schedule, runner or supplied data.

## 1. Reproduce the failure — 10 minutes

```bash
.workshop-venv/bin/python -m workshop.scheduled_detection --database artifacts/scheduled_detection-baseline.duckdb
```

Inspect the report and database with DuckDB or the notebook. The starter runs to
completion but is intentionally incorrect. Compare early and late batches and find
one missed sequence and one duplicated notification. Explain each using source
event time, ingestion time and scheduler time.

`practice.json` is the complete delivery schedule for inspection, **not** a table
available to the rule. At each step the database contains only deliveries and
collector observations received so far. Retries may carry a new delivery ID or
repeat an existing delivery ID. A source event's content is immutable in this lab;
conflicting event revisions are outside scope.

## 2. Repair evidence handling — 20 minutes

Edit `pipeline.sql` and replay against a **new database filename** after each change.
Reusing a database resumes its committed progress and retains prior notifications;
it does not rerun completed batches or undo a flawed pipeline's previous output.

- Deduplicate on `(provider, account_uid, cluster_name, event_id)`, not delivery ID
  or event ID alone. Keep all grant subjects.
- Support first-arrival lateness of **30 minutes inclusive**, measured as
  `ingested_at - time`. A later retry must not make an on-time event late.
- Reconsider older evidence when a new event arrives. A late read can need an older
  grant; a late grant can need a read already in the cache.
- Preserve the original 15-minute behavioral window and all scope, outcome and
  approval conditions. Missing identity mappings must not remove matches.

The lab day is small: retaining and rescanning its canonical event cache is an
acceptable solution. An incremental solution is welcome if it produces equivalent
results. Explain how you would bound retention and scan cost before production use.

## 3. Repair notification state and survive a restart — 15 minutes

The full alert key is `(provider, account_uid, cluster_name, alert_key, subject)`.
A grant can alert for two recipients. Persist one initial notification per key in
`notifications`. Deduplicating source events alone does not prevent repeated alerts.

Try a new database with an injected failure:

```bash
.workshop-venv/bin/python -m workshop.scheduled_detection --database artifacts/scheduled_detection-crash.duckdb --crash before_commit --crash-batch 3
.workshop-venv/bin/python -m workshop.scheduled_detection --database artifacts/scheduled_detection-crash.duckdb
```

The first command intentionally exits with `SimulatedCrash`. The second resumes.
Repeat with `after_commit` and another fresh database. The result should match an
uninterrupted run. The runner commits ingestion, SQL changes, local outbox and
progress atomically. Keep transaction control in the runner.

Here a committed outbox row counts as a notification. A real external sender would
also need idempotent delivery; a database transaction alone cannot guarantee that.

## 4. Handle late evidence and visibility — 15 minutes

Publish `main.recovery_queue` with one row per canonical event beyond the lateness
bound, including its full scoped event key, `time` and `ingested_at`. Retain this
evidence. It must not silently disappear or generate an automatic online alert.
When `clock.recover` is true, explicitly reconsider retained late evidence:

```bash
.workshop-venv/bin/python -m workshop.scheduled_detection --database artifacts/scheduled_detection-fixed.duckdb --recover
```

Publish `main.coverage_state` from the latest `collector_health` observation for
each asset/stream. Insert one warning per stalled interval in `coverage_warnings`,
identified by asset, stream and `gap_since`. Healthy observations resolve the current
state without erasing historical warnings. A stream with no supplied health record
has **unknown** health. Lack of secret-list matches is not proof of either an outage
or safety. Use explicit collector observations to support a coverage warning.

## Tables and interfaces

| Relation | Contract |
|---|---|
| `deliveries` | Append-only deliveries: `delivery_id`, `event_id`, provider/account/cluster, `time`, `ingested_at`, principal, operation, resource_type, status_id, namespace, role_kind, role, subjects JSON |
| `clock` | One row: simulated `now`, operator-controlled `recover` flag |
| `replay.k8s_ocsf` | Your canonical event view; keep original field names and all evidence required by the rule |
| `replay.k8s_subjects` | Supplied subject-expansion adapter; update only as needed for your canonical view |
| `replay.approvals`, `replay.identities` | Static exact-scope approvals and optional attribution; identities intentionally empty |
| `collector_health` | Asset, `stream`, `observed_at`, `status` (`healthy`/`stalled`), `gap_since` |
| `notifications` | Asset, `alert_key`, `subject`, `first_read`, `read_events`, `notified_at`; persist the initial evidence summary |
| `coverage_warnings` | Asset, stream, gap_since, notified_at; historical warning outbox |
| `progress` | Harness-owned committed next batch; do not edit |

`status_id`: 0 unknown, 1 success, 2 failure. All times are UTC. Every alert and
warning timestamp must reflect the batch that emitted it, using `clock.now`.

## Submit and debrief — 10 minutes

Submit your pipeline and a short incident note explaining: the missed sequence,
the duplicate notification, your lateness and recovery policy, visibility limits,
and how state and notification delivery would work in production.

Practice acceptance targets: **27** distinct initial notifications, **3** historical
coverage warnings, **3** canonical beyond-bound events queued for recovery, and
**30** total notifications after backfill. Repeating backfill adds none. Counts alone
are insufficient: verify scoped keys, evidence and notification times. A supported
sequence must alert on the first scheduled run when both required events are available.

The organizer evaluates a different schedule and both crash points. Matching one
final snapshot is insufficient. Use [hints](../../labs/scheduled_detection/HINTS.md) progressively.
