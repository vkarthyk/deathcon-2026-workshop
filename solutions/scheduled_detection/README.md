# Facilitator guide: 05 Run the detection in batches

Use `pipeline.sql` as an answer overlay for `labs/scheduled_detection/pipeline.sql`, or pass
its path with `--pipeline`. Keep the answer and generator separate from students.

From a full repository checkout with workshop dependencies installed:

```bash
.workshop-venv/bin/python -m solutions.scheduled_detection.evaluate --pipeline solutions/scheduled_detection/pipeline.sql
.workshop-venv/bin/python -m solutions.scheduled_detection.evaluate --pipeline labs/scheduled_detection/pipeline.sql
.workshop-venv/bin/python -m unittest tests.test_scheduled_detection -v
```

The first command must pass; the starter must fail. Change `--seed` for a new private
delivery schedule. The evaluator derives expectations from scenario intent, not from
the reference SQL. It checks every committed prefix, latency, initial evidence,
duplicates, recovery and crashes on both sides of the commit. This is a teaching
grader for trusted local code, not a sandbox for hostile SQL submissions.

The reference deliberately rescans all canonical evidence for this small day. It
retains state indefinitely, supports one worker, assumes immutable source events,
and receives static approvals. Its atomic local notification outbox is not an
external exactly-once delivery implementation. Discuss state eviction, batching,
watermarks, concurrent workers, identity/approval history and idempotent external
delivery before adapting the design to production.

Debrief: ask learners to distinguish the 15-minute behavioral window, the 30-minute
lateness budget and the five-minute scheduling cadence. Ask why an older grant must
remain available for a delayed read, why a later retry cannot redefine first arrival,
and why an absent secret-list record says little without telemetry-health evidence.
The corpus includes failed and unknown outcomes, wrong assets/roles/subject kinds,
namespaced reads, approval decoys, multiple recipients and legitimate repeated IDs.
Matching behavior does not establish compromise or secret exfiltration.
