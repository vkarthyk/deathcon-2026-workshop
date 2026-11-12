# Progressive hints

<details><summary>1. Which time controls which decision?</summary>

Event time controls whether grant and read are within 15 minutes. Ingestion time
controls when the runner can see them. Processing time controls when it can notify.
Try stepping through one batch at a time and querying all three.
</details>

<details><summary>2. What survives between runs?</summary>

The deliveries table is durable. Build a canonical relation using the earliest
ingestion per full scoped event key before applying the lateness policy. In this
small lab, you can rerun the shared rule against the entire admissible cache.
Use ROW_NUMBER with a complete partition key and deterministic ordering.
</details>

<details><summary>3. Why do notifications still repeat?</summary>

A correct canonical event cache does not deduplicate alert emission. Compare each
candidate's full grant-and-subject key with the persisted notification outbox.
The runner's transaction includes that insertion and progress advancement.
</details>

<details><summary>4. What if the event is too late or the collector stops?</summary>

Make a separate view of canonical beyond-bound events; include them only during
explicit recovery. For health, rank observations per asset and stream by observation
time. Current state and historical warnings serve different purposes. A warning's
identity includes gap_since, so repeated stalled observations don't renotify.
</details>
