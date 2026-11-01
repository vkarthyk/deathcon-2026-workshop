# Source-format validation: release gate

**Status: modeled exports; NOT independently verified against sanitized live exports.**
The original dataset re-identifies public Kubernetes audit seeds and models provider
delivery envelopes. The behavioral corpus uses those same envelope generators. No
real EKS/GKE/AKS exports or cloud credentials were available during this refactor.
Do not advertise these fixtures as authoritative provider specifications.

Before a public session, collect one sanitized representative export per cloud plus
its logging category, export route, cluster version, timestamp semantics and logging
configuration. Include a successful write, failed request, read and RBAC request body.
Keep credentials and customer data out of the repository.

Run the real mapper against each sample:

```bash
python3 -m workshop.validate_exports --kind gke --input /path/to/sanitized-gke.jsonl.gz \
  --provenance sanitized-real-export --logging-configuration 'describe actual settings' \
  --reviewer 'reviewer name' --out artifacts/source-validation/gke.json
```

Repeat with `--kind eks` and `--kind aks`. The accepted delivery routes are the
CloudWatch subscription envelope, Cloud Logging JSONL and Azure diagnostic records
used by this repo. A different export route needs a different adapter; do not reshape
a sample silently to make the validator pass.

The report records sample/mapper hashes and missing-field counts, without copying
payloads. It is a **structural check**, not automatic proof of semantic correctness.
Manually compare native-to-normalized identity, role subjects, account/cluster,
request time, status, resource/subresource and preserved request data. Test mapper
changes against both the legacy golden tests and behavioral regression suite.

Pay special attention to event-ID availability in real GKE exports: the modeled
dataset uses `operation.id`; do not assume it is present on every real LogEntry.
Verify a stable source-specific ID strategy and duplicate handling on your exports.

Track sign-off here, with report paths and logging configuration:

| Source | Real sample | Semantic review | Current status |
|---|---|---|---|
| EKS | Not supplied | Pending | Modeled only |
| GKE | Not supplied | Pending | Modeled only |
| AKS | Not supplied | Pending | Modeled only |

Describe blind spots in terms of the observed export and configured collection.
This repo's GKE representation omits the native request URI; that is not a verified
universal claim about all Google telemetry. Similarly, claims about default Data
Access logging or read-excluding AKS categories need current provider documentation
and actual configuration evidence before appearing in slides.
