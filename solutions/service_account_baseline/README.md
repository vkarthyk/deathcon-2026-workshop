# Facilitator guide: 04 Detect service account deviations

`detection.sql` is the reference answer for `labs/service_account_baseline/detection.sql`.
Keep it, the evaluator and the generator away from students.

From a full repository checkout with workshop dependencies installed:

```bash
.workshop-venv/bin/python -m solutions.service_account_baseline.evaluate --sql solutions/service_account_baseline/detection.sql
.workshop-venv/bin/python -m solutions.service_account_baseline.evaluate --sql labs/service_account_baseline/detection.sql
.workshop-venv/bin/python -m unittest tests.test_service_account_baseline -v
```

The first command must pass and the starter must fail. Change `--seed` for a new
private data set: account IDs, application IDs, addresses, volumes and times change;
the scenarios stay the same. The evaluator derives expectations from scenario
intent, not from the reference SQL. It checks per-provider mapping counts, the set
of service-account identities, every deviation key with its `first_seen` and
`event_count`, and the insufficient-history list. It is a teaching grader for
trusted local SQL, not a sandbox.

## Scenarios (each cloud)

| Principal | Detection day | Correct outcome |
|---|---|---|
| `backup-agent` | Stolen credential: new /24, `python-requests`, secret reads, a key creation, an operation missing from the catalog, one failed user creation | 5 deviations (4 on Azure, which has no user agents); the failure is not one |
| `backup-agent`, second account | Normal; secret reads are routine here | None. Masks the first row if the baseline ignores the account (GCP, Azure) |
| `ci-deployer` | Legitimate new action; new NAT hosts in the same /24; Terraform 1.9 → 1.10; on AWS, CloudFormation calls with a service-name source | 1 deviation (`compute-modify`), benign on triage |
| `monitoring` | Stolen token used exactly like the baseline, at higher volume; on GCP some `private` sources | None. This is the deliberate blind spot |
| `data-export` | Created two days earlier | Insufficient history, not deviations |
| `alice` | A human doing something new | Out of scope |

Starter flaws, each caught by the evaluator: no success filter, baseline keyed by
principal only, unmapped actions become NULL, exact hosts, full user agents, NULL
values compared, and new principals alerting instead of being listed separately.

## Debrief

- Which deviations were benign, and what would you need to auto-close them
  (change tickets, deploy pipeline identity)?
- The monitoring token misuse is invisible to a "never seen" rule. Volume baselines,
  token-age and session-origin signals, or data-access logs would be needed.
- A credential stolen during the learning window becomes part of the baseline.
  Discuss baseline review, shorter windows and alert-on-first-use for sensitive actions.
- /24 and client-family choices trade noise for blind spots. An attacker inside the
  same NAT range or using Terraform would not stand out.
- Azure Activity Log has no user agent, so one dimension is unavailable for a third
  of the estate. Missing evidence limits conclusions in both directions.

The reference keeps all history and rescans it. Production needs a retained,
incrementally updated baseline table, IPv6 handling and an owner for new accounts.
