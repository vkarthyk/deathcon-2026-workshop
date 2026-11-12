# 05 Detect service account deviations

**Extra lab · about 60 minutes · after notebooks 01–04**

Notebooks 01–04 applied one schema to one Kubernetes behavior. This lab tests whether
the method transfers to a different log source and a different kind of detection.
You map AWS CloudTrail, GCP Cloud Audit Logs and Azure Activity Log records to one
contract, learn what each service account normally does, and flag what it has never
done before. The detection follows the "Service Account Activity Baseline Deviation"
example in [Multi-Cloud Detection at Scale](https://cloudnativedetection.substack.com/p/multi-cloud-detection-at-scale-a).

Everything runs locally on synthetic logs. No cloud access, credentials or model is needed.

Open [`05_Detect_service_account_deviations.ipynb`](../05_Detect_service_account_deviations.ipynb)
in the workshop JupyterLab session, or run from the repository root:

```bash
.workshop-venv/bin/python -m workshop.service_account_baseline --database artifacts/sa_baseline.duckdb
```

On Windows use `.\.workshop-venv\Scripts\python.exe`. Do not name the database file
`raw`, `ref`, `lab` or `sa`; DuckDB would confuse it with a lab schema.

## The brief

Service accounts are predictable: the same job calls the same APIs from the same
place with the same client every day. That makes "never done this before" a useful
signal when a credential is stolen. The data covers a 14-day learning window
(29 October to 11 November 2026) and one detection day (12 November). Your rule
reports, for each service account in each account or project, every action, source
network or client it used on the detection day that it never used in the learning
window.

Only edit `labs/service_account_baseline/detection.sql`. Keep its view names and columns.

## 1. Read the raw records — 10 minutes

Compare one `backup-agent` record from each cloud. For each, find the caller, the
account, the operation, the source address, the client and the outcome. Then read
the AWS adapter in `detection.sql`; it is a complete worked example. Notice:

- An AWS role session ARN changes with every session. The **issuing role ARN** is
  the stable identity.
- People also use roles in AWS, through IAM Identity Center (`AWSReservedSSO_*`).
  Those are humans.
- When an AWS service acts with the caller's credentials, the source address is a
  service name such as `cloudformation.amazonaws.com`, not an IP.

## 2. Map GCP and Azure — 15 minutes

Complete the `TODO` expressions in `sa.gcp_events` and `sa.azure_events`.

| Column | GCP | Azure |
|---|---|---|
| `account_uid` | Project ID in the monitored resource labels | Subscription ID inside `resourceId` |
| `principal` | Authenticated principal email | `identity.claims.appid` when `idtyp = 'app'`, otherwise `caller` |
| `principal_type` | `service_account` if the email ends in `.gserviceaccount.com` | `service_account` if `idtyp = 'app'` |
| `source_ip` | `callerIp`, or NULL if it is not an IPv4 address (for example `private`) | `callerIpAddress`, same rule |
| `user_agent` | `callerSuppliedUserAgent` | Not recorded: NULL |
| `status_id` | 1 when `status.code` is missing or 0, else 2 | `Success` 1, `Failure` 2, `Start` 0 |

Run `lab.run(detection)` then `lab.quality()`. You are done when every provider has
zero missing principals, accounts and statuses, and no invalid principal types.
The supplied `sa.events` view joins `ref.action_catalog`, which translates raw
operations such as `GetSecretValue` and `AccessSecretVersion` into one shared
`action_type`, here `secret-read`.

## 3. Fix the baseline rule — 20 minutes

The starter is the simple version: compare exact values with a baseline keyed by
principal. It runs, and it is wrong. Inspect `sa.deviations`, then fix it so that:

1. **Only successful service-account calls count**, in both the baseline and the
   detection day. Failed calls and Azure `Start` events are not behavior the
   account completed.
2. **The baseline is scoped to provider, account and principal.** In GCP and Azure,
   one service account can act in several projects or subscriptions with different
   duties. Reading secrets may be normal in one and new in another.
3. **Actions missing from the catalog still count.** Use the raw `cloud_api_action`
   when `action_type` is NULL. Unknown operations must not disappear.
4. **Networks, not hosts.** Compare IPv4 sources as `/24` networks, written as
   `a.b.c.0/24`. NAT gateways and CI runners rotate hosts within a range.
5. **Client family, not version.** Compare user agents as the lower-case text before
   the first `/`, trimmed: `Terraform/1.10.0 (...)` becomes `terraform`.
6. **Missing values are not deviations.** Compare only non-NULL sources and clients.
7. **Insufficient history is reported separately.** A principal with fewer than
   `min_baseline_days` (7) distinct active days in the learning window belongs in
   `sa.insufficient_baseline` with its `baseline_days` and detection-day event
   count, and nowhere in `sa.deviations`.

Each row of `sa.deviations` is one new value for one principal, with `first_seen`,
`last_seen`, `event_count` (successful detection-day events with that value) and a
`sample_event_id`.

## 4. Triage — 10 minutes

For each principal with deviations, decide whether it looks like credential misuse,
a legitimate change, or unknown, and say what evidence you used. Then find the
attack this rule cannot see. Hint: compare detection-day volume with the baseline.
What other signals would reveal it?

## Practice targets

With the practice data, a correct solution reports:

- **17 deviations**: 6 AWS, 6 GCP and 5 Azure (12 actions, 3 networks, 2 clients).
  Azure has no user agents, so it has one fewer.
- **3 principals with insufficient history**, one per cloud, each with 2 baseline days.
- `lab.quality()` shows AWS 233 rows (222 service account), GCP 226 (215) and
  Azure 448 (426), with Azure's 224 `Start` events as status 0.

The organizer grades with a different data set, so follow the rules above instead
of tuning to these counts.

## Submit and debrief

Submit `detection.sql` and a short note covering your identity choices for each
cloud, one false positive you removed and how, one deviation you consider benign
and why, and the blind spot. Discuss before production use: how long the learning
window should be, how to keep an attacker from becoming part of the baseline, how
to handle IPv6 and cloud-provider address ranges, and who reviews new accounts.

A deviation is a reason to investigate, not proof of compromise.
