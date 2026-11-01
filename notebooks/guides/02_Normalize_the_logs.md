# 02 Normalize the logs

Read each explanation, then run the following SQL. In DuckDB UI these explanations are comment-only cells; this file renders them as Markdown.

## SQL quick reference

Run each query, then use its `TODO` comment and **Try this** task to explore.
Single quotes delimit text; double quotes identify SQL columns, not strings.

| Task | Example |
|---|---|
| Match text exactly | `resource_type = 'clusterrolebindings'` |
| Extract text from raw JSON | `json_extract_string(event, '$.requestURI')` |
| Match part of a string | `LIKE '%clusterrolebinding%'` |
| Find a missing value | `person_id IS NULL` |
| Limit returned rows | `LIMIT 10` |
| Filter event time | `time >= TIMESTAMPTZ '2026-10-14 14:00:00+00'` |

Raw-source queries use JSON paths. Normalized queries use ordinary columns such as
`resource_type`, `principal` and `time`. Each SQL cell runs one statement.
Open **Need a hint?** only when you get stuck. An empty result can be valid after changing filters.

## Design the shared contract — 2 minutes

**Before opening the mapping hints:** which fields must survive normalization to detect a
cluster-admin binding attempt? Which fields identify the event and its asset?

**Your schema choices and why:** TODO — record your proposed fields here.

For this timed exercise, implement the ten-field contract below. It is a small,
OCSF-derived relational contract, not a complete OCSF event. You choose the SQL
expressions that populate it; the field names/types keep validation and the final
query shared across the room.

| Field | Type | Meaning |
|---|---|---|
| `event_id` | `VARCHAR` | Source audit-event identifier; never a generated row number. |
| `provider` | `VARCHAR` | AWS, GCP or Azure (supplied by the helper). |
| `account_uid` | `VARCHAR` | Native account/project/subscription ID, canonicalized for joins. |
| `cluster_name` | `VARCHAR` | Cluster name within provider/account scope. |
| `principal` | `VARCHAR` | Native actor who performed the operation, not an inferred person. |
| `operation` | `VARCHAR` | Kubernetes verb, such as create or list. |
| `resource_type` | `VARCHAR` | Kubernetes resource collection, such as clusterrolebindings. |
| `status_id` | `INTEGER` | 1 = success, 2 = failure, 0 = unknown. A normalized outcome, not a copied HTTP code. |
| `role_kind` | `VARCHAR` | Referenced role kind; nullable when the body is absent. |
| `role` | `VARCHAR` | Referenced role name; nullable when the body is absent. |

The checker also uses visible, separately named `main.binding_probe_eks`,
`main.binding_probe_gke` and `main.binding_probe_aks` practice records. These cover
failed outcomes, wrong roles/kinds, other operations/resources and missing bodies/status.
They test semantics even when the log day lacks a particular case; they are never
inserted into your log-day table.

The helper reads **all binding events**, including failures, other roles and events
without request bodies. It supplies the binding-only source filter and provider label,
casts the fields and collapses identical audit deliveries. Mapping is not detection:
do not filter to successful cluster-admin grants or hard-code their values.

Notebook 03 uses the fuller prepared `enterprise.k8s_ocsf` and `enterprise.k8s_subjects`
relations for sequence detection. Your `main.binding_events` stays separate; this
exercise does not silently replace it with the prepared table.


## Map EKS — 3 minutes

Replace the four `None` values with **Python strings containing SQL expressions**.
The supplied entries handle event identity, asset scope, actor and role kind.
Copy the `json_extract_string` pattern when you need another JSON field. Missing
request bodies should produce NULL role values; do not invent their contents.

<details>
<summary>Hints for each mapping TODO</summary>

- **operation:** extract `$.verb` from `event` as text.
- **resource_type:** extract `$.objectRef.resource` from `event` as text.
- **status_id:** paste this Python string as the mapping value (keep the outer double quotes):
  ```python
  "CASE WHEN json_extract_string(event, '$.responseStatus.code') IS NULL THEN 0 WHEN CAST(json_extract_string(event, '$.responseStatus.code') AS INTEGER) BETWEEN 200 AND 299 THEN 1 ELSE 2 END"
  ```
  This maps a missing code to **0 (unknown)**, HTTP 200–299 to **1 (success)**, and every other code to **2 (failure)**.
- **role:** extract `$.requestObject.roleRef.name` from `event` as text.

Python's double-quoted string can contain SQL's single-quoted JSON path, e.g.
`"json_extract_string(event, '$.verb')"`. A Python `None` marks unfinished work;
SQL NULL may still be a valid result for an individual log record.

</details>

```python
eks_mapping = {
    'event_id': "json_extract_string(event, '$.auditID')",
    'account_uid': 'aws_account',
    'cluster_name': "regexp_extract(log_group, '^/aws/eks/([^/]+)/', 1)",
    'principal': "json_extract_string(event, '$.user.username')",
    'operation': None,  # TODO: SQL expression; see the hint for operation
    'resource_type': None,  # TODO: SQL expression; see the hint for resource_type
    'status_id': None,  # TODO: SQL expression; see the hint for status_id
    'role_kind': "json_extract_string(event, '$.requestObject.roleRef.kind')",
    'role': None,  # TODO: SQL expression; see the hint for role
}
```

## Map GKE — 3 minutes

Replace the four `None` values with **Python strings containing SQL expressions**.
The supplied entries handle event identity, asset scope, actor and role kind.
Copy the `json_extract_string` pattern when you need another JSON field. Missing
request bodies should produce NULL role values; do not invent their contents.

<details>
<summary>Hints for each mapping TODO</summary>

- **operation:** take the last segment of methodName: `split_part(json_extract_string(entry, '$.protoPayload.methodName'), '.', -1)`.
- **resource_type:** for the binding-only input, the preceding segment is the resource; use `split_part(..., '.', -2)`.
- **status_id:** `CASE WHEN COALESCE(CAST(json_extract_string(entry, '$.protoPayload.status.code') AS INTEGER), 0) = 0 THEN 1 ELSE 2 END`. An absent gRPC status means success in this modeled source.
- **role:** extract `$.protoPayload.request.roleRef.name` from `entry`.

Python's double-quoted string can contain SQL's single-quoted JSON path, e.g.
`"json_extract_string(event, '$.verb')"`. A Python `None` marks unfinished work;
SQL NULL may still be a valid result for an individual log record.

</details>

```python
gke_mapping = {
    'event_id': "json_extract_string(entry, '$.operation.id')",
    'account_uid': "json_extract_string(entry, '$.resource.labels.project_id')",
    'cluster_name': "json_extract_string(entry, '$.resource.labels.cluster_name')",
    'principal': "json_extract_string(entry, '$.protoPayload.authenticationInfo.principalEmail')",
    'operation': None,  # TODO: SQL expression; see the hint for operation
    'resource_type': None,  # TODO: SQL expression; see the hint for resource_type
    'status_id': None,  # TODO: SQL expression; see the hint for status_id
    'role_kind': "json_extract_string(entry, '$.protoPayload.request.roleRef.kind')",
    'role': None,  # TODO: SQL expression; see the hint for role
}
```

## Map AKS — 3 minutes

Replace the four `None` values with **Python strings containing SQL expressions**.
The supplied entries handle event identity, asset scope, actor and role kind.
Copy the `json_extract_string` pattern when you need another JSON field. Missing
request bodies should produce NULL role values; do not invent their contents.

<details>
<summary>Hints for each mapping TODO</summary>

- **operation:** extract `$.verb` from `event` as text.
- **resource_type:** extract `$.objectRef.resource` from `event` as text.
- **status_id:** paste this Python string as the mapping value (keep the outer double quotes):
  ```python
  "CASE WHEN json_extract_string(event, '$.responseStatus.code') IS NULL THEN 0 WHEN CAST(json_extract_string(event, '$.responseStatus.code') AS INTEGER) BETWEEN 200 AND 299 THEN 1 ELSE 2 END"
  ```
  This maps a missing code to **0 (unknown)**, HTTP 200–299 to **1 (success)**, and every other code to **2 (failure)**.
- **role:** extract `$.requestObject.roleRef.name` from `event` as text.
- EKS and AKS share these Kubernetes paths. Reuse the four expressions, while retaining the supplied Azure asset-key canonicalization.

Python's double-quoted string can contain SQL's single-quoted JSON path, e.g.
`"json_extract_string(event, '$.verb')"`. A Python `None` marks unfinished work;
SQL NULL may still be a valid result for an individual log record.

</details>

```python
aks_mapping = {
    'event_id': "json_extract_string(event, '$.auditID')",
    'account_uid': "lower(regexp_extract(resource_id, '/SUBSCRIPTIONS/([^/]+)/', 1))",
    'cluster_name': "lower(regexp_extract(resource_id, '/MANAGEDCLUSTERS/([^/]+)$', 1))",
    'principal': "json_extract_string(event, '$.user.username')",
    'operation': None,  # TODO: SQL expression; see the hint for operation
    'resource_type': None,  # TODO: SQL expression; see the hint for resource_type
    'status_id': None,  # TODO: SQL expression; see the hint for status_id
    'role_kind': "json_extract_string(event, '$.requestObject.roleRef.kind')",
    'role': None,  # TODO: SQL expression; see the hint for role
}
```

## Normalize and check — 2 minutes

Run the helper after completing all three mapping cells. It displays the SQL assembled
from **your expressions**, then reports missing/unexpected source keys, duplicate keys,
and per-field differences against the workshop contract, for both the log day and
the visible practice records. Row counts alone cannot pass.
If a check fails, edit that provider's mapping cell and rerun it, then rerun this cell.
Only a passing mapping publishes `main.binding_events`; there is no reference fallback.

<details>
<summary>How to read a failure</summary>

### Troubleshooting mappings

1. Find the failing **provider and field** in the error or check table.
2. EKS/AKS use `event`; GKE uses `entry`.
3. Put single quotes around each JSON path: `"json_extract_string(event, '$.verb')"`.
4. Rerun the edited mapping cell, then rerun normalization. Editing alone does not update Python variables.

| Error | What to check |
|---|---|
| Parameters: verb | Replace `$verb` with `'$.verb'` |
| Syntax error near . | Single-quote the JSON path |
| Referenced column entry not found | EKS/AKS use `event` |
| status_id mismatch | Convert native codes to 0=unknown, 1=success, 2=failure; do not copy HTTP codes |
| role mismatch | EKS/AKS: `$.requestObject.roleRef.name`; GKE: `$.protoPayload.request.roleRef.name` |
| Same error after editing | Rerun the mapping cell before normalization |

For EKS and AKS, use `event`; for GKE, use `entry`. JSON paths must be
single-quoted inside the Python string. For example, the EKS/AKS resource mapping is
`"json_extract_string(event, '$.objectRef.resource')"`.
If the displayed SQL points to `$.objectRef.resource`, check these quotes in your
mapping cell. The helper adds `CAST(... AS VARCHAR)` automatically.

An incomplete mapping names the unfilled provider/field. Missing or unexpected keys
usually mean an event ID or asset mapping is wrong. A `status_id` mismatch means
the provider-specific outcome was not translated correctly; a `role` mismatch often means the request JSON path is wrong.
Preserve NULL for bodies absent from the source. Do not replace every value with the
detection's target constant just to get matches.

</details>

```python
from workshop.normalization import normalize_bindings
mappings = {'eks': eks_mapping, 'gke': gke_mapping, 'aks': aks_mapping}
normalization_report = normalize_bindings(session, mappings)
```

## 1. Write one normalized binding detection

Complete the same binding-attempt detection over your validated main.binding_events table, regardless of outcome.

**What to look for:** Matches must agree with the raw binding attempts, including failed or unknown-outcome requests, with the same source event IDs, assets, actors and roles. No JSON extraction belongs in this query.

**Your next step:** Fill the four target values from the shared contract, then run this cell. Explain which differences normalization removed.

<details>
<summary>Need a hint?</summary>

The operation is create, resource is clusterrolebindings, the exact role kind/name are ClusterRole and cluster-admin. Use single quotes for text.

</details>

```sql
-- TODO: Fill the target values using your contract. Compare the simplicity with the three raw rules.
-- Complete the same binding-attempt detection over your validated main.binding_events table, regardless of outcome.
-- Matches must agree with the raw binding attempts, including failed or unknown-outcome requests, with the same source event IDs, assets, actors and roles. No JSON extraction belongs in this query.
SELECT event_id, provider, account_uid, cluster_name, principal AS grant_actor, role
FROM main.binding_events
-- TODO: use the shared contract; no JSON paths or provider-specific branches are needed.
WHERE operation = '__TODO_OPERATION__'
  AND resource_type = '__TODO_RESOURCE__'
  AND role_kind = '__TODO_ROLE_KIND__'
  AND role = '__TODO_ROLE_NAME__';
```

## 2. Update the rule to successful attempts

A new requirement arrives: keep only successful cluster-admin binding-create attempts. Add one predicate to the normalized rule.

**What to look for:** The log-day count may stay unchanged because its matching attempts are already successful. Practice matches drop from 9 to 4: failed requests and unknown HTTP outcomes are excluded; absent gRPC status maps to success in this modeled source.

**Your next step:** Fill the single TODO using the shared status_id contract, then run the cell. Which three cloud-specific clauses would otherwise have to change?

<details>
<summary>Need a hint?</summary>

The shared contract defines success as `status_id = 1` (numeric, not quoted). Add that one predicate; there is no need to edit the three provider mappings again.

| Without a normalized contract | Outcome condition to add to each raw rule |
|---|---|
| EKS | Cast `$.responseStatus.code` to INTEGER and require HTTP 200–299. |
| GKE | Read `$.protoPayload.status.code`; zero or absent means success in this modeled source. |
| AKS | Cast `$.responseStatus.code` to INTEGER and require HTTP 200–299. |
| Shared rule | `status_id = 1` covers all three providers. |

The visible practice inputs include failures and missing status, so this check demonstrates the change even when the real-day match count stays the same. Mapping absorbs provider differences once; this rule update changes one condition.

</details>

```sql
-- TODO: Add a single status_id predicate. Compare practice-match counts with the attempt rule above.
-- A new requirement arrives: keep only successful cluster-admin binding-create attempts. Add one predicate to the normalized rule.
-- The log-day count may stay unchanged because its matching attempts are already successful. Practice matches drop from 9 to 4: failed requests and unknown HTTP outcomes are excluded; absent gRPC status maps to success in this modeled source.
SELECT event_id, provider, account_uid, cluster_name, principal AS grant_actor, role
FROM main.binding_events
WHERE operation = 'create' AND resource_type = 'clusterrolebindings'
  AND role_kind = 'ClusterRole' AND role = 'cluster-admin'
  -- TODO: add one normalized outcome predicate, then compare practice-match counts.
  AND __TODO_SUCCESS_FILTER__;
```
