# 01 Cloud specific detections

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

## 1. Inspect a native EKS record

Preview the unwrapped Kubernetes audit JSON from the modeled CloudWatch envelope.

**What to look for:** Expand the single event JSON and locate user, verb and objectRef. requestObject is available only when the audit record includes a body.

**Your next step:** Identify the actor and request time in this sample. To inspect RBAC subjects, select a clusterrolebindings event with a requestObject body; the first row is not filtered to grants. These exports are modeled, not live-verified.

<details>
<summary>Need a hint?</summary>

Extract requestURI with json_extract_string. A LIKE pattern needs single quotes, such as '%clusterrolebinding%'. Inspect requestObject for the body.

</details>

```sql
-- TODO: Find a binding event that includes a request body.
-- Preview the unwrapped Kubernetes audit JSON from the modeled CloudWatch envelope.
-- Expand the single event JSON and locate user, verb and objectRef. requestObject is available only when the audit record includes a body.
SELECT event FROM enterprise.raw_eks LIMIT 1;
```

## 2. Inspect a native GKE record

Preview a Cloud Logging entry rather than assuming it uses the native Kubernetes event shape.

**What to look for:** The operation, identity and request live under protoPayload; the surrounding entry carries cloud metadata.

**Your next step:** Compare these paths with EKS. See docs/source-validation.md for the real-export release gate.

<details>
<summary>Need a hint?</summary>

Look under $.protoPayload for methodName, authenticationInfo.principalEmail and request. These paths differ from native Kubernetes audit paths.

</details>

```sql
-- TODO: Locate operation, caller and request fields; compare their paths with EKS.
-- Preview a Cloud Logging entry rather than assuming it uses the native Kubernetes event shape.
-- The operation, identity and request live under protoPayload; the surrounding entry carries cloud metadata.
SELECT entry FROM enterprise.raw_gke LIMIT 1;
```

## 3. Inspect a native AKS record

Preview the Azure resource envelope alongside the native audit event.

**What to look for:** resource_id and category surround the event JSON. The modeled resource ID requires canonicalization for inventory joins.

**Your next step:** Find account and cluster scope; do not infer a region that is absent.

<details>
<summary>Need a hint?</summary>

resource_id belongs to the envelope. The subscription and managed-cluster segments identify asset scope; event contains the Kubernetes audit JSON.

</details>

```sql
-- TODO: Locate account and cluster scope; distinguish envelope fields from event fields.
-- Preview the Azure resource envelope alongside the native audit event.
-- resource_id and category surround the event JSON. The modeled resource ID requires canonicalization for inventory joins.
SELECT resource_id, category, event FROM enterprise.raw_aks LIMIT 1;
```

## 4. Detect a cluster-admin binding in EKS

Complete the four TODO predicate slots to detect cluster-admin ClusterRoleBinding create attempts in this source. Outcome is not filtered, so a match does not establish that the binding was created.

**What to look for:** Unfinished tokens report Detection incomplete. Once filled, the check compares source event IDs, account/cluster scope, actors and roles, and rejects missing, unexpected or duplicate matches.

**Your next step:** Use the collapsed field hints if needed; aim for three minutes per cloud. Keep the supplied output columns and complete all predicates before continuing to notebook 02.

<details>
<summary>Field hints for the TODOs</summary>

**OPERATION:** Compare `json_extract_string(event, '$.verb')` with `'create'`.

**RESOURCE:** Compare `json_extract_string(event, '$.objectRef.resource')` with `'clusterrolebindings'`.

**ROLE_KIND:** Compare `json_extract_string(event, '$.requestObject.roleRef.kind')` with `'ClusterRole'`.

**ROLE_NAME:** Compare `json_extract_string(event, '$.requestObject.roleRef.name')` with `'cluster-admin'`.

</details>

```sql
-- TODO: Fill every predicate token, then run the cell to check event and asset identity.
-- Complete the four TODO predicate slots to detect cluster-admin ClusterRoleBinding create attempts in this source. Outcome is not filtered, so a match does not establish that the binding was created.
-- Unfinished tokens report Detection incomplete. Once filled, the check compares source event IDs, account/cluster scope, actors and roles, and rejects missing, unexpected or duplicate matches.
SELECT DISTINCT json_extract_string(event, '$.auditID') AS event_id,
       'AWS' AS provider, aws_account AS account_uid,
       regexp_extract(log_group, '^/aws/eks/([^/]+)/', 1) AS cluster_name,
       json_extract_string(event, '$.user.username') AS grant_actor,
       json_extract_string(event, '$.requestObject.roleRef.name') AS role
FROM enterprise.raw_eks
-- TODO: replace each token with a complete SQL predicate. Open the field hints above.
WHERE __TODO_OPERATION__
  AND __TODO_RESOURCE__
  AND __TODO_ROLE_KIND__
  AND __TODO_ROLE_NAME__;
```

## 5. Write the same detection for GKE

Complete the four TODO predicate slots to detect cluster-admin ClusterRoleBinding create attempts in this source. Outcome is not filtered, so a match does not establish that the binding was created.

**What to look for:** Unfinished tokens report Detection incomplete. Once filled, the check compares source event IDs, account/cluster scope, actors and roles, and rejects missing, unexpected or duplicate matches.

**Your next step:** Use the collapsed field hints if needed; aim for three minutes per cloud. Keep the supplied output columns and complete all predicates before continuing to notebook 02.

<details>
<summary>Field hints for the TODOs</summary>

**OPERATION and RESOURCE:** methodName combines both. Compare `json_extract_string(entry, '$.protoPayload.methodName')` with `'io.k8s.authorization.rbac.v1.clusterrolebindings.create'`; this one predicate can cover both checks.

**ROLE_KIND:** Compare `json_extract_string(entry, '$.protoPayload.request.roleRef.kind')` with `'ClusterRole'`.

**ROLE_NAME:** Compare `json_extract_string(entry, '$.protoPayload.request.roleRef.name')` with `'cluster-admin'`.

</details>

```sql
-- TODO: Complete the GKE attempt predicates. The method check can fill both operation/resource slots; outcome is not filtered here.
-- Complete the four TODO predicate slots to detect cluster-admin ClusterRoleBinding create attempts in this source. Outcome is not filtered, so a match does not establish that the binding was created.
-- Unfinished tokens report Detection incomplete. Once filled, the check compares source event IDs, account/cluster scope, actors and roles, and rejects missing, unexpected or duplicate matches.
SELECT DISTINCT json_extract_string(entry, '$.operation.id') AS event_id,
       'GCP' AS provider,
       json_extract_string(entry, '$.resource.labels.project_id') AS account_uid,
       json_extract_string(entry, '$.resource.labels.cluster_name') AS cluster_name,
       json_extract_string(entry, '$.protoPayload.authenticationInfo.principalEmail') AS grant_actor,
       json_extract_string(entry, '$.protoPayload.request.roleRef.name') AS role
FROM enterprise.raw_gke
-- TODO: replace each token with a complete SQL predicate. Open the field hints above.
WHERE __TODO_OPERATION__
  AND __TODO_RESOURCE__
  AND __TODO_ROLE_KIND__
  AND __TODO_ROLE_NAME__;
```

## 6. Write the same detection for AKS

Complete the four TODO predicate slots to detect cluster-admin ClusterRoleBinding create attempts in this source. Outcome is not filtered, so a match does not establish that the binding was created.

**What to look for:** Unfinished tokens report Detection incomplete. Once filled, the check compares source event IDs, account/cluster scope, actors and roles, and rejects missing, unexpected or duplicate matches.

**Your next step:** Use the collapsed field hints if needed; aim for three minutes per cloud. Keep the supplied output columns and complete all predicates before continuing to notebook 02.

<details>
<summary>Field hints for the TODOs</summary>

**OPERATION:** Compare `json_extract_string(event, '$.verb')` with `'create'`.

**RESOURCE:** Compare `json_extract_string(event, '$.objectRef.resource')` with `'clusterrolebindings'`.

**ROLE_KIND:** Compare `json_extract_string(event, '$.requestObject.roleRef.kind')` with `'ClusterRole'`.

**ROLE_NAME:** Compare `json_extract_string(event, '$.requestObject.roleRef.name')` with `'cluster-admin'`.

</details>

```sql
-- TODO: Complete the AKS predicates. Reuse EKS logic where the native fields agree.
-- Complete the four TODO predicate slots to detect cluster-admin ClusterRoleBinding create attempts in this source. Outcome is not filtered, so a match does not establish that the binding was created.
-- Unfinished tokens report Detection incomplete. Once filled, the check compares source event IDs, account/cluster scope, actors and roles, and rejects missing, unexpected or duplicate matches.
SELECT DISTINCT json_extract_string(event, '$.auditID') AS event_id,
       'Azure' AS provider,
       lower(regexp_extract(resource_id, '/SUBSCRIPTIONS/([^/]+)/', 1)) AS account_uid,
       lower(regexp_extract(resource_id, '/MANAGEDCLUSTERS/([^/]+)$', 1)) AS cluster_name,
       json_extract_string(event, '$.user.username') AS grant_actor,
       json_extract_string(event, '$.requestObject.roleRef.name') AS role
FROM enterprise.raw_aks
-- TODO: replace each token with a complete SQL predicate. Open the field hints above.
WHERE __TODO_OPERATION__
  AND __TODO_RESOURCE__
  AND __TODO_ROLE_KIND__
  AND __TODO_ROLE_NAME__;
```
