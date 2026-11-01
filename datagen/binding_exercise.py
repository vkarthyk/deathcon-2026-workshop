"""Participant scaffolds and progressively revealed hints for the one-hour path."""
from workshop.behavioral import ROOT
from workshop.normalization import BINDING_SCHEMA

RAW_HEADINGS = {
    'Detect a cluster-admin binding in EKS': 'eks',
    'Write the same detection for GKE': 'gke',
    'Write the same detection for AKS': 'aks',
}


def raw_scaffold(cloud):
    reference = (ROOT / 'detection/simple_cluster_admin' / (cloud + '.sql')).read_text()
    projection = reference[reference.index('SELECT DISTINCT'):reference.index('\n-- ', reference.index('FROM enterprise.'))]
    return projection + """
-- TODO: replace each token with a complete SQL predicate. Open the field hints above.
WHERE __TODO_OPERATION__
  AND __TODO_RESOURCE__
  AND __TODO_ROLE_KIND__
  AND __TODO_ROLE_NAME__;"""


UNIFIED_SCAFFOLD = """SELECT event_id, provider, account_uid, cluster_name, principal AS grant_actor, role
FROM main.binding_events
-- TODO: use the shared contract; no JSON paths or provider-specific branches are needed.
WHERE operation = '__TODO_OPERATION__'
  AND resource_type = '__TODO_RESOURCE__'
  AND role_kind = '__TODO_ROLE_KIND__'
  AND role = '__TODO_ROLE_NAME__';"""


NORMALIZED_HEADINGS = {
    'Write one normalized binding detection': 'normalized',
    'Update the rule to successful attempts': 'normalized-success',
}
SUCCESS_UPDATE_SCAFFOLD = """SELECT event_id, provider, account_uid, cluster_name, principal AS grant_actor, role
FROM main.binding_events
WHERE operation = 'create' AND resource_type = 'clusterrolebindings'
  AND role_kind = 'ClusterRole' AND role = 'cluster-admin'
  -- TODO: add one normalized outcome predicate, then compare practice-match counts.
  AND __TODO_SUCCESS_FILTER__;"""


def raw_hints(cloud):
    if cloud == 'gke':
        entries = [
            ('OPERATION and RESOURCE', "methodName combines both. Compare `json_extract_string(entry, '$.protoPayload.methodName')` with `'io.k8s.authorization.rbac.v1.clusterrolebindings.create'`; this one predicate can cover both checks."),
            ('ROLE_KIND', "Compare `json_extract_string(entry, '$.protoPayload.request.roleRef.kind')` with `'ClusterRole'`."),
            ('ROLE_NAME', "Compare `json_extract_string(entry, '$.protoPayload.request.roleRef.name')` with `'cluster-admin'`."),
        ]
    else:
        entries = [
            ('OPERATION', "Compare `json_extract_string(event, '$.verb')` with `'create'`."),
            ('RESOURCE', "Compare `json_extract_string(event, '$.objectRef.resource')` with `'clusterrolebindings'`."),
            ('ROLE_KIND', "Compare `json_extract_string(event, '$.requestObject.roleRef.kind')` with `'ClusterRole'`."),
            ('ROLE_NAME', "Compare `json_extract_string(event, '$.requestObject.roleRef.name')` with `'cluster-admin'`."),
        ]
    # GKE participants can repeat its method predicate in both slots; no unexplained TRUE is needed.
    return '\n\n<details>\n<summary>Field hints for the TODOs</summary>\n\n' + '\n\n'.join(f'**{name}:** {hint}' for name, hint in entries) + '\n\n</details>'


# Envelope/source identity fields are supplied to keep the activity within 15 minutes.
BASE = {
    'eks': {
        'event_id': "json_extract_string(event, '$.auditID')", 'account_uid': 'aws_account',
        'cluster_name': "regexp_extract(log_group, '^/aws/eks/([^/]+)/', 1)",
        'principal': "json_extract_string(event, '$.user.username')",
        'role_kind': "json_extract_string(event, '$.requestObject.roleRef.kind')",
    },
    'gke': {
        'event_id': "json_extract_string(entry, '$.operation.id')",
        'account_uid': "json_extract_string(entry, '$.resource.labels.project_id')",
        'cluster_name': "json_extract_string(entry, '$.resource.labels.cluster_name')",
        'principal': "json_extract_string(entry, '$.protoPayload.authenticationInfo.principalEmail')",
        'role_kind': "json_extract_string(entry, '$.protoPayload.request.roleRef.kind')",
    },
    'aks': {
        'event_id': "json_extract_string(event, '$.auditID')",
        'account_uid': "lower(regexp_extract(resource_id, '/SUBSCRIPTIONS/([^/]+)/', 1))",
        'cluster_name': "lower(regexp_extract(resource_id, '/MANAGEDCLUSTERS/([^/]+)$', 1))",
        'principal': "json_extract_string(event, '$.user.username')",
        'role_kind': "json_extract_string(event, '$.requestObject.roleRef.kind')",
    },
}
MEANINGS = {
    'event_id': 'Source audit-event identifier; never a generated row number.',
    'provider': 'AWS, GCP or Azure (supplied by the helper).',
    'account_uid': 'Native account/project/subscription ID, canonicalized for joins.',
    'cluster_name': 'Cluster name within provider/account scope.',
    'principal': 'Native actor who performed the operation, not an inferred person.',
    'operation': 'Kubernetes verb, such as create or list.',
    'resource_type': 'Kubernetes resource collection, such as clusterrolebindings.',
    'status_id': '1 = success, 2 = failure, 0 = unknown. A normalized outcome, not a copied HTTP code.',
    'role_kind': 'Referenced role kind; nullable when the body is absent.',
    'role': 'Referenced role name; nullable when the body is absent.',
}


def normalization_cells():
    contract = '\n'.join(f'| `{field}` | `{dtype}` | {MEANINGS[field]} |' for field, dtype in BINDING_SCHEMA.items())
    cells = [('markdown', """## Design the shared contract — 2 minutes

**Before opening the mapping hints:** which fields must survive normalization to detect a
cluster-admin binding attempt? Which fields identify the event and its asset?

**Your schema choices and why:** TODO — record your proposed fields here.

For this timed exercise, implement the ten-field contract below. It is a small,
OCSF-derived relational contract, not a complete OCSF event. You choose the SQL
expressions that populate it; the field names/types keep validation and the final
query shared across the room.

| Field | Type | Meaning |
|---|---|---|
""" + contract + """

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
""")]
    for cloud, base in BASE.items():
        if cloud == 'gke':
            hints = """- **operation:** take the last segment of methodName: `split_part(json_extract_string(entry, '$.protoPayload.methodName'), '.', -1)`.
- **resource_type:** for the binding-only input, the preceding segment is the resource; use `split_part(..., '.', -2)`.
- **status_id:** `CASE WHEN COALESCE(CAST(json_extract_string(entry, '$.protoPayload.status.code') AS INTEGER), 0) = 0 THEN 1 ELSE 2 END`. An absent gRPC status means success in this modeled source.
- **role:** extract `$.protoPayload.request.roleRef.name` from `entry`."""
        else:
            hints = """- **operation:** extract `$.verb` from `event` as text.
- **resource_type:** extract `$.objectRef.resource` from `event` as text.
- **status_id:** paste this Python string as the mapping value (keep the outer double quotes):
  ```python
  "CASE WHEN json_extract_string(event, '$.responseStatus.code') IS NULL THEN 0 WHEN CAST(json_extract_string(event, '$.responseStatus.code') AS INTEGER) BETWEEN 200 AND 299 THEN 1 ELSE 2 END"
  ```
  This maps a missing code to **0 (unknown)**, HTTP 200–299 to **1 (success)**, and every other code to **2 (failure)**.
- **role:** extract `$.requestObject.roleRef.name` from `event` as text."""
        if cloud == 'aks':
            hints += '\n- EKS and AKS share these Kubernetes paths. Reuse the four expressions, while retaining the supplied Azure asset-key canonicalization.'
        cells.append(('markdown', f"""## Map {cloud.upper()} — 3 minutes

Replace the four `None` values with **Python strings containing SQL expressions**.
The supplied entries handle event identity, asset scope, actor and role kind.
Copy the `json_extract_string` pattern when you need another JSON field. Missing
request bodies should produce NULL role values; do not invent their contents.

<details>
<summary>Hints for each mapping TODO</summary>

{hints}

Python's double-quoted string can contain SQL's single-quoted JSON path, e.g.
`"json_extract_string(event, '$.verb')"`. A Python `None` marks unfinished work;
SQL NULL may still be a valid result for an individual log record.

</details>"""))
        entries = []
        for field in BINDING_SCHEMA:
            if field == 'provider':
                continue
            value = repr(base[field]) if field in base else 'None  # TODO: SQL expression; see the hint for ' + field
            entries.append(f'    {field!r}: {value}' + (',' if field in base else ''))
            if field not in base:
                entries[-1] = f'    {field!r}: None,  # TODO: SQL expression; see the hint for {field}'
        cells.append(('code', f'{cloud}_mapping = {{\n' + '\n'.join(entries) + '\n}'))
    cells += [('markdown', """## Normalize and check — 2 minutes

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

</details>"""), ('code', """from workshop.normalization import normalize_bindings
mappings = {'eks': eks_mapping, 'gke': gke_mapping, 'aks': aks_mapping}
normalization_report = normalize_bindings(session, mappings)""")]
    return cells
