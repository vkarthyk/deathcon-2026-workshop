"""Brief tasks and optional syntax hints for the existing notebook queries."""
SQL_REFERENCE = """## SQL quick reference

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
"""

TASKS = {
    'Explore the enterprise day': 'Narrow the provider and time range before aggregating. What changes?',
    'Inventory the available activity': 'Identify the operations and resources a grant-to-secret-list rule would need.',
    'Inspect the behavioral alerts': 'Choose one alert and identify the evidence you would need to review it.',
    'Inspect a native EKS record': 'Find a binding event that includes a request body.',
    'Inspect a native GKE record': 'Locate operation, caller and request fields; compare their paths with EKS.',
    'Inspect a native AKS record': 'Locate account and cluster scope; distinguish envelope fields from event fields.',
    'Detect a cluster-admin binding in EKS': 'Fill every predicate token, then run the cell to check event and asset identity.',
    'Write the same detection for GKE': 'Complete the GKE attempt predicates. The method check can fill both operation/resource slots; outcome is not filtered here.',
    'Write the same detection for AKS': 'Complete the AKS predicates. Reuse EKS logic where the native fields agree.',
    'Update the rule to successful attempts': 'Add a single status_id predicate. Compare practice-match counts with the attempt rule above.',
    'Write one normalized binding detection': 'Fill the target values using your contract. Compare the simplicity with the three raw rules.',
    'Inspect grant subjects as rows': 'Compare actor and subject; identify predicates still needed for a valid grant.',
    'Define your SQL detection': 'Try one rule change, keeping the output keys intact. Save a copy first.',
    'Run your detection': 'Choose an alert and explain how to retrieve its individual evidence events.',
    'Inspect audit-stage deduplication': 'How would you find repeated source keys rather than just their total count?',
    'Select an alert from your rule': 'Choose an alert, keeping its asset and subject keys for the timeline below.',
    'Read the surrounding activity': 'Select your chosen alert inside the CTE; adjust the window or row limit if needed.',
}

HINTS = {
    'Update the rule to successful attempts': """The shared contract defines success as `status_id = 1` (numeric, not quoted). Add that one predicate; there is no need to edit the three provider mappings again.

| Without a normalized contract | Outcome condition to add to each raw rule |
|---|---|
| EKS | Cast `$.responseStatus.code` to INTEGER and require HTTP 200–299. |
| GKE | Read `$.protoPayload.status.code`; zero or absent means success in this modeled source. |
| AKS | Cast `$.responseStatus.code` to INTEGER and require HTTP 200–299. |
| Shared rule | `status_id = 1` covers all three providers. |

The visible practice inputs include failures and missing status, so this check demonstrates the change even when the real-day match count stays the same. Mapping absorbs provider differences once; this rule update changes one condition.""",
    'Write one normalized binding detection': "The operation is create, resource is clusterrolebindings, the exact role kind/name are ClusterRole and cluster-admin. Use single quotes for text.",
    'Explore the enterprise day': 'A WHERE clause goes before GROUP BY. The relevant columns are provider and time; use the summary output to choose a range.',
    'Inspect a native EKS record': "Extract requestURI with json_extract_string. A LIKE pattern needs single quotes, such as '%clusterrolebinding%'. Inspect requestObject for the body.",
    'Inspect a native GKE record': 'Look under $.protoPayload for methodName, authenticationInfo.principalEmail and request. These paths differ from native Kubernetes audit paths.',
    'Inspect a native AKS record': 'resource_id belongs to the envelope. The subscription and managed-cluster segments identify asset scope; event contains the Kubernetes audit JSON.',
    'Inspect audit-stage deduplication': 'Group the cached rows by provider, account_uid, cluster_name and event_id. HAVING COUNT(*) > 1 finds repeated keys.',
    'Read the surrounding activity': 'Add filters inside chosen, before ORDER BY. Use the selected alert key together with provider/account/cluster and subject to retain scope.',
}


def optional_hint(heading):
    hint = HINTS.get(heading)
    return f"\n\n<details>\n<summary>Need a hint?</summary>\n\n{hint}\n\n</details>" if hint else ""
