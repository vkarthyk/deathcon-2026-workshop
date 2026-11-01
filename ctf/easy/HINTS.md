# Progressive hints: Find the admin grant

<details>
<summary>Hint 1 — What fields matter?</summary>

Check the action, resource type, referenced role kind/name, and outcome. Searching for the string `cluster-admin` anywhere in an event will include decoys.

</details>

<details>
<summary>Hint 2 — Where are those fields?</summary>

For EKS/AKS, inspect `$.verb`, `$.objectRef.resource`, `$.requestObject.roleRef.kind`, `$.requestObject.roleRef.name` and `$.responseStatus.code` in `event`.

For GKE, inspect `$.protoPayload.methodName`, `$.protoPayload.request.roleRef.kind`, `$.protoPayload.request.roleRef.name` and `$.protoPayload.status.code` in `entry`.

</details>

<details>
<summary>Hint 3 — How do I extract and filter?</summary>

DuckDB extracts JSON text with `json_extract_string(event, '$.verb')`. JSON paths and text values use single quotes. For numeric comparisons use `CAST(... AS INTEGER)`.

The target action is `create`, resource is `clusterrolebindings`, role kind is `ClusterRole` and role name is `cluster-admin`. Require all conditions, including success. In GKE, methodName ends in `.clusterrolebindings.create`; an absent gRPC status indicates success here. In HTTP logs, do not treat missing status as success.

Return the native event IDs; assemble AWS, GCP, Azure in that order.

</details>
