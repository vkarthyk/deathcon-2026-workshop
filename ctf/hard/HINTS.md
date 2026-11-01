# Progressive hints: Follow the recipient

<details>
<summary>Hint 1 — Follow access, not just the actor</summary>

The principal creating the binding is the grant actor. Join its request-subject rows to identify the recipient. Match subsequent activity to that recipient, not necessarily the grant actor. Follow every User subject; the first subject is not necessarily the one that acts.

</details>

<details>
<summary>Hint 2 — Preserve asset scope and time</summary>

Join subjects to events using provider, account_uid, cluster_name and event_id. Join subsequent activity using provider, account_uid, cluster_name and the granted subject's name. Require the secret-list time to be at or after grant time and at most `grant_time + INTERVAL '15' MINUTE`.

Both actions must succeed. The read must be `list` on `secrets` with a NULL namespace. Namespaced reads, denied requests and activity on another asset are decoys.

</details>

<details>
<summary>Hint 3 — Structure the query</summary>

Use a first CTE to select valid grants and all User recipients. Join it to the event table again to find qualifying recipient activity. Exclude a pair only when `NOT EXISTS` finds an approval matching **all** required scope fields and containing the grant time. An approval for another actor, role, recipient or asset, or an expired approval, is insufficient.

Return distinct grant and read event IDs. Identity resolution is optional attribution; do not require a person mapping to keep a match.

</details>
