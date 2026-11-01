# Follow the recipient

**Hard · 30–45 minutes · suggested 400 points**

Your detection found several privilege changes across Kubernetes clusters. Identify the **one unapproved grant-to-secret-list sequence** satisfying all these conditions:

1. A successful **create** of a **ClusterRoleBinding** grants the **ClusterRole `cluster-admin`** to a **User**.
2. That **recipient**, who can differ from the grant actor, successfully **lists secrets cluster-wide** at or after the grant and within **15 minutes**, inclusive.
3. Both events belong to the same **provider, account and cluster**.
4. No approval matches the **provider, account, cluster, grant actor, recipient and role**, with the **grant time** inside its validity interval, inclusive.

Return the source events that prove the sequence. Do not classify every matching sequence as malicious: this exercise detects behavior, not intent.

## Start

Extract `hard.zip` and open `Start.ipynb` in JupyterLab from the extracted `hard/` folder. Use a Python environment with `duckdb`, `pandas`, `jupyterlab` and `ipykernel` installed (the workshop environment includes these). If needed: `python -m pip install duckdb==2.0.0 pandas jupyterlab ipykernel`, then `python -m jupyterlab`.

No earlier notebook setup is needed. The starter opens `challenge.duckdb` read-only. Use `con.sql("""YOUR SELECT QUERY""").df()` or DuckDB CLI (`duckdb -readonly challenge.duckdb`). JSONL exports hold the same records. All timestamps represent UTC; row order is not event order.

## Schema reference

| Table | Columns and meaning |
|---|---|
| `k8s_ocsf` | `event_id`, `provider`, `account_uid`, `cluster_name`, `time`, `principal`, `operation`, `resource_type`, `status_id`, `namespace`, `role_kind`, `role`. One row per source event and asset. `principal` is the actor performing the action. |
| `k8s_subjects` | `provider`, `account_uid`, `cluster_name`, `event_id`, `subject`, `subject_kind`. One row per binding request subject. A binding can have multiple subjects. |
| `approvals` | `cloud_provider`, `account_uid`, `cluster_name`, `grant_actor`, `subject`, `role`, `start_time`, `end_time`, `ticket`. Only exact scope and grant-time validity authorize suppression. |
| `identities` | `cloud_provider`, `account_uid`, `principal_name`, `person_id`. Optional attribution context; missing identity does not prevent detection. |

`status_id`: **0 unknown, 1 success, 2 failure**. `namespace IS NULL` denotes a cluster-wide request. Role fields are populated for binding records; use `k8s_subjects` to identify every recipient. Providers are `AWS`, `GCP` and `Azure`. These are prepared workshop-style relational fields; no provider-specific JSON extraction is needed.

Windows users: use the native PowerShell workshop environment, or Ubuntu inside WSL2. See the [Windows setup guide](https://github.com/ved-k_data/k8s-ocsf-workshop/blob/main/docs/windows-setup.md) for installation, ZIP extraction and launching these notebooks with the workshop environment. Native Windows uses `.\.workshop-venv\Scripts\python.exe` instead of `.workshop-venv/bin/python`.

## Submit

Exactly one grant/secret-list pair meets every condition. Submit its IDs in this order:

```text
CTF{GRANT_EVENT_ID_SECRET_LIST_EVENT_ID}
```

Keep UUID hyphens. No spaces. Do not submit an actor, person ID or ticket ID. Retain your query and a short explanation naming the recipient, asset and elapsed time. You should also be able to explain why a near-matching approval does not suppress this pair.

## Stuck?

Open HINTS.md progressively. Workshop connections: [02 Normalize the logs](https://github.com/ved-k_data/k8s-ocsf-workshop/blob/main/notebooks/02_Normalize_the_logs.ipynb), [03 Write the behavioral rule](https://github.com/ved-k_data/k8s-ocsf-workshop/blob/main/notebooks/03_Write_the_behavioral_rule.ipynb) and [04 Investigate alerts](https://github.com/ved-k_data/k8s-ocsf-workshop/blob/main/notebooks/04_Investigate_alerts.ipynb). The challenge is synthetic and contains deliberately similar sequences.
