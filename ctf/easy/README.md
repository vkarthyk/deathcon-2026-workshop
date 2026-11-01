# Find the admin grant

**Easy · 10–15 minutes · suggested 100 points**

A platform team collected audit records from EKS, GKE and AKS. Routine activity and unsuccessful requests are mixed with privilege changes. Find the **one successful creation of a ClusterRoleBinding granting the ClusterRole `cluster-admin` in each cloud**.

A binding's display name is not the granted role. A failed request does not establish that access was granted.

## Start

Extract `easy.zip` and open `Start.ipynb` in JupyterLab from the extracted `easy/` folder. Use a Python environment with `duckdb`, `pandas`, `jupyterlab` and `ipykernel` installed (the workshop environment includes these). If needed, install with `python -m pip install duckdb==2.0.0 pandas jupyterlab ipykernel`, then `python -m jupyterlab`.

The notebook opens `challenge.duckdb` read-only. No workshop setup cell or SQL magic is needed. Add cells using:

```python
con.sql("""SELECT * FROM raw_eks LIMIT 5""").df()
```

You can also use DuckDB CLI: `duckdb -readonly challenge.duckdb`. JSONL exports contain the same records for other tools. Delivery order is not meaningful; use event contents.

| Table | Scope columns | Audit payload |
|---|---|---|
| `raw_eks` | `account_uid`, `cluster_name` | `event` JSON |
| `raw_gke` | `account_uid`, `cluster_name` | `entry` JSON |
| `raw_aks` | `account_uid`, `cluster_name` | `event` JSON |

EKS and AKS use Kubernetes HTTP response codes: **200–299 means success**; absent status is unknown. GKE uses gRPC status: **zero or absent status means success** in this modeled source. Other gRPC codes indicate failure. Missing request bodies cannot prove which role was granted.

Windows users: use the native PowerShell workshop environment, or Ubuntu inside WSL2. See the [Windows setup guide](https://github.com/ved-k_data/k8s-ocsf-workshop/blob/main/docs/windows-setup.md) for installation, ZIP extraction and launching these notebooks with the workshop environment. Native Windows uses `.\.workshop-venv\Scripts\python.exe` instead of `.workshop-venv/bin/python`.

## Submit

Submit the three native event IDs in **AWS, GCP, Azure** order, separated by underscores:

```text
CTF{AWS_EVENT_ID_GCP_EVENT_ID_AZURE_EVENT_ID}
```

Keep UUID hyphens. No spaces. The event ID is `auditID` for EKS/AKS and `operation.id` for GKE. Exactly one event per provider meets every condition.

For your own review, save the query and one sentence explaining how you verified success and the actual granted role.

## Stuck?

Open HINTS.md one hint at a time. Workshop connections: [01 Cloud-specific detections](https://github.com/ved-k_data/k8s-ocsf-workshop/blob/main/notebooks/01_Cloud_specific_detections.ipynb) and [02 Normalize the logs](https://github.com/ved-k_data/k8s-ocsf-workshop/blob/main/notebooks/02_Normalize_the_logs.ipynb). The challenge uses modeled synthetic logs; it is not a real incident.
