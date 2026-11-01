"""Generate the Lab 1 notebook (participant + solution) from one cell list.

    python3.11 datagen/make_lab1.py
"""

import sys
from pathlib import Path

import nbformat as nbf

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from solutions.lab1_raw.rules import RULES  # noqa: E402

CLOUD_NAME = {"eks": "EKS", "gke": "GKE", "aks": "AKS"}

# Starter queries: runnable (WHERE FALSE) so the notebook executes top to bottom before any edits.
TODO_SQL = {
    "eks": "SELECT json_extract_string(event, '$.auditID') AS event_id\nFROM raw_eks\nWHERE FALSE  -- TODO",
    "aks": "SELECT json_extract_string(event, '$.auditID') AS event_id\nFROM raw_aks\nWHERE FALSE  -- TODO",
    "gke": "SELECT json_extract_string(entry, '$.operation.id') AS event_id\nFROM raw_gke\nWHERE FALSE  -- TODO",
}

HINTS = {
    ("privileged_pod", "aks"): "The audit event inside `properties.log` is the same native Kubernetes Event as EKS - "
                               "start from the EKS query. What actually changes?",
    ("privileged_pod", "gke"): "GKE has no `verb` or `objectRef`. Look at `protoPayload.methodName` and "
                               "`protoPayload.resourceName` in the sample above. The pod spec is under "
                               "`protoPayload.request`.",
    ("pod_exec", "eks"): "`kubectl exec` is a `create` on the `exec` **subresource** of a pod.",
    ("pod_exec", "aks"): "Same shape as EKS.",
    ("pod_exec", "gke"): "On GKE the subresource is folded into `methodName`. Run "
                         "`lab1.q(\"SELECT DISTINCT json_extract_string(entry, '$.protoPayload.methodName') m "
                         "FROM raw_gke ORDER BY m\", 100)` to see every method name.",
    ("host_escape_exec", "eks"): "The exec command is only recorded as `command=` query parameters on "
                                 "`requestURI`. Look for `nsenter`, which enters the host's namespaces.",
    ("host_escape_exec", "aks"): "Same as EKS.",
}


def md(text):
    return nbf.v4.new_markdown_cell(text.strip())


def code(text):
    return nbf.v4.new_code_cell(text.strip())


def rule_cell(rule, cloud, solved):
    var = f"{rule.upper()}_{cloud.upper()}"
    sql = RULES[rule][cloud].strip() if solved else TODO_SQL[cloud]
    return code(f'{var} = """\n{sql}\n"""\nlab1.check("{rule}", "{cloud}", {var})\nlab1.q({var})')


def hit_counts():
    """Reference hit counts per (rule, cloud), so the prose matches whatever scale the data was built at."""
    from workshop import lab1
    con = lab1.setup()
    return {(rule, cloud): con.sql(f"SELECT count(*) FROM ({sql})").fetchone()[0]
            for rule, by_cloud in RULES.items() for cloud, sql in by_cloud.items()}


def counts_text(counts, rule):
    return ", ".join(f"{CLOUD_NAME[c]} {counts[(rule, c)]:,}" for c in ("eks", "gke", "aks") if (rule, c) in counts)


def build(solved, counts):
    cells = [
        md("""
# Lab 1 — One detection, three clouds (≈10 min)

The same attack hit the `payments-prod` Kubernetes cluster on **AWS EKS**, **GCP GKE** and **Azure AKS**.
Every cloud logged it. Every cloud logged it **differently**.

You will write two detections against each cloud's raw audit logs:

| Rule | Question |
|---|---|
| **A. Privileged pod** | Did anyone create a pod with `securityContext.privileged: true`? |
| **B. Pod exec** | Did anyone `kubectl exec` into a pod? |

Run each cell with **Shift+Enter**. Edit the `-- TODO` queries until `lab1.check(...)` prints ✅.

> ⚠️ **DuckDB gotcha:** `->>` binds *looser* than `AND` and `=`, so
> `event->>'$.verb' = 'create' AND event->>'$.x' = 'y'` silently parses wrong.
> Use `json_extract_string(event, '$.path')` (as the starters do) or wrap every `->>` in parentheses.
> JSONPath arrays start at **0** (`$.sourceIPs[0]`).
"""),
        code("""
import sys, os
sys.path.insert(0, os.path.abspath("../.."))
from workshop import lab1
con = lab1.setup()
"""),
        md("""
## Step 1 — Look before you query

One raw record per cloud. Note **where the Kubernetes audit event lives** in each, and what the envelope adds.

- **EKS**: CloudWatch Logs → the native audit `Event`, plus `aws_account` and `log_group`
- **AKS**: Azure diagnostics → the native audit `Event` from `properties.log`, plus an upper-cased `resource_id`
- **GKE**: Cloud Logging → no native `Event`; Google re-shapes it into `protoPayload`
"""),
        code('lab1.sample("eks")'),
        code('lab1.sample("aks")'),
        code('lab1.sample("gke")'),
        md("""
## Rule A — Privileged pod created

A privileged container runs with full access to the node. Combined with `hostPID` and a host-path mount,
it is a container escape waiting to happen (MITRE **T1611**).

**EKS is done for you** — read it, run it, then adapt it for the other two clouds.
"""),
        rule_cell("privileged_pod", "eks", solved=True),
        md(f"### AKS\n{HINTS[('privileged_pod', 'aks')]}"),
        rule_cell("privileged_pod", "aks", solved),
        md(f"### GKE\n{HINTS[('privileged_pod', 'gke')]}"),
        rule_cell("privileged_pod", "gke", solved),
        md(f"""
Hits: **{counts_text(counts, "privileged_pod")}**, and only **1 per cloud** is the attack.
The rest are the cloud provider's own networking/storage DaemonSets (privileged by design, recreated every time
a node joins) and, on EKS, an SRE's `kubectl debug node` pod. Raw logs can't tell them apart.
Hold that thought until Lab 4.

## Rule B — Exec into a pod

`kubectl exec` gives an interactive shell inside a running container (MITRE **T1609**).
This time you write all three. Expect **{counts_text(counts, "pod_exec")}** hits.
"""),
        md(f"### EKS\n{HINTS[('pod_exec', 'eks')]}"),
        rule_cell("pod_exec", "eks", solved),
        md(f"### AKS\n{HINTS[('pod_exec', 'aks')]}"),
        rule_cell("pod_exec", "aks", solved),
        md(f"### GKE\n{HINTS[('pod_exec', 'gke')]}"),
        rule_cell("pod_exec", "gke", solved),
        md("""
## Stretch — Only the execs that escape to the host

Most execs are engineers opening `sh` or `bash` to debug. One per cloud is the attacker running
`nsenter --target 1` to jump into the node's namespaces. Narrow Rule B to the host-escape only.
"""),
        md(f"### EKS\n{HINTS[('host_escape_exec', 'eks')]}"),
        rule_cell("host_escape_exec", "eks", solved),
        md(f"### AKS\n{HINTS[('host_escape_exec', 'aks')]}"),
        rule_cell("host_escape_exec", "aks", solved),
        md("""
### GKE — try it

Find the attacker's exec on GKE and look for the command. Where did it go?

<details><summary>Answer</summary>

GKE's audit log never records the request URI, so the `nsenter` arguments **do not exist** in GKE logs.
No query can recover them. Some detections are not portable *at all*, no matter how you normalize:
know what each source can and cannot see.
</details>
"""),
        code("""lab1.q(\"\"\"
SELECT json_extract_string(entry, '$.protoPayload.methodName') AS method,
       json_extract_string(entry, '$.protoPayload.resourceName') AS resource,
       json_extract(entry, '$.protoPayload') AS payload
FROM raw_gke
WHERE json_extract_string(entry, '$.protoPayload.methodName') LIKE '%exec%'
\"\"\")"""),
        md("""
## Wrap-up

"""),
        code("lab1.scorecard()"),
        md("""
**Count what you just maintained:** 2 rules × 3 clouds = **6 queries**, built on 3 different field
layouts, plus one rule that works on only 2 of the 3 clouds. Add a fourth cloud, or change the definition of
"privileged" (say, to include `hostPID` without `privileged`), and you edit every one of them.

| | EKS | AKS | GKE |
|---|---|---|---|
| Where the event lives | `logEvents[].message` (JSON string) | `properties.log` (JSON string) | `protoPayload` (re-shaped) |
| Verb | `verb` | `verb` | last segment of `methodName` |
| Resource / subresource | `objectRef.resource` / `.subresource` | same | packed into `methodName` and `resourceName` |
| Who | `user.username` (an IAM role ARN) | `user.username` (UPN or GUID) | `authenticationInfo.principalEmail` |
| Request URI | ✅ | ✅ | ❌ never logged |

**Next — Lab 2:** map all three into one schema (OCSF), so Lab 3 can write each rule **once**.
"""),
    ]
    nb = nbf.v4.new_notebook(cells=cells)
    nb.metadata["kernelspec"] = {"name": "python3", "display_name": "Python 3", "language": "python"}
    return nb


def main():
    counts = hit_counts()
    for solved, path in [(False, ROOT / "labs" / "lab1_raw" / "01_raw_detections.ipynb"),
                         (True, ROOT / "solutions" / "lab1_raw" / "01_raw_detections.ipynb")]:
        path.parent.mkdir(parents=True, exist_ok=True)
        nbf.write(build(solved, counts), path)
        print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
