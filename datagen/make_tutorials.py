"""Generate runnable tutorials using only Python's standard library.

Run: python3 datagen/make_tutorials.py
Edit this source, then regenerate; notebooks are committed without outputs.
"""

import json
from pathlib import Path
import sys
import textwrap

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from solutions.lab1_raw.rules import PRIVILEGED_POD, POD_EXEC  # noqa: E402


def cell(kind, source):
    result = {"cell_type": kind, "metadata": {},
              "source": textwrap.dedent(source).strip() + "\n"}
    if kind == "code":
        result.update(execution_count=None, outputs=[])
    return result


def md(source):
    return cell("markdown", source)


def code(source):
    return cell("code", source)


def sql_var(name, sql):
    return code(f'{name} = """\n{sql.strip()}\n"""\nq(con, {name})')


BOOTSTRAP = '''
from pathlib import Path
import sys

# Works when Jupyter starts at the repository root or inside tutorials/.
ROOT = next((p for p in (Path.cwd(), *Path.cwd().parents)
             if (p / "workshop" / "db.py").is_file()), None)
if ROOT is None:
    raise RuntimeError("Start JupyterLab from the workshop checkout: ./setup.sh --notebooks")
sys.path.insert(0, str(ROOT))
from workshop.tutorial import open_workshop, q, compare, evaluate
'''

PRIVILEGED = """
SELECT metadata.uid AS event_id, cloud.provider AS provider, time,
       actor.user.name AS principal, resources[1].namespace AS namespace,
       json_extract_string(api.request.data, '$.spec.containers[0].image') AS image,
       json_extract_string(api.request.data, '$.metadata.ownerReferences[0].name') AS owner_name,
       json_extract_string(api.request.data, '$.metadata.ownerReferences[0].kind') AS owner_kind,
       cloud.account.uid AS account_uid,
       cloud.account.labels['cluster_name'] AS cluster_name,
       src_endpoint.ip AS src_ip, http_request.user_agent AS user_agent
FROM ocsf_api_activity
WHERE api.operation = 'create'
  AND resources[1].type = 'pods'
  AND status_id = 1
  AND json_extract_string(api.request.data, '$.spec.containers[0].securityContext.privileged') = 'true'
"""

EXEC = """
SELECT metadata.uid AS event_id, cloud.provider AS provider, time,
       actor.user.name AS principal, resources[1].namespace AS namespace,
       resources[1].name AS pod, src_endpoint.ip AS src_ip
FROM ocsf_api_activity
WHERE api.operation = 'create' AND resources[1].type = 'pods/exec'
"""

ENRICHED = """
SELECT p.*, w.owner_name IS NOT NULL AS platform_allowlisted,
       c.region, c.data_classification,
       i.display_name, i.out_of_office, i.usual_client_os,
       CASE WHEN i.usual_client_os IS NOT NULL AND p.user_agent IS NOT NULL
            THEN NOT contains(p.user_agent, i.usual_client_os) END AS unusual_client,
       r.reputation, r.as_org,
       NOT EXISTS (SELECT 1 FROM approved_registries a
                   WHERE starts_with(p.image, a.registry_prefix)) AS unapproved_registry
FROM privileged_hits p
LEFT JOIN privileged_allowlist w
  ON w.cloud_provider = p.provider AND w.namespace = p.namespace
 AND w.owner_name = p.owner_name AND w.owner_kind = p.owner_kind
 AND starts_with(p.image, w.image_prefix)
LEFT JOIN clusters c
  ON c.cloud_provider = p.provider AND c.account_uid = p.account_uid
 AND c.cluster_name = p.cluster_name
LEFT JOIN identity_links l
  ON l.cloud_provider = p.provider AND l.principal_name = p.principal
LEFT JOIN identities i ON i.person_id = l.person_id
LEFT JOIN ip_reputation r ON r.ip = p.src_ip
"""


def raw():
    cells = [md('''
        # Tutorial 1 — Detect privileged pods in raw audit logs (20 minutes)

        **Start here:** `./setup.sh --notebooks`. Choose Python 3, then **Run → Run All Cells**.
        Every example and practice cell runs before you edit anything. Use Shift+Enter to rerun one cell.

        Scenario: investigate Kubernetes audit activity on `payments-prod` across EKS, GKE, and AKS.
        You will inspect raw events, run a working privileged-pod detection, and modify a pod-exec rule.
        No cloud account or model API key is needed. See `WORKSHOP.md` for the full route.
        '''), code(BOOTSTRAP + '\ncon = open_workshop(raw_only=True)'),
        md('''
        ## 1. Inspect the three source formats
        `raw_eks.event` and `raw_aks.event` contain native Kubernetes audit events.
        `raw_gke.entry` contains a Cloud Logging envelope with `protoPayload`.
        Counts and samples come from your local bundled dataset.
        '''), code('''
        for cloud in ("eks", "gke", "aks"):
            print(cloud, con.sql(f"SELECT count(*) FROM raw_{cloud}").fetchone()[0])
        '''), code('''
        q(con, "SELECT event FROM raw_eks LIMIT 1")
        '''), code('q(con, "SELECT entry FROM raw_gke LIMIT 1")'),
        md('''
        ## 2. Run the same detection in each cloud
        These examples check pod creates with the **first regular container** marked privileged.
        They identify candidates, including benign platform workloads; a hit does not prove an attack.
        EKS/AKS expose `verb` and `objectRef`; GKE encodes the operation in `methodName`.
        Read the SQL before running it. Every detection returns `event_id` for evaluation.
        '''),
    ]
    for cloud in ("eks", "aks", "gke"):
        cells += [md(f'### {cloud.upper()}'), sql_var(f'PRIVILEGED_{cloud.upper()}', PRIVILEGED_POD[cloud])]
    cells += [code('''
        for cloud, sql in {"AWS": PRIVILEGED_EKS, "Azure": PRIVILEGED_AKS, "GCP": PRIVILEGED_GKE}.items():
            print(cloud, con.sql(f"SELECT count(*) FROM ({sql})").fetchone()[0])
        '''), md('''
        ## 3. Practice: change an EKS pod-exec detection
        The baseline is complete. Copy this cell using **Edit → Duplicate Cell**, or insert a code cell
        with the `+` toolbar button. Add namespace, principal, or time filters and inspect the difference.
        `json_extract_string` avoids DuckDB's JSON-arrow operator precedence trap.
        JSON array indexes start at 0; SQL LIST indexes start at 1.
        '''), sql_var('POD_EXEC_EKS', POD_EXEC['eks']), code('''
        # YOUR QUERY: edit this string, then rerun this cell and the comparison below.
        MY_EXEC_SQL = POD_EXEC_EKS + "\\n  AND json_extract_string(event, '$.objectRef.namespace') = 'payments'"
        q(con, MY_EXEC_SQL)
        '''), code('compare(con, MY_EXEC_SQL, POD_EXEC_EKS)'),
        md('''
        A narrower query will normally show missing IDs relative to the broad baseline. That is useful
        feedback, not a notebook failure. Remove your additional filter expression to recover an exact match.
        For the full raw exercise, open `labs/lab1_raw/01_raw_detections.ipynb`; its remaining TODO
        cells intentionally do not pass the grader until you implement them.

        ## 4. Evaluate separately from detection
        The synthetic ground truth labels outputs **after** the rule runs. Never build a detection
        from the ground-truth IDs. Inspect both true hits and benign lookalikes.
        '''), code('evaluate(con, PRIVILEGED_EKS)'),
        md('''
        **Checkpoint:** explain why three SQL variants were necessary and why privileged workloads
        can be benign. Save with Ctrl+S / Cmd+S. Continue with `02_normalized_detections.ipynb`;
        it is independent, so you can close this kernel first to free memory.
        '''), code('# Add your next query below: q(con, "SELECT ...")\n# Leave con open while exploring; shut down this kernel when finished.')]
    return cells


def normalized():
    return [md('''
        # Tutorial 2 — Write a detection once for every cloud (25 minutes)

        Run all cells once. This notebook uses the **completed reference mappings** so it works even
        if you have not finished Lab 2. It does not edit participant SQL files or attach the UI database.
        You will inspect OCSF fields, compare one normalized rule with three raw rules, and write a variation.
        '''), code(BOOTSTRAP + '\ncon = open_workshop(mappings="solutions")'),
        md('''
        ## 1. Learn the normalized schema
        `metadata.uid` is the event ID; `cloud.provider` is AWS/GCP/Azure; `actor.user.name`
        is the source principal; `api.operation` is the Kubernetes verb. `resources[1]` is the first
        resource (SQL LIST indexes start at 1). Pod exec becomes resource type `pods/exec`.
        Nested `api.request.data` retains the Kubernetes pod spec as JSON.
        '''), code('''
        q(con, """
        SELECT cloud.provider, api.operation, resources[1].type AS resource_type, count(*) AS events
        FROM ocsf_api_activity GROUP BY ALL ORDER BY events DESC
        """)
        '''), code('q(con, "DESCRIBE ocsf_api_activity", 30)'),
        md('''
        ## 2. A complete portable privileged-pod rule
        We require a successful create (`status_id = 1`). Kubernetes has several container lists:
        this baseline intentionally checks only `spec.containers[0]`, matching the existing raw exercise.
        You will expand that coverage below. The remaining projection includes enrichment join keys.
        '''), sql_var('PRIVILEGED_SQL', PRIVILEGED),
        code('''
        q(con, f"SELECT provider, count(*) AS hits FROM ({PRIVILEGED_SQL}) GROUP BY ALL ORDER BY 1")
        '''), md('''
        ## 3. Check equivalence to the existing raw rules
        Exact ID equality checks portability on this fixture dataset. It does not demonstrate that every
        hit is malicious, nor guarantee coverage of every real Kubernetes audit format.
        '''), code('''
        from solutions.lab1_raw.rules import PRIVILEGED_POD
        RAW_REFERENCE = " UNION ALL ".join(f"SELECT event_id FROM ({sql})" for sql in PRIVILEGED_POD.values())
        result = compare(con, PRIVILEGED_SQL, RAW_REFERENCE)
        assert result["match"], "Inspect missing/extra event IDs before proceeding"
        '''), md('''
        ## 4. Your rule: pod exec across all three clouds
        Start with the complete example. Then duplicate the practice cell and add filters for a namespace,
        principal, or time range. Run the comparison to see how much the narrower rule drops.
        No cloud-specific JSON paths are necessary for this rule.
        '''), sql_var('EXEC_SQL', EXEC), code('''
        MY_EXEC_SQL = EXEC_SQL  # YOUR QUERY: replace this with your own SQL string.
        q(con, MY_EXEC_SQL)
        '''), code('compare(con, MY_EXEC_SQL, EXEC_SQL)'), code('evaluate(con, MY_EXEC_SQL)'),
        md('''
        ## 5. Worked extension: inspect every regular container
        `json_each` expands the containers array; `EXISTS` avoids duplicating the event if two containers
        are privileged. Edit the JSON path to investigate `initContainers` too, or add a separate condition
        for `hostPID`. A hostPID-only workload is a different rule and should have a different name.
        Missing or null fields must not crash a detection.
        '''), code('''
        ALL_CONTAINERS_SQL = """
        SELECT o.metadata.uid AS event_id, o.cloud.provider AS provider,
               o.actor.user.name AS principal, o.resources[1].namespace AS namespace
        FROM ocsf_api_activity o
        WHERE o.api.operation = 'create' AND o.resources[1].type = 'pods' AND o.status_id = 1
          AND EXISTS (
            SELECT 1 FROM json_each(json_extract(o.api.request.data, '$.spec.containers')) c
            WHERE json_extract_string(c.value, '$.securityContext.privileged') = 'true'
          )
        """
        q(con, ALL_CONTAINERS_SQL)
        '''), code('compare(con, ALL_CONTAINERS_SQL, PRIVILEGED_SQL)'),
        md('''
        This dataset may produce the same hits: that alone does not test the new multi-container case.
        Here is a tiny regression fixture with a privileged **second** container.
        '''), code('''
        second_container_test = con.sql("""
        WITH example AS (
          SELECT json '{"spec":{"containers":[{"securityContext":{"privileged":false}},
                                               {"securityContext":{"privileged":true}}]}}' AS payload
        )
        SELECT EXISTS (
          SELECT 1 FROM json_each(json_extract(payload, '$.spec.containers')) c
          WHERE json_extract_string(c.value, '$.securityContext.privileged') = 'true'
        ) AS detected FROM example
        """).fetchone()[0]
        assert second_container_test
        print("Second-container regression fixture passed")
        '''), md('''
        **Checkpoint:** keep an `event_id` column in your custom rule. Document what it detects,
        required fields, likely benign causes, and information missing from a cloud's logs.
        GKE does not record the exec command URI here, so normalization cannot recover command arguments.

        Optional mapper challenge: edit `labs/lab2_ocsf/*.sql` and run the Lab 2 tests in `WORKSHOP.md`.
        Then change the setup cell to `open_workshop(mappings="participant")` and rerun the notebook.
        Continue with `03_enrichment_and_tuning.ipynb`.
        '''), code('# Add your next query below: q(con, "SELECT ...")')]


def enrichment():
    return [md('''
        # Tutorial 3 — Turn detection candidates into reviewable alerts (25 minutes)

        Run all cells once. This notebook stands alone and uses completed reference mappings.
        You will join inventory and identity context, suppress known platform workloads, and examine
        the false-positive tradeoff of your own tuning rule. Context is evidence, not a verdict.
        '''), code(BOOTSTRAP + '\ncon = open_workshop(mappings="solutions")'),
        md('## 1. Recreate the baseline candidate set'), sql_var('PRIVILEGED_SQL', PRIVILEGED),
        code('con.execute("CREATE OR REPLACE TEMP VIEW privileged_hits AS " + PRIVILEGED_SQL)'),
        md('''
        ## 2. Inspect enrichment inputs
        All fixture data is synthetic. Allowlists match a provider, namespace, owner kind/name, and image
        prefix; identity links connect cloud principals to people. Review those keys before joining.
        '''), code('q(con, "SELECT * FROM privileged_allowlist")'),
        code('q(con, "SELECT * FROM identities")'), code('q(con, "SELECT * FROM clusters")'),
        md('''
        ## 3. Join context without dropping unmatched events
        LEFT JOIN retains hits when inventory is incomplete. Null identity/reputation means unknown,
        not safe. Image-prefix checks model a workshop allowlist, not cryptographic image verification.
        Client OS mismatch is a weak signal and may have benign explanations.
        '''), sql_var('ENRICHED_SQL', ENRICHED),
        code('con.execute("CREATE OR REPLACE TEMP VIEW enriched_hits AS " + ENRICHED_SQL)'),
        code('''
        q(con, """
        SELECT provider, platform_allowlisted, count(*) AS candidates
        FROM enriched_hits GROUP BY ALL ORDER BY 1, 2
        """)
        '''), md('''
        ## 4. Suppress known platform workloads, retain evidence
        This rule leaves non-allowlisted privileged creates for human review. It is not a claim that every
        remaining hit is malicious. The allowlist itself could be wrong or imitated.
        '''), sql_var('REVIEW_SQL', 'SELECT * FROM enriched_hits WHERE NOT platform_allowlisted'),
        code('''
        labels = evaluate(con, REVIEW_SQL)
        print("Candidates for review:", len(labels))
        print("Known attack hits:", int(labels["is_attack"].sum()))
        print("Benign review hits:", int((~labels["is_attack"]).sum()))
        labels
        '''), md('''
        ## 5. Your tuning rule
        The starting query is runnable. Duplicate it and test conditions such as `unapproved_registry`,
        `out_of_office`, `unusual_client`, or source IP reputation. First inspect actual values with
        GROUP BY queries; do not assume a reputation label's spelling.
        Preserve `event_id` so you can compare missed attacks and extra benign hits.
        '''), code('''
        q(con, "SELECT reputation, count(*) AS hits FROM enriched_hits GROUP BY ALL")
        '''), code('''
        # YOUR QUERY: add evidence-based conditions; never filter on evaluation ground-truth IDs.
        MY_REVIEW_SQL = REVIEW_SQL + " AND reputation = 'malicious'"
        q(con, MY_REVIEW_SQL)
        '''), code('''
        compare(con, MY_REVIEW_SQL, REVIEW_SQL)
        tuned_labels = evaluate(con, MY_REVIEW_SQL)
        before = set(labels.loc[labels["is_attack"], "event_id"])
        after = set(tuned_labels.loc[tuned_labels["is_attack"], "event_id"])
        print("Known attack hits lost by tuning:", len(before - after))
        tuned_labels
        '''), md('''
        ### Counterexample: an approved registry does not imply a safe workload
        This deliberately over-restrictive variant keeps only unapproved images. On the bundled
        dataset it removes **all three known attack hits**: the malicious activity used approved images.
        Treat a lower alert count as a tradeoff to measure, not automatic evidence of a better rule.
        '''), code('''
        UNAPPROVED_ONLY_SQL = REVIEW_SQL + " AND unapproved_registry"
        registry_labels = evaluate(con, UNAPPROVED_ONLY_SQL)
        retained = set(registry_labels.loc[registry_labels["is_attack"], "event_id"])
        print("Attack hits lost by requiring an unapproved registry:", len(before - retained))
        registry_labels
        '''), md('''
        ## 6. Explore a second detection: service-account use outside its expected network
        This fixture models networks with string prefixes. In production use actual CIDR membership
        plus workload identity context. These matches are suspicious candidates, not proof of token theft.
        '''), sql_var('SERVICE_ACCOUNT_SQL', '''
        SELECT o.metadata.uid AS event_id, o.cloud.provider AS provider,
               o.actor.user.name AS principal, o.api.operation AS operation,
               o.resources[1].type AS resource_type, o.src_endpoint.ip AS src_ip,
               s.privilege, r.reputation
        FROM ocsf_api_activity o
        JOIN service_accounts s
          ON s.cloud_provider = o.cloud.provider AND s.principal_name = o.actor.user.name
        LEFT JOIN ip_reputation r ON r.ip = o.src_endpoint.ip
        WHERE NOT starts_with(o.src_endpoint.ip, s.in_cluster_ip_prefix)
        '''), code('evaluate(con, SERVICE_ACCOUNT_SQL)'),
        md('''
        **Final deliverable:** save one SQL detection and a short description containing its intent,
        required telemetry, expected benign causes, enrichment joins, and test results. Include at least
        one benign example you would retain for review and one extra fixture that tests an edge case.
        Do not describe recall against the entire attack chain: these rules target only selected steps.
        See `WORKSHOP.md` for sharing SQL in DuckDB UI and the optional mapping/agent exercises.
        '''), code('# Add your next query below: q(con, "SELECT ...")')]


def main():
    for name, cells in (("01_raw_detections", raw()), ("02_normalized_detections", normalized()),
                        ("03_enrichment_and_tuning", enrichment())):
        for index, item in enumerate(cells):
            item["id"] = f"cell-{index:03d}"
        notebook = {"cells": cells, "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}
        path = ROOT / "tutorials" / f"{name}.ipynb"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(notebook, indent=1) + "\n")
        print(path.relative_to(ROOT))


if __name__ == "__main__":
    main()
