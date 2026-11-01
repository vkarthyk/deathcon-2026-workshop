"""Smoke test: with the reference mappers, one OCSF rule + Lab 4 fixtures isolate exactly the attack."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from workshop.db import ROOT, connect  # noqa: E402

con = connect(mapper_path=ROOT / "solutions" / "lab2_ocsf")
con.sql(f"CREATE VIEW gt AS SELECT * FROM read_csv('{ROOT}/data/raw/ground_truth.csv')")

# Lab 3: one privileged-pod rule for every cloud.
con.sql("""
CREATE VIEW privileged_pods AS
SELECT *,
       api.request.data->>'$.metadata.ownerReferences[0].name' AS owner_name,
       api.request.data->>'$.spec.containers[0].image' AS image
FROM ocsf_api_activity
WHERE api.operation = 'create' AND resources[1].type = 'pods' AND status_id = 1
  AND (api.request.data->>'$.spec.containers[0].securityContext.privileged')::BOOLEAN""")

# Lab 4: drop known-good platform DaemonSets, then attach identity / asset / IP context.
con.sql("""
CREATE VIEW privileged_pods_enriched AS
SELECT p.cloud.provider AS provider, p.time, p.actor.user.name AS principal, p.src_endpoint.ip AS ip,
       p.resources[1].namespace AS ns, p.image,
       coalesce(p.cloud.region, c.region) AS region, c.data_classification,
       i.display_name, i.out_of_office, i.usual_client_os,
       NOT contains(p.http_request.user_agent, i.usual_client_os) AS unusual_client,
       r.reputation, r.as_org, r.tags,
       NOT EXISTS (SELECT 1 FROM approved_registries a WHERE starts_with(p.image, a.registry_prefix)) AS unapproved_registry,
       p.metadata.uid
FROM privileged_pods p
LEFT JOIN privileged_allowlist w
       ON w.cloud_provider = p.cloud.provider AND w.namespace = p.resources[1].namespace
      AND w.owner_name = p.owner_name AND starts_with(p.image, w.image_prefix)
LEFT JOIN clusters c
       ON c.cloud_provider = p.cloud.provider AND c.account_uid = p.cloud.account.uid
      AND c.cluster_name = p.cloud.account.labels['cluster_name']
LEFT JOIN identity_links l ON l.cloud_provider = p.cloud.provider AND l.principal_name = p.actor.user.name
LEFT JOIN identities i ON i.person_id = l.person_id
LEFT JOIN ip_reputation r ON r.ip = p.src_endpoint.ip
WHERE w.owner_name IS NULL""")

raw_hits = con.sql("SELECT count(*) FROM privileged_pods").fetchone()[0]
con.sql("""SELECT provider, region, data_classification, display_name, out_of_office, unusual_client,
                  reputation, as_org, unapproved_registry, uid IN (SELECT auditID FROM gt) AS is_attack
           FROM privileged_pods_enriched ORDER BY time""").show(max_width=250)
print(f"privileged pod creates: {raw_hits} before allowlist")

# Stolen SA token: a service account calling the API from outside its cluster's network.
con.sql("""
SELECT o.cloud.provider AS provider, o.actor.user.name AS principal, o.api.operation AS op,
       o.resources[1].type AS rtype, o.src_endpoint.ip AS ip, s.privilege, r.reputation,
       o.metadata.uid IN (SELECT auditID FROM gt) AS is_attack
FROM ocsf_api_activity o
JOIN service_accounts s ON s.cloud_provider = o.cloud.provider AND s.principal_name = o.actor.user.name
LEFT JOIN ip_reputation r ON r.ip = o.src_endpoint.ip
WHERE NOT starts_with(o.src_endpoint.ip, s.in_cluster_ip_prefix)
ORDER BY o.time""").show(max_width=250)
