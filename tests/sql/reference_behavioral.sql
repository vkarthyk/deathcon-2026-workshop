-- One behavioral rule over one canonical event contract, regardless of source cloud.
-- The RBAC actor grants access TO a subject. Follow that subject, not the actor.
CREATE OR REPLACE VIEW behavioral_candidates AS
-- Expand request subjects and keep successful cluster-admin grants to users.
-- Preserve the actor separately from the subject who receives access.
WITH grants AS (
    SELECT e.event_id AS alert_key, e.provider, e.account_uid, e.cluster_name,
           e.time AS grant_time, e.principal AS grant_actor,
           json_extract_string(s.value, '$.name') AS subject,
           json_extract_string(e.request, '$.roleRef.name') AS role
    FROM events e, LATERAL json_each(json_extract(e.request, '$.subjects')) s
    WHERE e.operation = 'create' AND e.resource_type = 'clusterrolebindings'
      AND e.status_id = 1 AND e.time IS NOT NULL
      AND json_extract_string(e.request, '$.roleRef.kind') = 'ClusterRole'
      AND json_extract_string(e.request, '$.roleRef.name') = 'cluster-admin'
      AND json_extract_string(s.value, '$.kind') = 'User'
),
-- Correlate the subject's successful cluster-wide secret lists on the same asset.
-- Aggregate distinct evidence within the inclusive 15-minute window after the grant.
sequences AS (
    SELECT g.*, min(r.time) AS first_read, max(r.time) AS last_read,
           count(DISTINCT r.event_id) AS read_events,
           list_sort(list_distinct(list(r.src_ip))) AS source_ips,
           list_sort(list_distinct(list(r.event_id))) AS read_event_ids
    FROM grants g JOIN events r
      ON r.provider = g.provider AND r.account_uid = g.account_uid AND r.cluster_name = g.cluster_name
     AND r.principal = g.subject
     AND r.time >= g.grant_time AND r.time <= g.grant_time + INTERVAL '15 minutes'
    WHERE r.resource_type = 'secrets' AND r.operation = 'list'
      AND r.namespace IS NULL AND r.status_id = 1
    GROUP BY ALL
)
-- Attach supplied person mappings without dropping subjects that cannot be resolved.
-- Preserve source event IDs as evidence for later triage and reference comparisons.
SELECT s.*, i.person_id, list_prepend(s.alert_key, s.read_event_ids) AS evidence_ids
FROM sequences s LEFT JOIN identities i
  ON i.cloud_provider = s.provider AND i.account_uid = s.account_uid AND i.principal_name = s.subject;

-- Suppression is scoped to the grant actor, subject, role, asset and valid change interval.
CREATE OR REPLACE VIEW behavioral_matches AS
SELECT c.* FROM behavioral_candidates c
WHERE NOT EXISTS (
    SELECT 1 FROM approvals a
    WHERE a.cloud_provider = c.provider AND a.account_uid = c.account_uid
      AND a.cluster_name = c.cluster_name AND a.grant_actor = c.grant_actor
      AND a.subject = c.subject AND a.role = c.role
      AND c.grant_time BETWEEN a.start_time::TIMESTAMPTZ AND a.end_time::TIMESTAMPTZ
);

-- Apply the reference enrichment stage to the unsuppressed sequence matches.
-- Inventory context changes severity while preserving detection membership.
CREATE OR REPLACE VIEW behavioral_alerts AS
SELECT * FROM main.enrich_alerts('behavioral_matches', 'ip_enrichment',
                               'user_enrichment', 'k8s_cluster_enrichment');

-- A bounded batch correlation: corroborate the resolved person across cloud providers.
-- Per-grant alerts remain valid when identity enrichment is absent or only one cloud is involved.
CREATE OR REPLACE VIEW cross_cloud_campaigns AS
SELECT person_id, min(grant_time) AS first_seen, max(last_read) AS last_seen,
       count(DISTINCT provider) AS provider_count, list_sort(list(DISTINCT provider)) AS providers,
       list_sort(list(DISTINCT alert_key)) AS alert_ids,
       list_sort(list_distinct(flatten(list(evidence_ids)))) AS evidence_ids
FROM behavioral_alerts WHERE person_id IS NOT NULL
GROUP BY person_id
HAVING count(DISTINCT provider) >= 2
   AND max(last_read) - min(grant_time) <= INTERVAL '90 minutes';
