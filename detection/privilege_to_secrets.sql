-- Query the full normalized event table; a child relation preserves repeated request subjects.
CREATE OR REPLACE VIEW main.workshop_alerts AS
-- Keep successful cluster-admin grants to users, with one row per granted subject.
-- Retain the source event ID and asset scope so later activity joins to the right grant.
WITH grants AS (
    SELECT e.event_id AS alert_key, e.provider, e.account_uid, e.cluster_name,
           e.time AS grant_time, e.principal AS grant_actor, s.subject, e.role
    FROM enterprise.k8s_ocsf e
    JOIN enterprise.k8s_subjects s
      ON s.provider = e.provider AND s.account_uid = e.account_uid
     AND s.cluster_name = e.cluster_name AND s.event_id = e.event_id
    WHERE e.operation = 'create' AND e.resource_type = 'clusterrolebindings'
      AND e.status_id = 1 AND e.time IS NOT NULL
      AND e.role_kind = 'ClusterRole' AND e.role = 'cluster-admin'
      AND s.subject_kind = 'User'
),
-- Follow the granted subject, who may differ from the actor who created the binding.
-- Match successful cluster-wide secret lists on the same asset within 15 minutes.
sequences AS (
    SELECT g.alert_key, g.provider, g.account_uid, g.cluster_name,
           g.grant_time, g.grant_actor, g.subject, g.role,
           MIN(r.time) AS first_read, MAX(r.time) AS last_read,
           COUNT(DISTINCT r.event_id) AS read_events
    FROM grants g
    JOIN enterprise.k8s_ocsf r
      ON r.provider = g.provider AND r.account_uid = g.account_uid
     AND r.cluster_name = g.cluster_name AND r.principal = g.subject
     AND r.time >= g.grant_time
     AND r.time <= g.grant_time + INTERVAL '15' MINUTE
    WHERE r.resource_type = 'secrets' AND r.operation = 'list'
      AND r.namespace IS NULL AND r.status_id = 1
    GROUP BY g.alert_key, g.provider, g.account_uid, g.cluster_name,
             g.grant_time, g.grant_actor, g.subject, g.role
)
-- Attach a supplied person mapping for attribution; LEFT JOIN keeps unmapped subjects.
-- Return one alert row per grant and subject, with the observed read times and count.
SELECT s.alert_key, s.provider, s.account_uid, s.cluster_name,
       s.grant_time, s.grant_actor, s.subject, s.role,
       s.first_read, s.last_read, s.read_events, i.person_id
FROM sequences s
LEFT JOIN enterprise.identities i
  ON i.cloud_provider = s.provider AND i.account_uid = s.account_uid
 AND i.principal_name = s.subject
-- Suppress only an exact approval for this actor, subject, role and asset at grant time.
-- NOT EXISTS keeps the alert when no matching, currently valid approval is supplied.
WHERE NOT EXISTS (
    SELECT 1 FROM enterprise.approvals a
    WHERE a.cloud_provider = s.provider AND a.account_uid = s.account_uid
      AND a.cluster_name = s.cluster_name AND a.grant_actor = s.grant_actor
      AND a.subject = s.subject AND a.role = s.role
      AND s.grant_time BETWEEN CAST(a.start_time AS TIMESTAMP WITH TIME ZONE)
                           AND CAST(a.end_time AS TIMESTAMP WITH TIME ZONE)
);
