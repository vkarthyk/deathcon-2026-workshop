WITH grants AS (
    SELECT e.*, s.subject
    FROM k8s_ocsf e
    JOIN k8s_subjects s USING (provider, account_uid, cluster_name, event_id)
    WHERE e.operation = 'create' AND e.resource_type = 'clusterrolebindings'
      AND e.status_id = 1 AND e.role_kind = 'ClusterRole' AND e.role = 'cluster-admin'
      AND s.subject_kind = 'User'
), matches AS (
    SELECT g.event_id AS grant_id, r.event_id AS read_id
    FROM grants g
    JOIN k8s_ocsf r
      ON r.provider = g.provider AND r.account_uid = g.account_uid
     AND r.cluster_name = g.cluster_name AND r.principal = g.subject
     AND r.time >= g.time AND r.time <= g.time + INTERVAL '15' MINUTE
    WHERE r.operation = 'list' AND r.resource_type = 'secrets'
      AND r.namespace IS NULL AND r.status_id = 1
      AND NOT EXISTS (
          SELECT 1 FROM approvals a
          WHERE a.cloud_provider = g.provider AND a.account_uid = g.account_uid
            AND a.cluster_name = g.cluster_name AND a.grant_actor = g.principal
            AND a.subject = g.subject AND a.role = g.role
            AND g.time BETWEEN a.start_time AND a.end_time
      )
)
SELECT DISTINCT grant_id, read_id FROM matches;
