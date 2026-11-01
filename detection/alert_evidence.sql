-- Evidence is a relation: one supporting event per alert/subject, not an engine-specific list.
CREATE OR REPLACE VIEW main.alert_evidence AS
-- Retrieve the original RBAC grant using its source event ID and full asset scope.
-- Keep the alert subject on each evidence row to distinguish multi-subject grants.
SELECT a.alert_key, a.provider, a.account_uid, a.cluster_name, a.subject,
       e.event_id, e.time, e.principal, e.src_ip, 'grant' AS evidence_kind
FROM main.workshop_alerts a
JOIN enterprise.k8s_ocsf e
  ON e.provider = a.provider AND e.account_uid = a.account_uid
 AND e.cluster_name = a.cluster_name AND e.event_id = a.alert_key
UNION ALL
-- Append successful cluster-wide secret lists by the granted subject on the same asset.
-- Use the alert's observed read interval to return the events that support its sequence.
SELECT a.alert_key, a.provider, a.account_uid, a.cluster_name, a.subject,
       e.event_id, e.time, e.principal, e.src_ip, 'secret_list' AS evidence_kind
FROM main.workshop_alerts a
JOIN enterprise.k8s_ocsf e
  ON e.provider = a.provider AND e.account_uid = a.account_uid
 AND e.cluster_name = a.cluster_name AND e.principal = a.subject
 AND e.time BETWEEN a.first_read AND a.last_read
WHERE e.resource_type = 'secrets' AND e.operation = 'list'
  AND e.namespace IS NULL AND e.status_id = 1;
