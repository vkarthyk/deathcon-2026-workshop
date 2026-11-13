-- Rule update: one shared outcome filter expression keeps successful attempts across all providers.
-- Ingestion has already mapped asset keys, native identity and role references.
SELECT event_id, provider, account_uid, cluster_name, principal AS grant_actor, role
FROM enterprise.k8s_ocsf
-- Filter RBAC changes from the full event table, which also includes pods, secrets and other resources.
-- This flags a powerful access change for review, not proof of compromise or subsequent secret access.
WHERE operation = 'create' AND resource_type = 'clusterrolebindings'
  AND status_id = 1
  AND role_kind = 'ClusterRole' AND role = 'cluster-admin';
