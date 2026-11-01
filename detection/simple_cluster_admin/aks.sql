-- AKS retains the native Kubernetes audit fields, so its behavioral filters resemble EKS.
-- Asset scope comes from Azure's resource ID and needs casing aligned with the inventory.
SELECT DISTINCT json_extract_string(event, '$.auditID') AS event_id,
       'Azure' AS provider,
       lower(regexp_extract(resource_id, '/SUBSCRIPTIONS/([^/]+)/', 1)) AS account_uid,
       lower(regexp_extract(resource_id, '/MANAGEDCLUSTERS/([^/]+)$', 1)) AS cluster_name,
       json_extract_string(event, '$.user.username') AS grant_actor,
       json_extract_string(event, '$.requestObject.roleRef.name') AS role
FROM enterprise.raw_aks
-- Match a cluster-wide binding create attempt with the exact referenced role.
-- Keep the same detection meaning as EKS despite the different delivery envelope.
WHERE json_extract_string(event, '$.verb') = 'create'
  AND json_extract_string(event, '$.objectRef.resource') = 'clusterrolebindings'
  AND json_extract_string(event, '$.requestObject.roleRef.kind') = 'ClusterRole'
  AND json_extract_string(event, '$.requestObject.roleRef.name') = 'cluster-admin';
