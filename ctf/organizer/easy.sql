SELECT 'AWS' AS provider, json_extract_string(event, '$.auditID') AS event_id
FROM raw_eks
WHERE json_extract_string(event, '$.verb') = 'create'
  AND json_extract_string(event, '$.objectRef.resource') = 'clusterrolebindings'
  AND json_extract_string(event, '$.requestObject.roleRef.kind') = 'ClusterRole'
  AND json_extract_string(event, '$.requestObject.roleRef.name') = 'cluster-admin'
  AND CAST(json_extract_string(event, '$.responseStatus.code') AS INTEGER) BETWEEN 200 AND 299
UNION ALL
SELECT 'GCP', json_extract_string(entry, '$.operation.id')
FROM raw_gke
WHERE json_extract_string(entry, '$.protoPayload.methodName') = 'io.k8s.authorization.rbac.v1.clusterrolebindings.create'
  AND json_extract_string(entry, '$.protoPayload.request.roleRef.kind') = 'ClusterRole'
  AND json_extract_string(entry, '$.protoPayload.request.roleRef.name') = 'cluster-admin'
  AND COALESCE(CAST(json_extract_string(entry, '$.protoPayload.status.code') AS INTEGER), 0) = 0
UNION ALL
SELECT 'Azure', json_extract_string(event, '$.auditID')
FROM raw_aks
WHERE json_extract_string(event, '$.verb') = 'create'
  AND json_extract_string(event, '$.objectRef.resource') = 'clusterrolebindings'
  AND json_extract_string(event, '$.requestObject.roleRef.kind') = 'ClusterRole'
  AND json_extract_string(event, '$.requestObject.roleRef.name') = 'cluster-admin'
  AND CAST(json_extract_string(event, '$.responseStatus.code') AS INTEGER) BETWEEN 200 AND 299;
