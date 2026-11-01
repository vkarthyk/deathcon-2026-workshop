-- Detect the same binding-create attempts in GKE's Cloud Logging AuditLog shape.
-- Event identity, caller identity, asset scope and request fields use different paths from EKS.
SELECT DISTINCT json_extract_string(entry, '$.operation.id') AS event_id,
       'GCP' AS provider,
       json_extract_string(entry, '$.resource.labels.project_id') AS account_uid,
       json_extract_string(entry, '$.resource.labels.cluster_name') AS cluster_name,
       json_extract_string(entry, '$.protoPayload.authenticationInfo.principalEmail') AS grant_actor,
       json_extract_string(entry, '$.protoPayload.request.roleRef.name') AS role
FROM enterprise.raw_gke
-- methodName combines the API group, resource and verb instead of separate Kubernetes fields.
-- Outcome is not filtered here; failed or unknown-outcome attempts can match.
WHERE json_extract_string(entry, '$.protoPayload.methodName') = 'io.k8s.authorization.rbac.v1.clusterrolebindings.create'
  AND json_extract_string(entry, '$.protoPayload.request.roleRef.kind') = 'ClusterRole'
  AND json_extract_string(entry, '$.protoPayload.request.roleRef.name') = 'cluster-admin';
