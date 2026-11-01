-- Detect cluster-admin ClusterRoleBinding create attempts in the EKS audit event.
-- DISTINCT collapses repeated audit-stage records into one binding event per asset.
SELECT DISTINCT json_extract_string(event, '$.auditID') AS event_id,
       'AWS' AS provider, aws_account AS account_uid,
       regexp_extract(log_group, '^/aws/eks/([^/]+)/', 1) AS cluster_name,
       json_extract_string(event, '$.user.username') AS grant_actor,
       json_extract_string(event, '$.requestObject.roleRef.name') AS role
FROM enterprise.raw_eks
-- Match attempts by operation, resource and referenced role; outcome is not filtered here.
-- Check both role kind and name so a different kind with the same name cannot match.
WHERE json_extract_string(event, '$.verb') = 'create'
  AND json_extract_string(event, '$.objectRef.resource') = 'clusterrolebindings'
  AND json_extract_string(event, '$.requestObject.roleRef.kind') = 'ClusterRole'
  AND json_extract_string(event, '$.requestObject.roleRef.name') = 'cluster-admin';
