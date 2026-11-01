"""Facilitator answers for the ten-field, binding-only normalization exercise."""
HTTP_STATUS = "CASE WHEN CAST(json_extract_string(event, '$.responseStatus.code') AS INTEGER) BETWEEN 200 AND 299 THEN 1 WHEN json_extract_string(event, '$.responseStatus.code') IS NULL THEN 0 ELSE 2 END"
MAPPINGS = {
    'eks': {
        'event_id': "json_extract_string(event, '$.auditID')",
        'account_uid': 'aws_account',
        'cluster_name': "regexp_extract(log_group, '^/aws/eks/([^/]+)/', 1)",
        'principal': "json_extract_string(event, '$.user.username')",
        'operation': "json_extract_string(event, '$.verb')",
        'resource_type': "json_extract_string(event, '$.objectRef.resource')",
        'status_id': HTTP_STATUS,
        'role_kind': "json_extract_string(event, '$.requestObject.roleRef.kind')",
        'role': "json_extract_string(event, '$.requestObject.roleRef.name')",
    },
    'gke': {
        'event_id': "json_extract_string(entry, '$.operation.id')",
        'account_uid': "json_extract_string(entry, '$.resource.labels.project_id')",
        'cluster_name': "json_extract_string(entry, '$.resource.labels.cluster_name')",
        'principal': "json_extract_string(entry, '$.protoPayload.authenticationInfo.principalEmail')",
        'operation': "split_part(json_extract_string(entry, '$.protoPayload.methodName'), '.', -1)",
        'resource_type': "split_part(json_extract_string(entry, '$.protoPayload.methodName'), '.', -2)",
        'status_id': "CASE WHEN COALESCE(CAST(json_extract_string(entry, '$.protoPayload.status.code') AS INTEGER), 0) = 0 THEN 1 ELSE 2 END",
        'role_kind': "json_extract_string(entry, '$.protoPayload.request.roleRef.kind')",
        'role': "json_extract_string(entry, '$.protoPayload.request.roleRef.name')",
    },
    'aks': {
        'event_id': "json_extract_string(event, '$.auditID')",
        'account_uid': "lower(regexp_extract(resource_id, '/SUBSCRIPTIONS/([^/]+)/', 1))",
        'cluster_name': "lower(regexp_extract(resource_id, '/MANAGEDCLUSTERS/([^/]+)$', 1))",
        'principal': "json_extract_string(event, '$.user.username')",
        'operation': "json_extract_string(event, '$.verb')",
        'resource_type': "json_extract_string(event, '$.objectRef.resource')",
        'status_id': HTTP_STATUS,
        'role_kind': "json_extract_string(event, '$.requestObject.roleRef.kind')",
        'role': "json_extract_string(event, '$.requestObject.roleRef.name')",
    },
}
