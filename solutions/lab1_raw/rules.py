"""Lab 1 reference answers: each rule written once per cloud against the raw logs.

Uses json_extract_string() rather than ->>: in DuckDB ->> binds looser than AND / =.

Every query returns one row per hit with an `event_id` column (auditID; operation.id on GKE).
"""

PRIVILEGED_POD = {
    "eks": """
SELECT json_extract_string(event, '$.auditID') AS event_id,
       json_extract_string(event, '$.user.username') AS principal,
       json_extract_string(event, '$.objectRef.namespace') AS namespace,
       json_extract_string(event, '$.requestObject.spec.containers[0].image') AS image
FROM raw_eks
WHERE json_extract_string(event, '$.verb') = 'create'
  AND json_extract_string(event, '$.objectRef.resource') = 'pods'
  AND json_extract_string(event, '$.objectRef.subresource') IS NULL
  AND json_extract_string(event, '$.requestObject.spec.containers[0].securityContext.privileged') = 'true'
""",
    "aks": """
SELECT json_extract_string(event, '$.auditID') AS event_id,
       json_extract_string(event, '$.user.username') AS principal,
       json_extract_string(event, '$.objectRef.namespace') AS namespace,
       json_extract_string(event, '$.requestObject.spec.containers[0].image') AS image
FROM raw_aks
WHERE json_extract_string(event, '$.verb') = 'create'
  AND json_extract_string(event, '$.objectRef.resource') = 'pods'
  AND json_extract_string(event, '$.objectRef.subresource') IS NULL
  AND json_extract_string(event, '$.requestObject.spec.containers[0].securityContext.privileged') = 'true'
""",
    "gke": """
SELECT json_extract_string(entry, '$.operation.id') AS event_id,
       json_extract_string(entry, '$.protoPayload.authenticationInfo.principalEmail') AS principal,
       split_part(json_extract_string(entry, '$.protoPayload.resourceName'), '/', 4) AS namespace,
       json_extract_string(entry, '$.protoPayload.request.spec.containers[0].image') AS image
FROM raw_gke
WHERE json_extract_string(entry, '$.protoPayload.methodName') = 'io.k8s.core.v1.pods.create'
  AND json_extract_string(entry, '$.protoPayload.request.spec.containers[0].securityContext.privileged') = 'true'
""",
}

POD_EXEC = {
    "eks": """
SELECT json_extract_string(event, '$.auditID') AS event_id,
       json_extract_string(event, '$.user.username') AS principal,
       json_extract_string(event, '$.sourceIPs[0]') AS src_ip,
       json_extract_string(event, '$.objectRef.name') AS pod
FROM raw_eks
WHERE json_extract_string(event, '$.verb') = 'create'
  AND json_extract_string(event, '$.objectRef.resource') = 'pods'
  AND json_extract_string(event, '$.objectRef.subresource') = 'exec'
""",
    "aks": """
SELECT json_extract_string(event, '$.auditID') AS event_id,
       json_extract_string(event, '$.user.username') AS principal,
       json_extract_string(event, '$.sourceIPs[0]') AS src_ip,
       json_extract_string(event, '$.objectRef.name') AS pod
FROM raw_aks
WHERE json_extract_string(event, '$.verb') = 'create'
  AND json_extract_string(event, '$.objectRef.resource') = 'pods'
  AND json_extract_string(event, '$.objectRef.subresource') = 'exec'
""",
    "gke": """
SELECT json_extract_string(entry, '$.operation.id') AS event_id,
       json_extract_string(entry, '$.protoPayload.authenticationInfo.principalEmail') AS principal,
       json_extract_string(entry, '$.protoPayload.requestMetadata.callerIp') AS src_ip,
       split_part(json_extract_string(entry, '$.protoPayload.resourceName'), '/', 6) AS pod
FROM raw_gke
WHERE json_extract_string(entry, '$.protoPayload.methodName') = 'io.k8s.core.v1.pods.exec.create'
""",
}

# Stretch: only execs that break out to the host. The command lives in the request URI, which GKE never logs.
HOST_ESCAPE_EXEC = {
    cloud: POD_EXEC[cloud].rstrip() + "\n  AND json_extract_string(event, '$.requestURI') LIKE '%command=nsenter%'\n"
    for cloud in ("eks", "aks")
}

RULES = {"privileged_pod": PRIVILEGED_POD, "pod_exec": POD_EXEC, "host_escape_exec": HOST_ESCAPE_EXEC}
