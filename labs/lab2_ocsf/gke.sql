-- GKE -> OCSF API Activity (6003)
-- Input: raw_gke(entry JSON) -- one Cloud Logging LogEntry per row.
-- Unlike EKS/AKS there is no native audit Event: GKE re-shapes it into a protoPayload AuditLog,
-- so verb, resource, and status all have to be reverse-engineered.
-- Extract the method, resource path and status from the Cloud Logging payload.
-- Keep gRPC success semantics separate from any HTTP code in an error response.
WITH src AS (
    SELECT
        entry,
        entry->'$.protoPayload' AS p,
        -- methodName = io.k8s.<group>.<version>.<resource>[.<subresource>].<verb>
        NULL::VARCHAR AS verb, -- TODO(lab2): verb is the last dot-segment of protoPayload.methodName
        -- resourceName = <group>/<version>/[namespaces/<ns>/]<resource>[/<name>[/<subresource>]]
        NULL::STRUCT(grp VARCHAR, ver VARCHAR, ns VARCHAR, res VARCHAR, name VARCHAR, sub VARCHAR) AS rn, -- TODO(lab2): parse resourceName into grp/ver/ns/res/name/sub (hint: regexp_extract accepts a list of capture-group names)
        -- Errors carry the k8s Status in `response`; successes carry no HTTP code at all.
        (entry->>'$.protoPayload.response.code')::INTEGER AS http_code,
        coalesce((entry->>'$.protoPayload.status.code')::INTEGER, 0) AS grpc_code
    FROM raw_gke
)
-- Build one OCSF API Activity record per source event, preserving event time and identity.
-- Nested objects retain cloud scope, actor, request/response, resource and client context.
SELECT
    6003 AS class_uid,
    6 AS category_uid,
    k8s_activity_id(verb) AS activity_id,
    k8s_activity_name(k8s_activity_id(verb)) AS activity_name,
    600300 + k8s_activity_id(verb) AS type_uid,
    (entry->>'$.timestamp')::TIMESTAMPTZ AS time,
    NULL::INTEGER AS status_id, -- TODO(lab2): protoPayload.status is a google.rpc.Status - code 0/absent means OK
    status_name(status_id) AS status,
    http_code::VARCHAR AS status_code,
    -- Preserve the source event ID and log provenance for evidence retrieval.
    struct_pack(
        uid := entry->>'$.operation.id',
        version := '1.3.0',
        log_name := entry->>'$.logName',
        original_time := entry->>'$.timestamp',
        product := struct_pack(name := 'Google Kubernetes Engine', vendor_name := 'Google Cloud')
    ) AS metadata,
    -- Identify the cloud account and cluster so downstream joins stay within one asset.
    struct_pack(
        provider := 'GCP',
        region := entry->>'$.resource.labels.location',
        account := struct_pack(
            uid := entry->>'$.resource.labels.project_id',
            labels := MAP {'cluster_name': entry->>'$.resource.labels.cluster_name'}
        )
    ) AS cloud,
    -- Retain the native actor and authorization context; person resolution is separate enrichment.
    struct_pack(
        "user" := struct_pack(
            name := p->>'$.authenticationInfo.principalEmail',
            uid := NULL::VARCHAR,
            email_addr := CASE WHEN contains(p->>'$.authenticationInfo.principalEmail', '@')
                               THEN p->>'$.authenticationInfo.principalEmail' END,
            type := k8s_user_type(p->>'$.authenticationInfo.principalEmail'),
            type_id := k8s_user_type_id(p->>'$.authenticationInfo.principalEmail'),
            -- GKE audit logs drop group membership entirely.
            groups := NULL::STRUCT(name VARCHAR)[]
        ),
        authorizations := [struct_pack(
            decision := entry->>'$.labels."authorization.k8s.io/decision"',
            policy := struct_pack(name := entry->>'$.labels."authorization.k8s.io/reason"')
        )]
    ) AS actor,
    -- Preserve the API operation and request body needed to identify granted roles and subjects.
    struct_pack(
        operation := verb,
        version := rn.ver,
        service := struct_pack(name := 'kubernetes'),
        "group" := struct_pack(name := rn.grp),
        request := struct_pack(uid := entry->>'$.operation.id', data := p->'$.request'),
        response := struct_pack(code := http_code, message := p->>'$.response.message', data := p->'$.response')
    ) AS api,
    -- Represent the affected Kubernetes object, including namespace and optional subresource.
    CASE WHEN rn.res IS NULL OR rn.res = '' THEN [] ELSE [struct_pack(
        type := concat_ws('/', rn.res, nullif(rn.sub, '')),
        name := nullif(rn.name, ''),
        namespace := nullif(rn.ns, '')
    )] END AS resources,
    -- Keep the observed client IP and request metadata for investigation and IP enrichment.
    struct_pack(ip := p->>'$.requestMetadata.callerIp') AS src_endpoint,
    struct_pack(
        user_agent := p->>'$.requestMetadata.callerSuppliedUserAgent',
        -- GKE never logs the request URI, so exec command args are not recoverable.
        url := struct_pack(path := NULL::VARCHAR)
    ) AS http_request
FROM src
