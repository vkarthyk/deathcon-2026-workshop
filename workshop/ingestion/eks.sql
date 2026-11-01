-- EKS -> OCSF API Activity (6003)
-- Input: raw_eks(aws_account, log_group, log_stream, cw_timestamp_ms, event JSON)
-- `event` is the native audit.k8s.io/v1 Event; the envelope only adds account + log group.
-- Extract the Kubernetes verb and HTTP response code from the native audit event.
-- Keep the delivery envelope available for account, cluster and source-log metadata.
WITH src AS (
    SELECT
        *,
        event->>'$.verb' AS verb,
        (event->>'$.responseStatus.code')::INTEGER AS http_code
    FROM raw_eks
)
-- Build one OCSF API Activity record per source event, preserving event time and identity.
-- Nested objects retain cloud scope, actor, request/response, resource and client context.
SELECT
    6003 AS class_uid,
    6 AS category_uid,
    k8s_activity_id(verb) AS activity_id,
    k8s_activity_name(k8s_activity_id(verb)) AS activity_name,
    600300 + k8s_activity_id(verb) AS type_uid,
    (event->>'$.requestReceivedTimestamp')::TIMESTAMPTZ AS time,
    http_status_id(http_code) AS status_id,
    status_name(http_status_id(http_code)) AS status,
    http_code::VARCHAR AS status_code,
    -- Preserve the source event ID and log provenance for evidence retrieval.
    struct_pack(
        uid := event->>'$.auditID',
        version := '1.3.0',
        log_name := log_group,
        original_time := event->>'$.requestReceivedTimestamp',
        product := struct_pack(name := 'Amazon EKS', vendor_name := 'AWS')
    ) AS metadata,
    -- Identify the cloud account and cluster so downstream joins stay within one asset.
    struct_pack(
        provider := 'AWS',
        region := NULL::VARCHAR,
        account := struct_pack(
            uid := aws_account,
            labels := MAP {'cluster_name': regexp_extract(log_group, '^/aws/eks/([^/]+)/', 1)} -- @todo[MAP(VARCHAR, VARCHAR)]: the cluster name is only in the CloudWatch log group (/aws/eks/<cluster>/cluster)
        )
    ) AS cloud,
    -- Retain the native actor and authorization context; person resolution is separate enrichment.
    struct_pack(
        "user" := struct_pack(
            name := event->>'$.user.username',
            uid := event->>'$.user.uid',
            email_addr := CASE WHEN contains(event->>'$.user.extra.sessionName[0]', '@') THEN event->>'$.user.extra.sessionName[0]' END, -- @todo[VARCHAR]: the username is an assumed-role ARN; where does the person's email live?
            type := k8s_user_type(event->>'$.user.username'),
            type_id := k8s_user_type_id(event->>'$.user.username'),
            groups := list_transform((event->'$.user.groups')::VARCHAR[], lambda g: struct_pack(name := g))
        ),
        authorizations := [struct_pack(
            decision := event->>'$.annotations."authorization.k8s.io/decision"',
            policy := struct_pack(name := event->>'$.annotations."authorization.k8s.io/reason"')
        )]
    ) AS actor,
    -- Preserve the API operation and request body needed to identify granted roles and subjects.
    struct_pack(
        operation := verb,
        version := event->>'$.objectRef.apiVersion',
        service := struct_pack(name := 'kubernetes'),
        "group" := struct_pack(name := coalesce(event->>'$.objectRef.apiGroup', 'core')),
        request := struct_pack(uid := event->>'$.auditID', data := event->'$.requestObject'),
        response := struct_pack(code := http_code, message := event->>'$.responseStatus.message',
                                data := event->'$.responseObject')
    ) AS api,
    -- Represent the affected Kubernetes object, including namespace and optional subresource.
    CASE WHEN (event->'$.objectRef') IS NULL THEN [] ELSE [struct_pack(
        type := concat_ws('/', event->>'$.objectRef.resource', event->>'$.objectRef.subresource'), -- @todo[VARCHAR]: RBAC-style type, e.g. 'pods' or 'pods/exec'
        name := event->>'$.objectRef.name',
        namespace := event->>'$.objectRef.namespace'
    )] END AS resources,
    -- Keep the observed client IP and request metadata for investigation and IP enrichment.
    struct_pack(ip := event->>'$.sourceIPs[0]') AS src_endpoint,
    struct_pack(
        user_agent := event->>'$.userAgent',
        url := struct_pack(path := event->>'$.requestURI')
    ) AS http_request
FROM src
