-- AKS -> OCSF API Activity (6003)
-- Input: raw_aks(time VARCHAR, resource_id, category, apiserver_pod, event JSON)
-- `event` is the native audit.k8s.io/v1 Event (shipped as a string in properties.log).
-- Extract the Kubernetes verb and HTTP response code from the native audit event.
-- Keep the delivery envelope available for account, cluster and source-log metadata.
WITH src AS (
    SELECT
        *,
        event->>'$.verb' AS verb,
        (event->>'$.responseStatus.code')::INTEGER AS http_code
    FROM raw_aks
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
        log_name := category,
        original_time := time,
        product := struct_pack(name := 'Azure Kubernetes Service', vendor_name := 'Microsoft')
    ) AS metadata,
    -- Identify the cloud account and cluster so downstream joins stay within one asset.
    struct_pack(
        provider := 'Azure',
        region := NULL::VARCHAR,
        account := struct_pack(
            uid := lower(regexp_extract(resource_id, '/SUBSCRIPTIONS/([^/]+)/', 1)), -- @todo[VARCHAR]: subscription ID is embedded in resource_id (/SUBSCRIPTIONS/<id>/...)
            labels := MAP {'cluster_name': lower(regexp_extract(resource_id, '/MANAGEDCLUSTERS/([^/]+)$', 1))} -- @todo[MAP(VARCHAR, VARCHAR)]: cluster name is the last segment of resource_id; Azure upper-cases it but inventory is lower-case
        )
    ) AS cloud,
    -- Retain the native actor and authorization context; person resolution is separate enrichment.
    struct_pack(
        "user" := struct_pack(
            name := event->>'$.user.username',
            uid := event->>'$.user.extra.oid[0]', -- @todo[VARCHAR]: AKS has no user.uid; the Entra object ID is in user.extra
            email_addr := CASE WHEN contains(event->>'$.user.username', '@') THEN event->>'$.user.username' END,
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
        type := concat_ws('/', event->>'$.objectRef.resource', event->>'$.objectRef.subresource'),
        name := event->>'$.objectRef.name',
        namespace := event->>'$.objectRef.namespace'
    )] END AS resources,
    -- In-cluster callers list [client, konnectivity tunnel]; the client is first.
    -- Keep the observed client IP and request metadata for investigation and IP enrichment.
    struct_pack(ip := event->>'$.sourceIPs[0]') AS src_endpoint,
    struct_pack(
        user_agent := event->>'$.userAgent',
        url := struct_pack(path := event->>'$.requestURI')
    ) AS http_request
FROM src
