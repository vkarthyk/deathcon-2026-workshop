-- Reference answer: service-account baseline deviation across AWS, GCP and Azure.
-- Facilitator only. Students start from labs/service_account_baseline/detection.sql.

-- 1. Source adapters: one per provider, all producing the same contract.
CREATE OR REPLACE VIEW sa.aws_events AS
WITH src AS (
    SELECT record AS r,
           record->>'$.userIdentity.type' = 'AssumedRole'
           AND NOT starts_with(record->>'$.userIdentity.sessionContext.sessionIssuer.userName', 'AWSReservedSSO_')
               AS is_workload,
           regexp_matches(record->>'$.sourceIPAddress', '^\d{1,3}(\.\d{1,3}){3}$') AS is_ip
    FROM raw.aws_cloudtrail
)
SELECT
    r->>'$.eventID' AS event_id,
    (r->>'$.eventTime')::TIMESTAMPTZ AS time,
    'AWS' AS cloud_provider,
    r->>'$.recipientAccountId' AS account_uid,
    -- Role sessions get a new ARN per session; the issuing role is the stable identity.
    CASE WHEN is_workload THEN r->>'$.userIdentity.sessionContext.sessionIssuer.arn'
         ELSE r->>'$.userIdentity.arn' END AS principal,
    CASE WHEN is_workload THEN 'service_account' ELSE 'human' END AS principal_type,
    r->>'$.eventName' AS cloud_api_action,
    -- A service acting on the caller's behalf reports its own name, not a client address.
    CASE WHEN is_ip THEN r->>'$.sourceIPAddress' END AS source_ip,
    CASE WHEN is_ip THEN r->>'$.userAgent' END AS user_agent,
    CASE WHEN r->>'$.errorCode' IS NULL THEN 1 ELSE 2 END AS status_id
FROM src;

CREATE OR REPLACE VIEW sa.gcp_events AS
WITH src AS (SELECT record AS r FROM raw.gcp_audit)
SELECT
    r->>'$.insertId' AS event_id,
    (r->>'$.timestamp')::TIMESTAMPTZ AS time,
    'GCP' AS cloud_provider,
    r->>'$.resource.labels.project_id' AS account_uid,
    r->>'$.protoPayload.authenticationInfo.principalEmail' AS principal,
    CASE WHEN ends_with(r->>'$.protoPayload.authenticationInfo.principalEmail', '.gserviceaccount.com')
         THEN 'service_account' ELSE 'human' END AS principal_type,
    r->>'$.protoPayload.methodName' AS cloud_api_action,
    CASE WHEN regexp_matches(r->>'$.protoPayload.requestMetadata.callerIp', '^\d{1,3}(\.\d{1,3}){3}$')
         THEN r->>'$.protoPayload.requestMetadata.callerIp' END AS source_ip,
    r->>'$.protoPayload.requestMetadata.callerSuppliedUserAgent' AS user_agent,
    -- A missing or zero gRPC status code means success.
    CASE WHEN coalesce((r->>'$.protoPayload.status.code')::INTEGER, 0) = 0 THEN 1 ELSE 2 END AS status_id
FROM src;

CREATE OR REPLACE VIEW sa.azure_events AS
WITH src AS (SELECT record AS r FROM raw.azure_activity)
SELECT
    r->>'$.eventDataId' AS event_id,
    (r->>'$.time')::TIMESTAMPTZ AS time,
    'Azure' AS cloud_provider,
    split_part(r->>'$.resourceId', '/', 3) AS account_uid,
    -- Application ID is the stable service-principal identity; caller is an object ID.
    CASE WHEN r->>'$.identity.claims.idtyp' = 'app' THEN r->>'$.identity.claims.appid'
         ELSE r->>'$.caller' END AS principal,
    CASE WHEN r->>'$.identity.claims.idtyp' = 'app' THEN 'service_account' ELSE 'human' END AS principal_type,
    r->>'$.operationName' AS cloud_api_action,
    CASE WHEN regexp_matches(r->>'$.callerIpAddress', '^\d{1,3}(\.\d{1,3}){3}$')
         THEN r->>'$.callerIpAddress' END AS source_ip,
    NULL::VARCHAR AS user_agent,
    -- Start events precede the outcome; they are not a second success.
    CASE r->>'$.resultType' WHEN 'Success' THEN 1 WHEN 'Failure' THEN 2 ELSE 0 END AS status_id
FROM src;

-- Supplied: one table for every provider, with shared action types from the catalog.
CREATE OR REPLACE VIEW sa.events AS
SELECT e.*, c.action_type, c.service_category
FROM (SELECT * FROM sa.aws_events
      UNION ALL BY NAME SELECT * FROM sa.gcp_events
      UNION ALL BY NAME SELECT * FROM sa.azure_events) e
LEFT JOIN ref.action_catalog c USING (cloud_provider, cloud_api_action);

-- 2. Observations: one row per comparable value of a successful service-account event.
CREATE OR REPLACE VIEW sa.observations AS
WITH ok AS (
    SELECT * FROM sa.events WHERE principal_type = 'service_account' AND status_id = 1
)
SELECT cloud_provider, account_uid, principal, time, event_id,
       'action' AS dimension, coalesce(action_type, cloud_api_action) AS observed_value
FROM ok
UNION ALL
SELECT cloud_provider, account_uid, principal, time, event_id,
       'source_network', regexp_replace(source_ip, '\.\d+$', '.0/24')
FROM ok WHERE source_ip IS NOT NULL
UNION ALL
SELECT cloud_provider, account_uid, principal, time, event_id,
       'user_agent', lower(trim(split_part(user_agent, '/', 1)))
FROM ok WHERE user_agent IS NOT NULL;

-- 3. Baseline: what each principal did in each account during the learning window.
CREATE OR REPLACE VIEW sa.baseline AS
SELECT o.cloud_provider, o.account_uid, o.principal, o.dimension, o.observed_value,
       min(o.time) AS first_seen, max(o.time) AS last_seen, count(*) AS event_count
FROM sa.observations o, lab.detection_window w
WHERE o.time >= w.baseline_start AND o.time < w.detection_start
GROUP BY ALL;

CREATE OR REPLACE VIEW sa.baseline_coverage AS
SELECT o.cloud_provider, o.account_uid, o.principal,
       count(DISTINCT date_trunc('day', o.time)) AS baseline_days
FROM sa.observations o, lab.detection_window w
WHERE o.time >= w.baseline_start AND o.time < w.detection_start AND o.dimension = 'action'
GROUP BY ALL;

CREATE OR REPLACE VIEW sa.detection_observations AS
SELECT o.* FROM sa.observations o, lab.detection_window w
WHERE o.time >= w.detection_start AND o.time < w.detection_end;

-- 4. Deviations: a value this principal never produced in this account, one row per value.
CREATE OR REPLACE VIEW sa.deviations AS
SELECT d.cloud_provider, d.account_uid, d.principal, d.dimension, d.observed_value,
       min(d.time) AS first_seen, max(d.time) AS last_seen, count(*) AS event_count,
       min(d.event_id) AS sample_event_id
FROM sa.detection_observations d
JOIN sa.baseline_coverage c USING (cloud_provider, account_uid, principal)
CROSS JOIN lab.detection_window w
WHERE c.baseline_days >= w.min_baseline_days
  AND NOT EXISTS (
      SELECT 1 FROM sa.baseline b
      WHERE b.cloud_provider = d.cloud_provider AND b.account_uid = d.account_uid
        AND b.principal = d.principal AND b.dimension = d.dimension
        AND b.observed_value = d.observed_value)
GROUP BY d.cloud_provider, d.account_uid, d.principal, d.dimension, d.observed_value;

-- 5. Principals active now without enough history to baseline: review separately.
CREATE OR REPLACE VIEW sa.insufficient_baseline AS
SELECT d.cloud_provider, d.account_uid, d.principal,
       coalesce(max(c.baseline_days), 0) AS baseline_days,
       count(DISTINCT d.event_id) AS detection_events
FROM sa.detection_observations d
LEFT JOIN sa.baseline_coverage c USING (cloud_provider, account_uid, principal)
CROSS JOIN lab.detection_window w
WHERE coalesce(c.baseline_days, 0) < w.min_baseline_days
GROUP BY d.cloud_provider, d.account_uid, d.principal;
