-- Lab 04: service-account baseline deviation across AWS, GCP and Azure.
-- Edit this file. Rerun it with lab.run(...) in the notebook or with
--   python -m workshop.service_account_baseline --database artifacts/sa_baseline.duckdb
-- Tables provided: raw.aws_cloudtrail, raw.gcp_audit, raw.azure_activity (one JSON
-- `record` per log line), ref.action_catalog and lab.detection_window.

-- ---------------------------------------------------------------------------
-- 1. Source adapters. Every provider must produce exactly these columns:
--    event_id, time, cloud_provider, account_uid, principal, principal_type
--    ('service_account' or 'human'), cloud_api_action, source_ip, user_agent,
--    status_id (1 success, 2 failure, 0 unknown).
-- ---------------------------------------------------------------------------

-- Worked example: AWS CloudTrail. Read it before mapping GCP and Azure.
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
    -- People sign in through IAM Identity Center roles (AWSReservedSSO_*): keep their session ARN.
    CASE WHEN is_workload THEN r->>'$.userIdentity.sessionContext.sessionIssuer.arn'
         ELSE r->>'$.userIdentity.arn' END AS principal,
    CASE WHEN is_workload THEN 'service_account' ELSE 'human' END AS principal_type,
    r->>'$.eventName' AS cloud_api_action,
    -- A service acting on the caller's behalf reports its own name, not a client address.
    CASE WHEN is_ip THEN r->>'$.sourceIPAddress' END AS source_ip,
    CASE WHEN is_ip THEN r->>'$.userAgent' END AS user_agent,
    CASE WHEN r->>'$.errorCode' IS NULL THEN 1 ELSE 2 END AS status_id
FROM src;

-- TODO: GCP Cloud Audit Logs. Fields live under protoPayload and resource.
CREATE OR REPLACE VIEW sa.gcp_events AS
WITH src AS (SELECT record AS r FROM raw.gcp_audit)
SELECT
    r->>'$.insertId' AS event_id,
    (r->>'$.timestamp')::TIMESTAMPTZ AS time,
    'GCP' AS cloud_provider,
    NULL::VARCHAR AS account_uid,     -- TODO: the project ID in the monitored resource labels
    NULL::VARCHAR AS principal,       -- TODO: the authenticated principal's email
    NULL::VARCHAR AS principal_type,  -- TODO: service-account emails end in .gserviceaccount.com
    r->>'$.protoPayload.methodName' AS cloud_api_action,
    NULL::VARCHAR AS source_ip,       -- TODO: caller IP; values such as 'private' are not addresses
    NULL::VARCHAR AS user_agent,      -- TODO: the caller-supplied user agent
    NULL::INTEGER AS status_id        -- TODO: a missing or zero status code is success
FROM src;

-- TODO: Azure Activity Log. Identity details are in identity.claims.
CREATE OR REPLACE VIEW sa.azure_events AS
WITH src AS (SELECT record AS r FROM raw.azure_activity)
SELECT
    r->>'$.eventDataId' AS event_id,
    (r->>'$.time')::TIMESTAMPTZ AS time,
    'Azure' AS cloud_provider,
    NULL::VARCHAR AS account_uid,     -- TODO: the subscription ID inside resourceId
    NULL::VARCHAR AS principal,       -- TODO: application ID for apps (idtyp = 'app'), else caller
    NULL::VARCHAR AS principal_type,  -- TODO
    r->>'$.operationName' AS cloud_api_action,
    NULL::VARCHAR AS source_ip,       -- TODO
    NULL::VARCHAR AS user_agent,      -- Activity Log does not record a user agent: keep NULL
    NULL::INTEGER AS status_id        -- TODO: resultType Success, Failure, or Start (neither)
FROM src;

-- Supplied: one table for every provider, with shared action types from the catalog.
CREATE OR REPLACE VIEW sa.events AS
SELECT e.*, c.action_type, c.service_category
FROM (SELECT * FROM sa.aws_events
      UNION ALL BY NAME SELECT * FROM sa.gcp_events
      UNION ALL BY NAME SELECT * FROM sa.azure_events) e
LEFT JOIN ref.action_catalog c USING (cloud_provider, cloud_api_action);

-- ---------------------------------------------------------------------------
-- 2-5. The detection. This starter is the simple version: compare exact values
-- with a per-principal baseline. It runs, but it is wrong in several ways.
-- Step 3 of notebooks/04_Detect_service_account_deviations.ipynb lists what to fix. Keep the view names and columns.
-- ---------------------------------------------------------------------------

-- One row per comparable value of a service-account event.
CREATE OR REPLACE VIEW sa.observations AS
WITH ok AS (
    SELECT * FROM sa.events WHERE principal_type = 'service_account'
)
SELECT cloud_provider, account_uid, principal, time, event_id,
       'action' AS dimension, action_type AS observed_value
FROM ok
UNION ALL
SELECT cloud_provider, account_uid, principal, time, event_id, 'source_network', source_ip
FROM ok
UNION ALL
SELECT cloud_provider, account_uid, principal, time, event_id, 'user_agent', user_agent
FROM ok;

-- What each principal did during the learning window.
CREATE OR REPLACE VIEW sa.baseline AS
SELECT o.principal, o.dimension, o.observed_value,
       min(o.time) AS first_seen, max(o.time) AS last_seen, count(*) AS event_count
FROM sa.observations o, lab.detection_window w
WHERE o.time >= w.baseline_start AND o.time < w.detection_start
GROUP BY ALL;

-- How many distinct days of history each principal has.
CREATE OR REPLACE VIEW sa.baseline_coverage AS
SELECT o.cloud_provider, o.account_uid, o.principal,
       count(DISTINCT date_trunc('day', o.time)) AS baseline_days
FROM sa.observations o, lab.detection_window w
WHERE o.time >= w.baseline_start AND o.time < w.detection_start AND o.dimension = 'action'
GROUP BY ALL;

CREATE OR REPLACE VIEW sa.detection_observations AS
SELECT o.* FROM sa.observations o, lab.detection_window w
WHERE o.time >= w.detection_start AND o.time < w.detection_end;

-- A value never seen in the baseline, one row per new value.
CREATE OR REPLACE VIEW sa.deviations AS
SELECT d.cloud_provider, d.account_uid, d.principal, d.dimension, d.observed_value,
       min(d.time) AS first_seen, max(d.time) AS last_seen, count(*) AS event_count,
       min(d.event_id) AS sample_event_id
FROM sa.detection_observations d
WHERE NOT EXISTS (
    SELECT 1 FROM sa.baseline b
    WHERE b.principal = d.principal AND b.dimension = d.dimension
      AND b.observed_value = d.observed_value)
GROUP BY d.cloud_provider, d.account_uid, d.principal, d.dimension, d.observed_value;

-- TODO: principals active in the detection window with fewer than
-- min_baseline_days of history. They cannot be baselined: list them here
-- instead of in sa.deviations.
CREATE OR REPLACE VIEW sa.insufficient_baseline AS
SELECT NULL::VARCHAR AS cloud_provider, NULL::VARCHAR AS account_uid, NULL::VARCHAR AS principal,
       NULL::BIGINT AS baseline_days, NULL::BIGINT AS detection_events
WHERE false;
