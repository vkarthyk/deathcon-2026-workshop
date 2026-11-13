-- ## SQL quick reference
--
-- Run each query, then use its `TODO` comment and **Try this** task to explore.
-- Single quotes delimit text; double quotes identify SQL columns, not strings.
--
-- | Task | Example |
-- |---|---|
-- | Match text exactly | `resource_type = 'clusterrolebindings'` |
-- | Extract text from raw JSON | `json_extract_string(event, '$.requestURI')` |
-- | Match part of a string | `LIKE '%clusterrolebinding%'` |
-- | Find a missing value | `person_id IS NULL` |
-- | Limit returned rows | `LIMIT 10` |
-- | Filter event time | `time >= TIMESTAMPTZ '2026-10-14 14:00:00+00'` |
--
-- Raw-source queries use JSON paths. Normalized queries use ordinary columns such as
-- `resource_type`, `principal` and `time`. Each SQL cell runs one statement.
-- Open **Need a hint?** only when you get stuck. An empty result can be valid after changing filters.

-- %%

-- READ FIRST — 1. Inspect grant subjects as rows
--
-- What this does: Extend the simple binding detection from notebook 02 into a grant-to-secret-list sequence, using only normalized fields. Join the full Kubernetes event table to its request-subject child relation. Every supported subject in the request gets its own row without duplicating the event table.
--
-- What to look for: Compare grant_actor, subject, subject_kind, role_kind, status_id and event_id. This preview filters only resource_type and role name; it does not yet require a successful create, a User subject or a subsequent secret list.
--
-- Your next step: Compare grant_actor with subject. To inspect the request body, look up event_id in enterprise.k8s_ocsf using provider, account and cluster scope; then choose the detection filter expressions.
--
-- Read this cell; run the SQL cell immediately below it.

-- %%

-- TODO: Compare actor and subject; identify filter expressions still needed for a valid grant.
-- Extend the simple binding detection from notebook 02 into a grant-to-secret-list sequence, using only normalized fields. Join the full Kubernetes event table to its request-subject child relation. Every supported subject in the request gets its own row without duplicating the event table.
-- Compare grant_actor, subject, subject_kind, role_kind, status_id and event_id. This preview filters only resource_type and role name; it does not yet require a successful create, a User subject or a subsequent secret list.
SELECT e.provider, e.principal AS grant_actor, s.subject, s.subject_kind,
       e.role, e.role_kind, e.status_id, e.time AS grant_time, e.event_id
FROM enterprise.k8s_ocsf e
JOIN enterprise.k8s_subjects s
  ON s.provider = e.provider AND s.account_uid = e.account_uid
 AND s.cluster_name = e.cluster_name AND s.event_id = e.event_id
WHERE e.resource_type = 'clusterrolebindings' AND e.role = 'cluster-admin'
ORDER BY e.time;

-- %%

-- READ FIRST — 2. Define your SQL detection
--
-- What this does: We are trying to catch a user receiving cluster-admin privileges and then quickly using that access to list secrets across the cluster, without a matching approved change. This sequence can indicate privilege escalation followed by secret discovery. It is a reason to investigate, not proof of malicious intent.
--
-- The rule below looks for this sequence:
--
-- 1. Someone successfully creates a ClusterRoleBinding granting `cluster-admin` to a **User**.
-- 2. The **granted user** successfully lists secrets cluster-wide within **15 minutes** of the grant, on the same provider, account and cluster. The user receiving access may differ from the actor creating the binding.
-- 3. No approval matches the grant actor, granted user, role and asset at the grant time.
--
-- For example, Alice grants Bob cluster-admin at 10:00, and Bob lists secrets cluster-wide at 10:05. That produces an alert if no matching approval exists. Alice listing secrets, Bob listing them on another cluster, or Bob listing them after the window does not complete this sequence.
--
-- **What this demonstrates:** Notebook 02 detected a single binding event. Here, one rule correlates multiple normalized events across all three clouds, using shared fields for identity, asset scope, success and time. We can change the behavior we detect without repeating provider-specific JSON logic. Normalization supplies consistent fields; the joins and filters supply the detection logic.
--
-- **Your task:** Read the supplied rule, then run it to save `main.workshop_alerts`. Follow the `grants` subquery (who received access), the `sequences` subquery (what they did next), and `NOT EXISTS` (whether the change was approved). The final LEFT JOIN adds a supplied person identity for attribution; it does not decide whether the sequence matches. Inspect the alerts in the next section, then try a rule change while preserving the output columns.
--
-- What to look for: CREATE VIEW defines main.workshop_alerts. The Run your detection section selects its rows.
--
-- Your next step: Save this view definition. Keep alert_key and the asset/subject/time columns needed to retrieve supporting events.
--
-- Read this cell; run the SQL cell immediately below it.

-- %%

-- TODO: Try one rule change, keeping the output keys intact. Save a copy first.
-- We are trying to catch a user receiving cluster-admin privileges and then quickly using that access to list secrets across the cluster, without a matching approved change. This sequence can indicate privilege escalation followed by secret discovery. It is a reason to investigate, not proof of malicious intent.
-- 
-- The rule below looks for this sequence:
-- 
-- 1. Someone successfully creates a ClusterRoleBinding granting `cluster-admin` to a **User**.
-- 2. The **granted user** successfully lists secrets cluster-wide within **15 minutes** of the grant, on the same provider, account and cluster. The user receiving access may differ from the actor creating the binding.
-- 3. No approval matches the grant actor, granted user, role and asset at the grant time.
-- 
-- For example, Alice grants Bob cluster-admin at 10:00, and Bob lists secrets cluster-wide at 10:05. That produces an alert if no matching approval exists. Alice listing secrets, Bob listing them on another cluster, or Bob listing them after the window does not complete this sequence.
-- 
-- **What this demonstrates:** Notebook 02 detected a single binding event. Here, one rule correlates multiple normalized events across all three clouds, using shared fields for identity, asset scope, success and time. We can change the behavior we detect without repeating provider-specific JSON logic. Normalization supplies consistent fields; the joins and filters supply the detection logic.
-- 
-- **Your task:** Read the supplied rule, then run it to save `main.workshop_alerts`. Follow the `grants` subquery (who received access), the `sequences` subquery (what they did next), and `NOT EXISTS` (whether the change was approved). The final LEFT JOIN adds a supplied person identity for attribution; it does not decide whether the sequence matches. Inspect the alerts in the next section, then try a rule change while preserving the output columns.
-- CREATE VIEW defines main.workshop_alerts. The Run your detection section selects its rows.
CREATE OR REPLACE VIEW main.workshop_alerts AS
-- Keep successful cluster-admin grants to users, with one row per granted subject.
-- Retain the source event ID and asset scope so later activity joins to the right grant.
WITH grants AS (
    SELECT e.event_id AS alert_key, e.provider, e.account_uid, e.cluster_name,
           e.time AS grant_time, e.principal AS grant_actor, s.subject, e.role
    FROM enterprise.k8s_ocsf e
    JOIN enterprise.k8s_subjects s
      ON s.provider = e.provider AND s.account_uid = e.account_uid
     AND s.cluster_name = e.cluster_name AND s.event_id = e.event_id
    WHERE e.operation = 'create' AND e.resource_type = 'clusterrolebindings'
      AND e.status_id = 1 AND e.time IS NOT NULL
      AND e.role_kind = 'ClusterRole' AND e.role = 'cluster-admin'
      AND s.subject_kind = 'User'
),
-- Follow the granted subject, who may differ from the actor who created the binding.
-- Match successful cluster-wide secret lists on the same asset within 15 minutes.
sequences AS (
    SELECT g.alert_key, g.provider, g.account_uid, g.cluster_name,
           g.grant_time, g.grant_actor, g.subject, g.role,
           MIN(r.time) AS first_read, MAX(r.time) AS last_read,
           COUNT(DISTINCT r.event_id) AS read_events
    FROM grants g
    JOIN enterprise.k8s_ocsf r
      ON r.provider = g.provider AND r.account_uid = g.account_uid
     AND r.cluster_name = g.cluster_name AND r.principal = g.subject
     AND r.time >= g.grant_time
     AND r.time <= g.grant_time + INTERVAL '15' MINUTE
    WHERE r.resource_type = 'secrets' AND r.operation = 'list'
      AND r.namespace IS NULL AND r.status_id = 1
    GROUP BY g.alert_key, g.provider, g.account_uid, g.cluster_name,
             g.grant_time, g.grant_actor, g.subject, g.role
)
-- Attach a supplied person mapping for attribution; LEFT JOIN keeps unmapped subjects.
-- Return one alert row per grant and subject, with the observed read times and count.
SELECT s.alert_key, s.provider, s.account_uid, s.cluster_name,
       s.grant_time, s.grant_actor, s.subject, s.role,
       s.first_read, s.last_read, s.read_events, i.person_id
FROM sequences s
LEFT JOIN enterprise.identities i
  ON i.cloud_provider = s.provider AND i.account_uid = s.account_uid
 AND i.principal_name = s.subject
-- Suppress only an exact approval for this actor, subject, role and asset at grant time.
-- NOT EXISTS keeps the alert when no matching, currently valid approval is supplied.
WHERE NOT EXISTS (
    SELECT 1 FROM enterprise.approvals a
    WHERE a.cloud_provider = s.provider AND a.account_uid = s.account_uid
      AND a.cluster_name = s.cluster_name AND a.grant_actor = s.grant_actor
      AND a.subject = s.subject AND a.role = s.role
      AND s.grant_time BETWEEN CAST(a.start_time AS TIMESTAMP WITH TIME ZONE)
                           AND CAST(a.end_time AS TIMESTAMP WITH TIME ZONE)
);

-- %%

-- READ FIRST — 3. Run your detection
--
-- What this does: Select alerts from your saved SQL view.
--
-- What to look for: One row per grant and subject, with first/last read times and the number of distinct reads.
--
-- Your next step: Use main.alert_evidence to retrieve individual source event IDs. Evidence is represented as rows rather than arrays.
--
-- Read this cell; run the SQL cell immediately below it.

-- %%

-- TODO: Choose an alert and explain how to retrieve its individual evidence events.
-- Select alerts from your saved SQL view.
-- One row per grant and subject, with first/last read times and the number of distinct reads.
SELECT * FROM main.workshop_alerts ORDER BY grant_time;

-- %%

-- READ FIRST — 4. Inspect audit-stage deduplication
--
-- What this does: Compare the cached source count with the deduplicated event view.
--
-- What to look for: Read duplicate_rows_removed: the cached row count minus the normalized event count. This aggregate does not show which event IDs or audit stages were removed.
--
-- Your next step: To inspect duplicates, group enterprise.event_cache by provider, account_uid, cluster_name and event_id and compare those keys with enterprise.k8s_ocsf.
--
-- Read this cell; run the SQL cell immediately below it.

-- %%

-- TODO: How would you find repeated source keys rather than just their total count?
-- Compare the cached source count with the deduplicated event view.
-- Read duplicate_rows_removed: the cached row count minus the normalized event count. This aggregate does not show which event IDs or audit stages were removed.
SELECT (SELECT count(*) FROM enterprise.event_cache) -
       (SELECT count(*) FROM enterprise.k8s_ocsf) AS duplicate_rows_removed;
