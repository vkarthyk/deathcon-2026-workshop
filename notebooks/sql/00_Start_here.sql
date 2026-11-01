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

-- READ FIRST — 1. Explore the enterprise day
--
-- What this does: Count normalized activity and its time range by provider.
--
-- What to look for: Compare event counts and first/last timestamps across providers to understand the dataset’s size and time coverage. Later queries explore the activity and suspicious sequences.
--
-- Your next step: Start with provider and time filters instead of reading every event.
--
-- Read this cell; run the SQL cell immediately below it.

-- %%

-- TODO: Narrow the provider and time range before aggregating. What changes?
-- Count normalized activity and its time range by provider.
-- Compare event counts and first/last timestamps across providers to understand the dataset’s size and time coverage. Later queries explore the activity and suspicious sequences.
SELECT provider, count(*) AS events, min(time) AS first_seen, max(time) AS last_seen
FROM enterprise.k8s_ocsf GROUP BY provider ORDER BY provider;

-- %%

-- READ FIRST — 2. Inventory the available activity
--
-- What this does: Group activity by provider, operation and resource.
--
-- What to look for: Compare counts by provider, operation and resource_type. This inventory does not identify behavioral sequences.
--
-- Your next step: Locate create operations on clusterrolebindings and list operations on secrets; notebook 03 correlates them by subject, asset and time.
--
-- Read this cell; run the SQL cell immediately below it.

-- %%

-- TODO: Identify the operations and resources a grant-to-secret-list rule would need.
-- Group activity by provider, operation and resource.
-- Compare counts by provider, operation and resource_type. This inventory does not identify behavioral sequences.
SELECT provider, operation, resource_type, count(*) AS events
FROM enterprise.k8s_ocsf GROUP BY provider, operation, resource_type ORDER BY 1, 2, 3;

-- %%

-- READ FIRST — 3. Inspect the behavioral alerts
--
-- What this does: List sequence matches from the current participant rule (the reference rule unless you have saved edits).
--
-- What to look for: Compare grant actors, granted subjects, grant times and first-read times. alert_key identifies the grant; individual evidence events are not selected here.
--
-- Your next step: Choose an alert_key, then query main.alert_evidence for its source event IDs or use notebook 05.
--
-- Read this cell; run the SQL cell immediately below it.

-- %%

-- TODO: Choose one alert and identify the evidence you would need to review it.
-- List sequence matches from the current participant rule (the reference rule unless you have saved edits).
-- Compare grant actors, granted subjects, grant times and first-read times. alert_key identifies the grant; individual evidence events are not selected here.
SELECT provider, subject, grant_actor, grant_time, first_read, alert_key
FROM main.workshop_alerts ORDER BY grant_time;
