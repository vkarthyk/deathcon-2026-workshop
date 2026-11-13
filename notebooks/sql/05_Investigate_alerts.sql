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

-- READ FIRST — 1. Select an alert from your rule
--
-- What this does: List alerts produced by the current participant rule.
--
-- What to look for: Each row links an alert and its asset/subject keys to a supporting event_id and evidence_kind. Multiple evidence rows can belong to one alert; event bodies are not selected here.
--
-- Your next step: Choose an alert and retain its alert_key, provider, account_uid, cluster_name and subject. Add filters on these keys inside the next query’s chosen subquery to investigate it instead of the default earliest alert.
--
-- Read this cell; run the SQL cell immediately below it.

-- %%

-- TODO: Choose an alert, keeping its asset and subject keys for the timeline below.
-- List alerts produced by the current participant rule.
-- Each row links an alert and its asset/subject keys to a supporting event_id and evidence_kind. Multiple evidence rows can belong to one alert; event bodies are not selected here.
SELECT a.alert_key, a.provider, a.account_uid, a.cluster_name,
       a.subject, a.grant_time, e.event_id, e.evidence_kind
FROM main.workshop_alerts a
JOIN main.alert_evidence e
  ON e.alert_key = a.alert_key AND e.provider = a.provider
 AND e.account_uid = a.account_uid AND e.cluster_name = a.cluster_name AND e.subject = a.subject
ORDER BY a.grant_time, e.time;

-- %%

-- READ FIRST — 2. Read the surrounding activity
--
-- What this does: Inspect the first alert’s actor and subject on the exact asset around the sequence.
--
-- What to look for: Inspect up to 100 events for the grant actor or subject on the same provider/account/cluster, ordered by time and event_id, from five minutes before the grant through five minutes after last_read. The cap can omit later events.
--
-- Your next step: Filter the chosen subquery by your alert’s key, asset and subject, or adjust the time window and row limit. If no alerts exist, the timeline is empty. Missing events do not prove an action did not happen.
--
-- Read this cell; run the SQL cell immediately below it.

-- %%

-- TODO: Select your chosen alert inside the subquery; adjust the window or row limit if needed.
-- Inspect the first alert’s actor and subject on the exact asset around the sequence.
-- Inspect up to 100 events for the grant actor or subject on the same provider/account/cluster, ordered by time and event_id, from five minutes before the grant through five minutes after last_read. The cap can omit later events.
WITH chosen AS (
    SELECT * FROM main.workshop_alerts
    ORDER BY grant_time LIMIT 1
)
-- Retrieve activity for the grant actor and subject on this exact asset.
-- Include five minutes around the sequence and cap output at 100 events.
SELECT e.* FROM enterprise.k8s_ocsf e JOIN chosen c
 ON e.provider = c.provider AND e.account_uid = c.account_uid AND e.cluster_name = c.cluster_name
AND e.time BETWEEN c.grant_time - INTERVAL '5' MINUTE AND c.last_read + INTERVAL '5' MINUTE
WHERE e.principal IN (c.grant_actor, c.subject)
ORDER BY e.time, e.event_id FETCH FIRST 100 ROWS ONLY;

-- %%

-- ## Explain why this alert fired — 3 minutes
--
-- Before running the scripted checker or AI investigator, use the **source-event timeline above** to decide whether this alert matches the rule you wrote. Your goal is to explain the observed behavior, not to declare an incident.
--
-- ### Check the two sides of the sequence
--
-- | Check | Evidence to find |
-- |---|---|
-- | Access was granted | A successful `create` of a `clusterrolebindings` resource, with `role_kind = 'ClusterRole'`, `role = 'cluster-admin'` and the recipient listed as a User in the request subjects |
-- | The recipient used that access | A successful `list` of `secrets` by that recipient, with `namespace IS NULL` for a cluster-wide request |
-- | The events belong together | The same provider, account and cluster; the secret list occurs at or after the grant, within 15 minutes |
--
-- The actor creating the binding may differ from the recipient. Follow the **recipient** when checking the secret-list event. Use `status_id = 1` to verify success. Copy the event IDs so someone else can check your finding.
--
-- ### Write your finding
--
-- Add a **Markdown cell** below this section (press Escape, then B to insert a cell, then M to make it Markdown). Fill in these five lines using your selected alert:
--
-- ```text
-- Grant event ID: ...
-- Secret-list event ID: ...
-- Why the rule matched: [actor] granted [recipient] cluster-admin on [provider/account/cluster] at [time]; [recipient] listed secrets at [time], [N] minutes later.
-- Possible legitimate explanation: ...
-- Before escalating, I would check: ...
-- ```
--
-- For the last two lines, consider whether this was expected administrative work and which ticket, owner confirmation or additional logs would help establish that. The exercise data does not supply validated approvals; an empty approvals table does not prove the work was unauthorized.
--
-- **You are done when:** your finding cites both events and explains the recipient, asset scope, success and time window. If you cannot find a required event, say which evidence is missing instead of filling the gap with an assumption. A successful secret-list request alone does not establish that secrets were exfiltrated.
--
-- Next, run the scripted checker and compare its claims with your own finding. Check any disagreement against the events; do not treat its disposition as the answer key.
