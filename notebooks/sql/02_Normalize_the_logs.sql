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

-- This notebook has Python mapping steps. Open 02_Normalize_the_logs.ipynb in Jupyter to complete them before the final SQL exercise.

-- %%

-- READ FIRST — 1. Write one normalized binding detection
--
-- What this does: Complete the same binding-attempt detection over your validated main.binding_events table, regardless of outcome.
--
-- What to look for: Matches must agree with the raw binding attempts, including failed or unknown-outcome requests, with the same source event IDs, assets, actors and roles. No JSON extraction belongs in this query.
--
-- Your next step: Fill the four target values from the shared contract, then run this cell. Explain which differences normalization removed.
--
-- Read this cell; run the SQL cell immediately below it.

-- %%

-- TODO: Fill the target values using your contract. Compare the simplicity with the three raw rules.
-- Complete the same binding-attempt detection over your validated main.binding_events table, regardless of outcome.
-- Matches must agree with the raw binding attempts, including failed or unknown-outcome requests, with the same source event IDs, assets, actors and roles. No JSON extraction belongs in this query.
SELECT event_id, provider, account_uid, cluster_name, principal AS grant_actor, role
FROM main.binding_events
-- TODO: use the shared contract; no JSON paths or provider-specific branches are needed.
WHERE operation = '__TODO_OPERATION__'
  AND resource_type = '__TODO_RESOURCE__'
  AND role_kind = '__TODO_ROLE_KIND__'
  AND role = '__TODO_ROLE_NAME__';

-- %%

-- READ FIRST — 2. Update the rule to successful attempts
--
-- What this does: A new requirement arrives: keep only successful cluster-admin binding-create attempts. Add one filter expression to the normalized rule.
--
-- What to look for: The log-day count may stay unchanged because its matching attempts are already successful. Practice matches drop from 9 to 4: failed requests and unknown HTTP outcomes are excluded; absent gRPC status maps to success in this modeled source.
--
-- Your next step: Fill the single TODO using the shared status_id contract, then run the cell. Which three cloud-specific clauses would otherwise have to change?
--
-- Read this cell; run the SQL cell immediately below it.

-- %%

-- TODO: Add a single status_id filter expression. Compare practice-match counts with the attempt rule above.
-- A new requirement arrives: keep only successful cluster-admin binding-create attempts. Add one filter expression to the normalized rule.
-- The log-day count may stay unchanged because its matching attempts are already successful. Practice matches drop from 9 to 4: failed requests and unknown HTTP outcomes are excluded; absent gRPC status maps to success in this modeled source.
SELECT event_id, provider, account_uid, cluster_name, principal AS grant_actor, role
FROM main.binding_events
WHERE operation = 'create' AND resource_type = 'clusterrolebindings'
  AND role_kind = 'ClusterRole' AND role = 'cluster-admin'
  -- TODO: add one normalized outcome filter expression, then compare practice-match counts.
  AND __TODO_SUCCESS_FILTER__;
