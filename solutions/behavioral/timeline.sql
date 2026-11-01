-- Retrieve one principal's activity within the selected provider, account and cluster.
-- Bound the search by event time, then sort deterministically for evidence review.
SELECT * FROM events
WHERE provider = {{provider}} AND account_uid = {{account_uid}}
  AND cluster_name = {{cluster_name}} AND principal = {{principal}}
  AND time BETWEEN CAST({{start}} AS TIMESTAMP WITH TIME ZONE) AND CAST({{end}} AS TIMESTAMP WITH TIME ZONE)
ORDER BY time, event_id
