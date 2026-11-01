-- Deliberately incomplete agent tool: same principal may operate in several assets.
-- TODO: add provider, account and cluster constraints without dropping the time bound.
SELECT * FROM events
WHERE principal = {{principal}}
  AND time BETWEEN CAST({{start}} AS TIMESTAMP WITH TIME ZONE) AND CAST({{end}} AS TIMESTAMP WITH TIME ZONE)
ORDER BY time, event_id
