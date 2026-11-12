-- Deliberately flawed scheduled pipeline. Repair this file, not the behavior rule.
-- clock.now is simulated processing time; deliveries.time is source event time.
-- Keep the DETECTION_SQL marker: the runner inserts the existing shared rule.

-- TODO: this loses delayed grants and older evidence needed by a new delivery.
-- TODO: delivery retries are not distinct source events. Preserve full asset scope.
CREATE OR REPLACE VIEW replay.k8s_ocsf AS
SELECT * FROM deliveries
WHERE time BETWEEN (SELECT now FROM clock) - INTERVAL '15' MINUTE
               AND (SELECT now FROM clock);

-- Supplied adapter: expand all repeated subjects from each retained source event.
CREATE OR REPLACE VIEW replay.k8s_subjects AS
SELECT e.provider, e.account_uid, e.cluster_name, e.event_id,
       json_extract_string(s.value, '$.name') AS subject,
       json_extract_string(s.value, '$.kind') AS subject_kind
FROM replay.k8s_ocsf e, json_each(e.subjects) s;

{{DETECTION_SQL}}

-- TODO: overlapping runs and process restarts must not renotify the same alert.
-- An alert is identified by the complete asset, grant ID and granted subject.
INSERT INTO notifications
SELECT provider, account_uid, cluster_name, alert_key, subject, first_read,
       read_events, (SELECT now FROM clock)
FROM main.workshop_alerts;

-- TODO: publish main.recovery_queue for evidence beyond the supported 30-minute
-- lateness bound, and reconsider it when clock.recover is true.
-- TODO: publish main.coverage_state from the latest explicit collector_health
-- observation per asset/stream. Notify once per stalled interval in
-- coverage_warnings. Missing health is unknown; no read events does not prove
-- a logging outage or a safe cluster.
