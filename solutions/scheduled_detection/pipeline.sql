-- Reference: retain the small lab day and reconsider all canonical evidence.
-- This trades scan cost for correctness; it is not a bounded-state stream engine.
CREATE OR REPLACE VIEW canonical_events AS
SELECT * EXCLUDE (delivery_rank) FROM (
    SELECT *, ROW_NUMBER() OVER (
        PARTITION BY provider, account_uid, cluster_name, event_id
        ORDER BY ingested_at, delivery_id
    ) AS delivery_rank
    FROM deliveries
) WHERE delivery_rank = 1;

CREATE OR REPLACE VIEW recovery_queue AS
SELECT provider, account_uid, cluster_name, event_id, time, ingested_at
FROM canonical_events
WHERE ingested_at > time + INTERVAL '30' MINUTE;

CREATE OR REPLACE VIEW replay.k8s_ocsf AS
SELECT * FROM canonical_events
WHERE ingested_at <= time + INTERVAL '30' MINUTE
   OR (SELECT recover FROM clock);

CREATE OR REPLACE VIEW replay.k8s_subjects AS
SELECT e.provider, e.account_uid, e.cluster_name, e.event_id,
       json_extract_string(s.value, '$.name') AS subject,
       json_extract_string(s.value, '$.kind') AS subject_kind
FROM replay.k8s_ocsf e, json_each(e.subjects) s;

{{DETECTION_SQL}}

-- Persistent local outbox + progress commit together in the runner transaction.
INSERT INTO notifications
SELECT a.provider, a.account_uid, a.cluster_name, a.alert_key, a.subject,
       a.first_read, a.read_events, (SELECT now FROM clock)
FROM main.workshop_alerts a
WHERE NOT EXISTS (
    SELECT 1 FROM notifications n
    WHERE n.provider = a.provider AND n.account_uid = a.account_uid
      AND n.cluster_name = a.cluster_name AND n.alert_key = a.alert_key
      AND n.subject = a.subject
);

CREATE OR REPLACE VIEW coverage_state AS
SELECT * EXCLUDE (observation_rank) FROM (
    SELECT *, ROW_NUMBER() OVER (
        PARTITION BY provider, account_uid, cluster_name, stream
        ORDER BY observed_at DESC
    ) AS observation_rank FROM collector_health
) WHERE observation_rank = 1;

INSERT INTO coverage_warnings
SELECT h.provider, h.account_uid, h.cluster_name, h.stream, h.gap_since,
       (SELECT now FROM clock)
FROM coverage_state h
WHERE h.status = 'stalled' AND NOT EXISTS (
    SELECT 1 FROM coverage_warnings w
    WHERE w.provider = h.provider AND w.account_uid = h.account_uid
      AND w.cluster_name = h.cluster_name AND w.stream = h.stream
      AND w.gap_since = h.gap_since
);
