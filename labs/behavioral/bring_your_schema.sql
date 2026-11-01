-- Adapter contract: replace this SELECT with a projection from ECS, ASIM, UDM or your own schema.
-- Preserve event-time TIMESTAMP WITH TIME ZONE, source-native identity and full account/cluster scope.
-- Missing fields remain NULL; do not manufacture successful status or request bodies.
-- Expose the resulting events as enterprise.k8s_ocsf. Also prepare enterprise.k8s_ocsf
-- by expanding each request subject while retaining event ID, role, kind, status and scope.
-- Cast your source fields to the common event contract used by downstream detection.
-- Keep native principal and asset keys intact so correlations retain their original scope.
CREATE OR REPLACE VIEW events AS
SELECT CAST(event_id AS VARCHAR) AS event_id, CAST(time AS TIMESTAMP WITH TIME ZONE) AS time,
       CAST(provider AS VARCHAR) AS provider, CAST(account_uid AS VARCHAR) AS account_uid,
       CAST(cluster_name AS VARCHAR) AS cluster_name, CAST(principal AS VARCHAR) AS principal,
       CAST(email AS VARCHAR) AS email, CAST(operation AS VARCHAR) AS operation, CAST(status_id AS INTEGER) AS status_id,
       CAST(resource_type AS VARCHAR) AS resource_type, CAST(namespace AS VARCHAR) AS namespace,
       CAST(resource_name AS VARCHAR) AS resource_name, CAST(src_ip AS VARCHAR) AS src_ip,
       request AS request, CAST(request_uri AS VARCHAR) AS request_uri
FROM your_canonical_event_source;
