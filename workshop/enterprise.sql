-- Participant dataset: the larger modeled enterprise day, without test-case labels.
-- Prepare a separate schema for the participant-facing enterprise tables and views.
-- The raw aliases below expose the modeled cloud envelopes without changing their contents.
CREATE SCHEMA IF NOT EXISTS enterprise;
SET schema='enterprise';
CREATE OR REPLACE VIEW raw_eks AS SELECT * FROM main.raw_eks;
CREATE OR REPLACE VIEW raw_gke AS SELECT * FROM main.raw_gke;
CREATE OR REPLACE VIEW raw_aks AS SELECT * FROM main.raw_aks;
-- Connect native principals to supplied person IDs within each provider and account.
-- Missing person details remain NULL; this projection does not infer identity from log text.
CREATE OR REPLACE VIEW identities AS
SELECT l.person_id, l.cloud_provider, c.account_uid, l.principal_name, p.email
FROM main.identity_links l JOIN main.clusters c ON c.cloud_provider=l.cloud_provider
LEFT JOIN main.identities p USING(person_id);
-- Project synthetic HR and access inventory onto each mapped cloud principal.
-- Employment status and privileged-admin context can adjust an alert's severity.
CREATE OR REPLACE VIEW user_enrichment AS
SELECT l.cloud_provider, c.account_uid, l.principal_name, p.department,
       p.employment_status, p.title LIKE '%SRE%' AS is_privileged_admin,
       p.display_name, p.title, p.manager_email, p.usual_client_os, p.home_country,
       p.out_of_office, 'synthetic IdP / HR / access inventory' AS source
FROM main.identity_links l JOIN main.clusters c ON c.cloud_provider=l.cloud_provider
JOIN main.identities p USING(person_id);
-- Translate cluster inventory into the environment and sensitivity values used by scoring.
-- Provider, account and cluster together identify the asset whose context is being attached.
CREATE OR REPLACE VIEW k8s_cluster_enrichment AS
SELECT cloud_provider, account_uid, cluster_name,
       CASE WHEN environment='prod' THEN 'production' ELSE environment END AS environment,
       CASE WHEN data_classification='PCI' THEN 'restricted' ELSE 'internal' END AS data_sensitivity,
       owner_team, region, node_cidr, 'synthetic CMDB / Kubernetes inventory' AS source
FROM main.clusters;
-- Translate synthetic network inventory into IP lookup fields and explicit risk signals.
-- Preserve unknown geography as NULL; reserved example addresses do not imply maliciousness.
CREATE OR REPLACE VIEW ip_enrichment AS
SELECT ip AS ip_address, 'IPv4' AS ip_version, 'AS' || CAST(asn AS VARCHAR) AS asn,
       as_org AS asn_org,
       true AS bogon_or_private, -- All addresses in this corpus are reserved synthetic ranges.
       country AS country_code, CAST(NULL AS VARCHAR) AS city, CAST(NULL AS VARCHAR) AS region,
       CASE reputation WHEN 'malicious' THEN 90 WHEN 'suspicious' THEN 65
            WHEN 'benign' THEN 10 ELSE NULL END AS reputation_score,
       nullif(tags, '') AS threat_category, reputation='malicious' AS is_malicious,
       POSITION('vpn' IN COALESCE(tags,'')) > 0 AS is_vpn,
       POSITION('proxy' IN COALESCE(tags,'')) > 0 AS is_proxy,
       category='tor_exit' AS is_tor,
       category IN ('cloud_hosting','vps_hosting') AS is_hosting,
       category='cloud_hosting' AS is_cloud,
       CASE WHEN category='corp_egress' THEN 'corporate_vpn' ELSE 'external' END AS network_type,
       reputation, 'synthetic ' || source AS source, last_seen, category, tags
FROM main.ip_reputation;
-- No validated change records were supplied for this day; do not invent authorization.
-- Define the approval columns even though this day has no supplied change tickets.
-- WHERE false returns zero rows, so no detection is suppressed by invented approvals.
CREATE OR REPLACE VIEW approvals AS SELECT CAST(NULL AS VARCHAR) AS cloud_provider,
  CAST(NULL AS VARCHAR) AS account_uid, CAST(NULL AS VARCHAR) AS cluster_name, CAST(NULL AS VARCHAR) AS grant_actor,
  CAST(NULL AS VARCHAR) AS subject, CAST(NULL AS VARCHAR) AS role,
  CAST(NULL AS TIMESTAMP WITH TIME ZONE) AS start_time, CAST(NULL AS TIMESTAMP WITH TIME ZONE) AS end_time,
  CAST(NULL AS VARCHAR) AS ticket WHERE false;
