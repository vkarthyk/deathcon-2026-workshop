-- Ordinary SQL views and joins. Missing lookup rows remain visible and neutral.
CREATE OR REPLACE VIEW main.enriched_alerts AS
-- Summarize the source IPs of each alert's secret-list evidence without duplicating alerts.
-- Any malicious IP raises risk; lowering risk requires every read IP to be a known, nonmalicious corporate VPN.
WITH read_ip_context AS (
    SELECT e.alert_key, e.provider, e.account_uid, e.cluster_name, e.subject,
           MAX(CASE WHEN ip.is_malicious = TRUE THEN 1 ELSE 0 END) AS malicious_ip,
           MIN(CASE WHEN ip.network_type = 'corporate_vpn' AND ip.is_malicious = FALSE
                    THEN 1 ELSE 0 END) AS corporate_vpn
    FROM main.alert_evidence e
    LEFT JOIN enterprise.ip_enrichment ip ON ip.ip_address = e.src_ip
    WHERE e.evidence_kind = 'secret_list'
    GROUP BY e.alert_key, e.provider, e.account_uid, e.cluster_name, e.subject
),
-- Add user and cluster inventory using provider/account plus the principal or cluster key.
-- LEFT JOIN retains alerts with missing context; missing IP flags become neutral zeros.
context AS (
    SELECT a.alert_key, a.provider, a.account_uid, a.cluster_name,
           a.grant_time, a.grant_actor, a.subject, a.role,
           a.first_read, a.last_read, a.read_events, a.person_id,
           u.department, u.employment_status, u.is_privileged_admin,
           k.environment, k.data_sensitivity, k.owner_team,
           COALESCE(ip.malicious_ip, 0) AS malicious_ip,
           COALESCE(ip.corporate_vpn, 0) AS corporate_vpn
    FROM main.workshop_alerts a
    LEFT JOIN enterprise.user_enrichment u
      ON u.cloud_provider = a.provider AND u.account_uid = a.account_uid
     AND u.principal_name = a.subject
    LEFT JOIN enterprise.k8s_cluster_enrichment k
      ON k.cloud_provider = a.provider AND k.account_uid = a.account_uid
     AND k.cluster_name = a.cluster_name
    LEFT JOIN read_ip_context ip
      ON ip.alert_key = a.alert_key AND ip.provider = a.provider
     AND ip.account_uid = a.account_uid AND ip.cluster_name = a.cluster_name
     AND ip.subject = a.subject
),
-- Start at high severity (3), then add risk signals and subtract explicit lower-risk context.
-- Build a readable reason for each adjustment so an analyst can explain the priority.
adjustments AS (
    SELECT context.*, 'high' AS base_severity,
           3 + malicious_ip
             + CASE WHEN employment_status = 'inactive' THEN 1 ELSE 0 END
             + CASE WHEN environment = 'production' AND data_sensitivity = 'restricted' THEN 1 ELSE 0 END
             - corporate_vpn
             - CASE WHEN is_privileged_admin = TRUE AND employment_status = 'active' THEN 1 ELSE 0 END
             - CASE WHEN environment = 'development' THEN 1 ELSE 0 END AS raw_score,
           CASE WHEN malicious_ip = 1 THEN 'Malicious read IP (+1); ' ELSE '' END ||
           CASE WHEN employment_status = 'inactive' THEN 'Inactive user (+1); ' ELSE '' END ||
           CASE WHEN environment = 'production' AND data_sensitivity = 'restricted'
                THEN 'Restricted production cluster (+1); ' ELSE '' END ||
           CASE WHEN corporate_vpn = 1 THEN 'All read IPs corporate VPN and not malicious (-1); ' ELSE '' END ||
           CASE WHEN is_privileged_admin = TRUE AND employment_status = 'active'
                THEN 'Active privileged administrator (-1); ' ELSE '' END ||
           CASE WHEN environment = 'development' THEN 'Development cluster (-1); ' ELSE '' END AS severity_reasons
    FROM context
),
-- Clamp the adjusted score to the supported range: 1 (low) through 4 (critical).
-- Preserve the raw score and reasons so the effect of each inventory signal stays visible.
scored AS (
    SELECT adjustments.*,
           CASE WHEN raw_score < 1 THEN 1 WHEN raw_score > 4 THEN 4 ELSE raw_score END AS severity_score
    FROM adjustments
)
-- Translate the bounded numeric score into a severity label for the investigation queue.
-- Enrichment changes priority while retaining every detected alert and its evidence keys.
SELECT scored.*, CASE severity_score WHEN 1 THEN 'low' WHEN 2 THEN 'medium'
                                    WHEN 3 THEN 'high' ELSE 'critical' END AS severity
FROM scored;
