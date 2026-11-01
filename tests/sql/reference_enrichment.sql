-- Reusable enrichment stage for reference OR participant alerts. Lookup keys must be unique.
-- Synthetic current-state inventories: production pipelines must manage freshness/history.
-- Missing context is neutral; enrichment changes priority, never detection membership.
CREATE OR REPLACE MACRO main.enrich_alerts(alert_table, ip_table, user_table, cluster_table) AS TABLE
-- Attach user, cluster and observed read-IP context to each incoming alert.
-- LEFT JOIN retains missing lookups; all read IPs must be known to lower risk for VPN use.
WITH context AS (
    SELECT c.*, u.department, u.employment_status, u.is_privileged_admin::BOOLEAN AS is_privileged_admin,
           k.environment, k.data_sensitivity, k.owner_team,
           coalesce(ip.malicious_ip, false) AS malicious_ip,
           coalesce(ip.corporate_vpn, false) AS corporate_vpn
    FROM query_table(alert_table) c
    LEFT JOIN query_table(user_table) u ON u.cloud_provider=c.provider AND u.account_uid=c.account_uid
      AND u.principal_name=c.subject
    LEFT JOIN query_table(cluster_table) k ON k.cloud_provider=c.provider AND k.account_uid=c.account_uid
      AND k.cluster_name=c.cluster_name
    LEFT JOIN LATERAL (
      SELECT bool_or(is_malicious::BOOLEAN) AS malicious_ip,
             bool_and(network_type='corporate_vpn' AND NOT is_malicious::BOOLEAN)
               AND count(DISTINCT ip_address)=len(c.source_ips) AS corporate_vpn
      FROM query_table(ip_table) WHERE list_contains(c.source_ips, ip_address)
    ) ip ON true
),
-- Adjust the high base severity using explicit risk and lower-risk inventory signals.
-- Clamp scores to 1 through 4 and retain a reason for every adjustment.
scored AS (
    SELECT *, 'high' AS base_severity,
      greatest(1, least(4, 3
        + CASE WHEN malicious_ip THEN 1 ELSE 0 END
        + CASE WHEN employment_status='inactive' THEN 1 ELSE 0 END
        + CASE WHEN environment='production' AND data_sensitivity='restricted' THEN 1 ELSE 0 END
        - CASE WHEN corporate_vpn THEN 1 ELSE 0 END
        - CASE WHEN is_privileged_admin AND employment_status='active' THEN 1 ELSE 0 END
        - CASE WHEN environment='development' THEN 1 ELSE 0 END)) AS severity_score,
      list_filter([
        CASE WHEN malicious_ip THEN 'Threat-intelligence-listed source IP (+1)' END,
        CASE WHEN employment_status='inactive' THEN 'Inactive user account (+1)' END,
        CASE WHEN environment='production' AND data_sensitivity='restricted' THEN 'Restricted production cluster (+1)' END,
        CASE WHEN corporate_vpn THEN 'All observed read IPs are corporate VPN, none listed malicious (-1)' END,
        CASE WHEN is_privileged_admin AND employment_status='active' THEN 'Active privileged administrator (-1)' END,
        CASE WHEN environment='development' THEN 'Development cluster (-1)' END
      ], lambda reason: reason IS NOT NULL) AS severity_reasons
    FROM context
)
-- Map the numeric score to the severity label used in investigation output.
-- Keep the original alert columns and context so each decision can be reviewed.
SELECT *, CASE severity_score WHEN 1 THEN 'low' WHEN 2 THEN 'medium'
          WHEN 3 THEN 'high' ELSE 'critical' END AS severity
FROM scored;
