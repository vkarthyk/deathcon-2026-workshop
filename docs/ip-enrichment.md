# IP enrichment

`enterprise.ip_enrichment` models network inventory and
threat-intelligence exports. Each address has one row. Join event `src_ip` (or an
alert's `source_ips`) to `ip_address`. The agent's `get_ip_enrichment` tool accepts
an `ip` argument and returns this full record.

All examples are synthetic. ASN ownership, geolocation, threat labels and risk
scores are invented, including for reserved documentation addresses. No live
reputation or geolocation lookup is performed. The enterprise day uses reserved IPv4 documentation and benchmarking ranges, so
`bogon_or_private` is true. ASN/organization/country come from the bundled synthetic
inventory; city and region are unavailable. Internal-only addresses without a
lookup stay unmapped. The schema accepts IPv6 enrichment, but this day's source
inventory is IPv4. Automated tests separately cover other address families.

| Category | Field | Type | Meaning |
|---|---|---|---|
| Identification | `ip_address` | VARCHAR | Canonical IPv4 or IPv6 address; exact lookup key. |
| Identification | `ip_version` | VARCHAR | `IPv4` or `IPv6`. |
| Network | `asn` | VARCHAR, nullable | ASN such as `AS64511`; synthetic inventory values are not live ASN ownership claims. |
| Network | `asn_org` | VARCHAR | Fictional ASN owner or internal network organization. |
| Network | `bogon_or_private` | BOOLEAN | Non-global address, including private, reserved documentation, or loopback space. This flag alone does not imply a threat. |
| Geolocation | `country_code` | VARCHAR, nullable | Two-letter ISO country code, such as `US`. |
| Geolocation | `city` | VARCHAR, nullable | Example city; not proof of an actor's physical location. |
| Geolocation | `region` | VARCHAR, nullable | Example state or region. Location can be unavailable. |
| Reputation | `reputation_score` | INTEGER | Nullable risk score from 0–100; higher means higher risk. Unknown reputation has no numeric score. Not a trust score or probability. |
| Reputation | `threat_category` | VARCHAR | Example category: synthetic threat-feed tags, or null when unspecified. |
| Reputation | `is_malicious` | BOOLEAN | Explicit threat-intelligence classification used by the severity policy. |
| Infrastructure | `is_vpn` | BOOLEAN | VPN usage, whether enterprise or an anonymization service. |
| Infrastructure | `is_proxy` | BOOLEAN | Proxy service indicator. |
| Infrastructure | `is_tor` | BOOLEAN | Tor exit-node indicator; not automatically malicious. |
| Infrastructure | `is_hosting` | BOOLEAN | Hosting/datacenter infrastructure indicator. |
| Infrastructure | `is_cloud` | BOOLEAN | Cloud-provider infrastructure indicator; a subset of hosting in this inventory. |
| Enterprise context | `network_type` | VARCHAR | `corporate_vpn` or `external`; only the explicit corporate classification qualifies for a severity reduction. |
| Compatibility | `reputation` | VARCHAR | Existing categorical reputation: `malicious`, `suspicious`, `benign`, or `unknown`; is_malicious is true only for malicious records. Unknown does not mean safe. |
| Provenance | `source` | VARCHAR | Identifies the record as synthetic inventory/threat intelligence. |

A missing lookup retains the alert. Missing attributes are unknown, not evidence
of safety. The illustrative severity policy adds one point if any read IP has
`is_malicious=true`. It subtracts one only when **every** observed read IP is mapped
to `network_type='corporate_vpn'` and explicitly not malicious. Generic VPN,
proxy, Tor, hosting, cloud, geography and ASN fields do not independently change
severity; the numeric score is available for investigation and policy experiments.
This avoids counting the same IP threat twice through its flag and score.

Explore the richer records in notebook 05:

```sql
-- Inspect the network, geography and threat context supplied for each known IP.
-- Sort by descending risk score to review high-risk records before lower-risk ones.
SELECT ip_address, ip_version, asn, asn_org, country_code, city, region,
       reputation_score, threat_category, is_malicious,
       is_vpn, is_proxy, is_tor, is_hosting, is_cloud
FROM enterprise.ip_enrichment
ORDER BY reputation_score DESC, ip_address;
```
