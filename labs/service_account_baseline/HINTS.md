# Progressive hints

<details><summary>1. Where are the GCP and Azure fields?</summary>

GCP: `r->>'$.resource.labels.project_id'`,
`r->>'$.protoPayload.authenticationInfo.principalEmail'`,
`r->>'$.protoPayload.requestMetadata.callerIp'` and `.callerSuppliedUserAgent`,
`r->>'$.protoPayload.status.code'`.

Azure: `split_part(r->>'$.resourceId', '/', 3)`, `r->>'$.identity.claims.idtyp'`,
`r->>'$.identity.claims.appid'`, `r->>'$.caller'`, `r->>'$.callerIpAddress'`,
`r->>'$.resultType'`. Reuse the AWS IPv4 `regexp_matches` test.
</details>

<details><summary>2. Why are some secret reads missing from the deviations?</summary>

Look at the same GCP email or Azure application ID in both accounts. If the
baseline is keyed by principal alone, normal behavior in one account hides new
behavior in another. Add `cloud_provider` and `account_uid` to the baseline and
to the comparison.
</details>

<details><summary>3. Why are there deviations with a NULL observed value?</summary>

`NULL = NULL` is not true in SQL, so a NULL can never match the baseline. Filter
NULL sources and clients out of `sa.observations`, and use
`coalesce(action_type, cloud_api_action)` for actions.
</details>

<details><summary>4. How do I turn values into networks and client families?</summary>

`regexp_replace(source_ip, '\.\d+$', '.0/24')` and
`lower(trim(split_part(user_agent, '/', 1)))`.
</details>

<details><summary>5. How do I require enough history?</summary>

`sa.baseline_coverage` already counts distinct active days. Join it in
`sa.deviations` and keep principals with `baseline_days >= min_baseline_days`
from `lab.detection_window`. For `sa.insufficient_baseline`, start from the
detection-day observations, LEFT JOIN coverage, and keep principals below the
threshold, using `coalesce(baseline_days, 0)`. Count distinct `event_id`s.
</details>
