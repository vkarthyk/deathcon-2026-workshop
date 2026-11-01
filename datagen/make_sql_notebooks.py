"""Generate native DuckDB UI SQL notebook cells and portable SQL files."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from workshop.behavioral import participant_view_sql  # noqa: E402
from workshop.notebooks import split_statements, strip_leading_comments  # noqa: E402
from datagen.notebook_hints import SQL_REFERENCE, TASKS, optional_hint
from datagen.jupyter_exercises import EVIDENCE_REVIEW
from datagen.binding_exercise import RAW_HEADINGS, UNIFIED_SCAFFOLD, SUCCESS_UPDATE_SCAFFOLD, raw_scaffold, raw_hints, normalization_cells  # noqa: E402


def evaluation(split):
    return f"""-- Score the SAME editable macro on {split}; labels are evaluation-only.
-- Collect distinct grant keys emitted by the internal rule for this dataset.
-- Labels below measure the results; they are never inputs to the detection.
WITH actual AS (
    SELECT DISTINCT alert_key FROM main.participant_rule(
      '{split}.events', '{split}.identities', '{split}.approvals')
),
-- Compare emitted keys with labels, including outputs absent from the label set.
-- Count true/false positives and observable misses before calculating precision and recall.
counts AS (
    SELECT count(*) FILTER (WHERE a.alert_key IS NOT NULL AND l.malicious::BOOLEAN) AS tp,
           count(*) FILTER (WHERE a.alert_key IS NOT NULL AND (l.alert_key IS NULL OR NOT l.malicious::BOOLEAN)) AS fp,
           count(*) FILTER (WHERE a.alert_key IS NULL AND l.malicious::BOOLEAN AND l.observable::BOOLEAN) AS fn,
           count(*) FILTER (WHERE NOT l.observable::BOOLEAN) AS unobservable,
           count(*) FILTER (WHERE l.alert_key IS NULL) AS out_of_scope_alerts
    FROM {split}.evaluation_labels l FULL OUTER JOIN actual a USING(alert_key)
)
SELECT *, tp::DOUBLE/nullif(tp+fp,0) AS precision,
          tp::DOUBLE/nullif(tp+fn,0) AS recall_observable FROM counts;"""


def notebooks():
    result = {'00_Start_here': ['SELECT provider, count(*) AS events, min(time) AS first_seen, max(time) AS last_seen\n'
                       'FROM enterprise.k8s_ocsf GROUP BY provider ORDER BY provider;',
                       '-- The primary exercise: RBAC actor grants cluster-admin TO a subject;\n'
                       '-- the subject then lists secrets across the cluster. Correlate by asset AND time.\n'
                       'SELECT provider, operation, resource_type, count(*) AS events\n'
                       'FROM enterprise.k8s_ocsf GROUP BY provider, operation, resource_type ORDER BY 1, 2, 3;',
                       'SELECT provider, subject, grant_actor, grant_time, first_read, alert_key\n'
                       'FROM main.workshop_alerts ORDER BY grant_time;'],
     '01_Cloud_specific_detections': ['-- A source adapter preserves meaning, not just column names.\n'
                                          '-- These exports are modeled. docs/source-validation.md documents '
                                          'verification status and gaps.\n'
                                          'SELECT event FROM enterprise.raw_eks LIMIT 1;',
                                          'SELECT entry FROM enterprise.raw_gke LIMIT 1;',
                                          'SELECT resource_id, category, event FROM enterprise.raw_aks LIMIT 1;'],
     '02_Normalize_the_logs': [UNIFIED_SCAFFOLD, SUCCESS_UPDATE_SCAFFOLD],
     '03_Write_the_behavioral_rule': ["""-- Inspect granted subjects alongside their original normalized event.
-- Join the child relation by source event ID and full asset scope, retaining one row per subject.
SELECT e.provider, e.principal AS grant_actor, s.subject, s.subject_kind,
       e.role, e.role_kind, e.status_id, e.time AS grant_time, e.event_id
FROM enterprise.k8s_ocsf e
JOIN enterprise.k8s_subjects s
  ON s.provider = e.provider AND s.account_uid = e.account_uid
 AND s.cluster_name = e.cluster_name AND s.event_id = e.event_id
WHERE e.resource_type = 'clusterrolebindings' AND e.role = 'cluster-admin'
ORDER BY e.time;""",
                                      participant_view_sql() + ";",
                                      'SELECT * FROM main.workshop_alerts ORDER BY grant_time;',
                                      'SELECT (SELECT count(*) FROM enterprise.event_cache) -\n'
                                      '       (SELECT count(*) FROM enterprise.k8s_ocsf) AS '
                                      'duplicate_rows_removed;'],
     '04_Investigate_alerts': ['SELECT a.alert_key, a.provider, a.account_uid, a.cluster_name,\n'
                               '       a.subject, a.grant_time, e.event_id, e.evidence_kind\n'
                               'FROM main.workshop_alerts a\n'
                               'JOIN main.alert_evidence e\n'
                               '  ON e.alert_key = a.alert_key AND e.provider = a.provider\n'
                               ' AND e.account_uid = a.account_uid AND e.cluster_name = a.cluster_name AND '
                               'e.subject = a.subject\n'
                               'ORDER BY a.grant_time, e.time;',
                               'WITH chosen AS (\n'
                               '    SELECT * FROM main.workshop_alerts\n'
                               '    ORDER BY grant_time LIMIT 1\n'
                               ')\n'
                               'SELECT e.* FROM enterprise.k8s_ocsf e JOIN chosen c\n'
                               ' ON e.provider = c.provider AND e.account_uid = c.account_uid AND e.cluster_name '
                               '= c.cluster_name\n'
                               "AND e.time BETWEEN c.grant_time - INTERVAL '5' MINUTE AND c.last_read + INTERVAL "
                               "'5' MINUTE\n"
                               'WHERE e.principal IN (c.grant_actor, c.subject)\n'
                               'ORDER BY e.time, e.event_id FETCH FIRST 100 ROWS ONLY;',
                               ]}
    # Show the same simple detection in each raw source before the shared schema.
    result['01_Cloud_specific_detections'][3:3] = [
        raw_scaffold(name) for name in ('eks', 'gke', 'aks')]
    result['04_Investigate_alerts'][1] = result['04_Investigate_alerts'][1].replace(
        'WITH chosen AS (',
        '-- Select the earliest alert as a concrete investigation example.\n'
        '-- Its asset keys, actors and timestamps bound the source-event search below.\n'
        'WITH chosen AS (').replace(
        'SELECT e.* FROM enterprise.k8s_ocsf e JOIN chosen c',
        '-- Retrieve activity for the grant actor and subject on this exact asset.\n'
        '-- Include five minutes around the sequence and cap output at 100 events.\n'
        'SELECT e.* FROM enterprise.k8s_ocsf e JOIN chosen c')
    return result


EXPLANATIONS = {'00_Start_here': [('Explore the enterprise day',
                    'Count normalized activity and its time range by provider.',
                    'Compare event counts and first/last timestamps across providers to understand the dataset’s size and time coverage. Later queries explore the activity and suspicious sequences.',
                    'Start with provider and time filters instead of reading every event.'),
                   ('Inventory the available activity',
                    'Group activity by provider, operation and resource.',
                    'Compare counts by provider, operation and resource_type. This inventory does not identify behavioral sequences.',
                    'Locate create operations on clusterrolebindings and list operations on secrets; notebook 03 correlates them by subject, asset and time.'),
                   ('Inspect the behavioral alerts',
                    'List sequence matches from the current participant rule (the reference rule unless you have saved edits).',
                    'Compare grant actors, granted subjects, grant times and first-read times. alert_key identifies the grant; individual evidence events are not selected here.',
                    'Choose an alert_key, then query main.alert_evidence for its source event IDs or use notebook 05.')],
 '01_Cloud_specific_detections': [('Inspect a native EKS record',
                                       'Preview the unwrapped Kubernetes audit JSON from the modeled '
                                       'CloudWatch envelope.',
                                       'Expand the single event JSON and locate user, verb and objectRef. requestObject is available only when the audit record includes a body.',
                                       'Identify the actor and request time in this sample. To inspect RBAC subjects, select a clusterrolebindings event with a requestObject body; the first row is not filtered to grants. These exports are modeled, not live-verified.'),
                                      ('Inspect a native GKE record',
                                       'Preview a Cloud Logging entry rather than assuming it uses the '
                                       'native Kubernetes event shape.',
                                       'The operation, identity and request live under protoPayload; the '
                                       'surrounding entry carries cloud metadata.',
                                       'Compare these paths with EKS. See docs/source-validation.md for the '
                                       'real-export release gate.'),
                                      ('Inspect a native AKS record',
                                       'Preview the Azure resource envelope alongside the native audit '
                                       'event.',
                                       'resource_id and category surround the event JSON. The modeled '
                                       'resource ID requires canonicalization for inventory joins.',
                                       'Find account and cluster scope; do not infer a region that is '
                                       'absent.'),
                                      ('Detect a cluster-admin binding in EKS', 'Complete the four TODO predicate slots to detect cluster-admin ClusterRoleBinding create attempts in this source. Outcome is not filtered, so a match does not establish that the binding was created.', 'Unfinished tokens report Detection incomplete. Once filled, the check compares source event IDs, account/cluster scope, actors and roles, and rejects missing, unexpected or duplicate matches.', 'Use the collapsed field hints if needed; aim for three minutes per cloud. Keep the supplied output columns and complete all predicates before continuing to notebook 02.'),
                                      ('Write the same detection for GKE', 'Complete the four TODO predicate slots to detect cluster-admin ClusterRoleBinding create attempts in this source. Outcome is not filtered, so a match does not establish that the binding was created.', 'Unfinished tokens report Detection incomplete. Once filled, the check compares source event IDs, account/cluster scope, actors and roles, and rejects missing, unexpected or duplicate matches.', 'Use the collapsed field hints if needed; aim for three minutes per cloud. Keep the supplied output columns and complete all predicates before continuing to notebook 02.'),
                                      ('Write the same detection for AKS', 'Complete the four TODO predicate slots to detect cluster-admin ClusterRoleBinding create attempts in this source. Outcome is not filtered, so a match does not establish that the binding was created.', 'Unfinished tokens report Detection incomplete. Once filled, the check compares source event IDs, account/cluster scope, actors and roles, and rejects missing, unexpected or duplicate matches.', 'Use the collapsed field hints if needed; aim for three minutes per cloud. Keep the supplied output columns and complete all predicates before continuing to notebook 02.')],
 '02_Normalize_the_logs': [('Write one normalized binding detection', 'Complete the same binding-attempt detection over your validated main.binding_events table, regardless of outcome.', 'Matches must agree with the raw binding attempts, including failed or unknown-outcome requests, with the same source event IDs, assets, actors and roles. No JSON extraction belongs in this query.', 'Fill the four target values from the shared contract, then run this cell. Explain which differences normalization removed.'),
    ('Update the rule to successful attempts',
     'A new requirement arrives: keep only successful cluster-admin binding-create attempts. Add one predicate to the normalized rule.',
     'The log-day count may stay unchanged because its matching attempts are already successful. Practice matches drop from 9 to 4: failed requests and unknown HTTP outcomes are excluded; absent gRPC status maps to success in this modeled source.',
     'Fill the single TODO using the shared status_id contract, then run the cell. Which three cloud-specific clauses would otherwise have to change?')],
     '03_Write_the_behavioral_rule': [('Inspect grant subjects as rows',
                                   'Extend the simple binding detection from notebook 02 into a grant-to-secret-list sequence, using only normalized fields. Join the full Kubernetes event table to its request-subject child relation. Every '
                                   'supported subject in the request gets its own row without duplicating the event table.',
                                   'Compare grant_actor, subject, subject_kind, role_kind, status_id and event_id. This preview filters only resource_type and role name; it does not yet require a successful create, a User subject or a subsequent secret list.',
                                   'Compare grant_actor with subject. To inspect the request body, look up event_id in enterprise.k8s_ocsf using provider, account and cluster scope; then choose the detection predicates.'),
                                  ('Define your SQL detection',
                                   'We are trying to catch a user receiving cluster-admin privileges and then quickly using that access to list secrets across the cluster, without a matching approved change. This sequence can indicate privilege escalation followed by secret discovery. It is a reason to investigate, not proof of malicious intent.\n\nThe rule below looks for this sequence:\n\n1. Someone successfully creates a ClusterRoleBinding granting `cluster-admin` to a **User**.\n2. The **granted user** successfully lists secrets cluster-wide within **15 minutes** of the grant, on the same provider, account and cluster. The user receiving access may differ from the actor creating the binding.\n3. No approval matches the grant actor, granted user, role and asset at the grant time.\n\nFor example, Alice grants Bob cluster-admin at 10:00, and Bob lists secrets cluster-wide at 10:05. That produces an alert if no matching approval exists. Alice listing secrets, Bob listing them on another cluster, or Bob listing them after the window does not complete this sequence.\n\n**What this demonstrates:** Notebook 02 detected a single binding event. Here, one rule correlates multiple normalized events across all three clouds, using shared fields for identity, asset scope, success and time. We can change the behavior we detect without repeating provider-specific JSON logic. Normalization supplies consistent fields; the joins and filters supply the detection logic.\n\n**Your task:** Read the supplied rule, then run it to save `main.workshop_alerts`. Follow the `grants` CTE (who received access), the `sequences` CTE (what they did next), and `NOT EXISTS` (whether the change was approved). The final LEFT JOIN adds a supplied person identity for attribution; it does not decide whether the sequence matches. Inspect the alerts in the next section, then try a rule change while preserving the output columns.',
                                   'CREATE VIEW defines main.workshop_alerts. The Run your detection section selects its rows.',
                                   'Save this view definition. Keep alert_key and the asset/subject/time '
                                   'columns needed to retrieve supporting events.'),
                                  ('Run your detection',
                                   'Select alerts from your saved SQL view.',
                                   'One row per grant and subject, with first/last read times and the number '
                                   'of distinct reads.',
                                   'Use main.alert_evidence to retrieve individual source event IDs. '
                                   'Evidence is represented as rows rather than arrays.'),
                                  ('Inspect audit-stage deduplication',
                                   'Compare the cached source count with the deduplicated event view.',
                                   'Read duplicate_rows_removed: the cached row count minus the normalized event count. This aggregate does not show which event IDs or audit stages were removed.',
                                   'To inspect duplicates, group enterprise.event_cache by provider, account_uid, cluster_name and event_id and compare those keys with enterprise.k8s_ocsf.')],
 '04_Investigate_alerts': [('Select an alert from your rule',
                            'List alerts produced by the current participant rule.',
                            'Each row links an alert and its asset/subject keys to a supporting event_id and evidence_kind. Multiple evidence rows can belong to one alert; event bodies are not selected here.',
                            'Choose an alert and retain its alert_key, provider, account_uid, cluster_name and subject. Add filters on these keys inside the next query’s chosen CTE to investigate it instead of the default earliest alert.'),
                           ('Read the surrounding activity',
                            'Inspect the first alert’s actor and subject on the exact asset around the '
                            'sequence.',
                            'Inspect up to 100 events for the grant actor or subject on the same provider/account/cluster, ordered by time and event_id, from five minutes before the grant through five minutes after last_read. The cap can omit later events.',
                            'Filter the chosen CTE by your alert’s key, asset and subject, or adjust the time window and row limit. If no alerts exist, the timeline is empty. Missing events do not prove an action did not happen.'),
                           ]}


def explained_statements(name, cells):
    sql = [strip_leading_comments(statement) for cell in cells for statement in split_statements(cell)]
    notes = EXPLANATIONS[name]
    if len(notes) != len(sql):
        raise ValueError(f"{name}: {len(notes)} explanations for {len(sql)} statements")
    return [(note, '\n'.join('-- ' + line for line in
                            f'TODO: {TASKS[note[0]]}\n{note[1]}\n{note[2]}'.splitlines())
             + '\n' + statement)
            for note, statement in zip(notes, sql)]


def main():
    output = ROOT / "notebooks" / "sql"
    output.mkdir(parents=True, exist_ok=True)
    guides = ROOT / "notebooks" / "guides"
    guides.mkdir(parents=True, exist_ok=True)
    for name, cells in notebooks().items():
        native, guide = [], [f"# {name.replace('_', ' ')}\n",
            "Read each explanation, then run the following SQL. In DuckDB UI these explanations are comment-only cells; this file renders them as Markdown.\n"]
        guide.append(SQL_REFERENCE)
        native.append("\n".join("-- " + line if line else "--" for line in SQL_REFERENCE.splitlines()))
        if name == '02_Normalize_the_logs':
            for kind, source in normalization_cells():
                guide.append(source + "\n" if kind == 'markdown' else "```python\n" + source + "\n```\n")
            native.append('-- This notebook has Python mapping steps. Open 02_Normalize_the_logs.ipynb in Jupyter to complete them before the final SQL exercise.')
        for index, ((heading, purpose, expected, action), statement) in enumerate(explained_statements(name, cells), 1):
            hint = raw_hints(RAW_HEADINGS[heading]) if heading in RAW_HEADINGS else optional_hint(heading)
            explanation = (f"READ FIRST — {index}. {heading}\n\n"
                           f"What this does: {purpose}\n\n"
                           f"What to look for: {expected}\n\n"
                           f"Your next step: {action}\n\n"
                           "Read this cell; run the SQL cell immediately below it.")
            native += ["\n".join("-- " + line if line else "--" for line in explanation.splitlines()), statement]
            guide += [f"## {index}. {heading}\n", purpose + "\n", f"**What to look for:** {expected}\n",
                      f"**Your next step:** {action}{hint}\n", "```sql\n" + statement + "\n```\n"]
        if name == '04_Investigate_alerts':
            guide.append(EVIDENCE_REVIEW)
            native.append('\n'.join('-- ' + line if line else '--' for line in EVIDENCE_REVIEW.splitlines()))
        (output / f"{name}.sql").write_text("\n\n-- %%\n\n".join(native) + "\n")
        (guides / f"{name}.md").write_text("\n".join(guide))
        print(name)


if __name__ == "__main__":
    main()
