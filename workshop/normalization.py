"""Small, binding-only SQL mapping exercise; the full ingestion adapter stays separate."""
import re

from workshop.behavioral import literal
from workshop.binding_probes import prepare_binding_probes
from workshop.notebooks import split_statements, strip_leading_comments

BINDING_SCHEMA = {
    'event_id': 'VARCHAR', 'provider': 'VARCHAR', 'account_uid': 'VARCHAR',
    'cluster_name': 'VARCHAR', 'principal': 'VARCHAR', 'operation': 'VARCHAR',
    'resource_type': 'VARCHAR', 'status_id': 'INTEGER', 'role_kind': 'VARCHAR', 'role': 'VARCHAR',
}
SOURCES = {
    'eks': ('AWS', "json_extract_string(event, '$.objectRef.resource') = 'clusterrolebindings'"),
    'gke': ('GCP', "json_extract_string(entry, '$.protoPayload.methodName') LIKE '%clusterrolebindings.%'"),
    'aks': ('Azure', "json_extract_string(event, '$.objectRef.resource') = 'clusterrolebindings'"),
}
KEYS = ('provider', 'account_uid', 'cluster_name', 'event_id')
OUTPUTS = ('event_id', 'provider', 'account_uid', 'cluster_name', 'grant_actor', 'role')


def reference_matches(database, table, cloud, success_only=False):
    """Check against prepared relational evidence, without loading facilitator SQL files."""
    provider = '' if cloud.startswith('normalized') else ' AND provider=' + literal(SOURCES[cloud][0])
    return database.query(f"""SELECT event_id, provider, account_uid, cluster_name,
        principal AS grant_actor, role FROM {table}
        WHERE operation='create' AND resource_type='clusterrolebindings'
          AND role_kind='ClusterRole' AND role='cluster-admin'
          {'AND status_id=1' if success_only else ''}{provider}""")


def check_detection(database, cloud, sql):
    """Compare observed detections with the reference using event identity and asset scope."""
    if cloud not in (*SOURCES, 'normalized', 'normalized-success'):
        raise ValueError('Choose eks, gke, aks or normalized/normalized-success for --check-binding.')
    if '__TODO_' in sql:
        raise ValueError('Detection incomplete: replace each __TODO_...__ using the task and its hints, then rerun this cell.')
    if len(split_statements(sql)) != 1 or not re.match(r'^(SELECT|WITH)\b', strip_leading_comments(sql), re.I):
        raise ValueError('A detection check needs one SELECT query.')
    normalized = cloud.startswith('normalized')
    success_only = cloud == 'normalized-success'
    outcome_hint = 'Require status_id = 1 for successful attempts.' if success_only else 'Match attempts regardless of outcome.'
    if normalized and not database.query("SELECT table_name FROM information_schema.tables WHERE table_schema='main' AND table_name='binding_events'"):
        raise ValueError('Normalize and validate your mappings in notebook 02 before running the unified detection.')
    rows = database.query(sql)
    if rows and any(not set(OUTPUTS).issubset(row) for row in rows):
        raise ValueError('Keep the supplied output columns: ' + ', '.join(OUTPUTS))
    expected = reference_matches(database, 'enterprise.k8s_ocsf', cloud, success_only)
    key = lambda row: tuple(row[name] for name in OUTPUTS)
    actual_keys, expected_keys = {key(r) for r in rows}, {key(r) for r in expected}
    missing, extra = expected_keys - actual_keys, actual_keys - expected_keys
    if missing or extra or len(rows) != len(actual_keys):
        raise ValueError(f'Detection needs work: {len(missing)} missing, {len(extra)} unexpected, '
                         f'{len(rows) - len(actual_keys)} duplicate matches. Check operation, resource, '
                         'role kind and role name; retain the event and asset keys. '
                         + outcome_hint)
    prepare_binding_probes(database)
    if normalized:
        probe_sql = re.sub(r'\bmain\.binding_events\b', 'main.binding_events_practice', sql, flags=re.I)
        if not database.query("SELECT table_name FROM information_schema.tables WHERE table_schema='main' AND table_name='binding_events_practice'"):
            raise ValueError('Rerun notebook 02 normalization to prepare its practice checks.')
        probe_rows = database.query(probe_sql)
    else:
        probe_rows = database.query(re.sub(rf'\benterprise\.raw_{cloud}\b', f'main.binding_probe_{cloud}', sql, flags=re.I))
    probe_expected = reference_matches(database, 'main.binding_probe_expected', cloud, success_only)
    if {key(r) for r in probe_rows} != {key(r) for r in probe_expected} or len(probe_rows) != len({key(r) for r in probe_rows}):
        raise ValueError('Detection needs work on the visible practice records: check role kind/name, operation/resource and missing bodies. ' + outcome_hint + ' Inspect main.binding_probe_' + ('eks' if normalized else cloud) + ' for examples.')
    print(f"Practice matches: {len(probe_rows)} ({'success only' if success_only else 'all attempts'}).")
    print(f'PASS: {len(rows)} log-day matches plus practice edge cases; source IDs and asset scope agree.')
    return rows


def compile_mapping(mappings):
    """Compile participant SQL expressions, without supplying missing extraction logic."""
    if set(mappings) != set(SOURCES):
        raise ValueError('Supply mappings for eks, gke and aks.')
    selects, missing = [], []
    fields = set(BINDING_SCHEMA) - {'provider'}
    for cloud, (provider, scope) in SOURCES.items():
        mapping = mappings[cloud]
        if not isinstance(mapping, dict) or set(mapping) != fields:
            raise ValueError(f'{cloud}: keep exactly these mapping fields: {", ".join(sorted(fields))}. provider is supplied by the helper.')
        for field, expression in mapping.items():
            if not isinstance(expression, str) or not expression.strip() or '__TODO_' in expression:
                missing.append(f'{cloud}.{field}')
        if missing:
            continue
        projection = []
        for field, dtype in BINDING_SCHEMA.items():
            expression = repr(provider) if field == 'provider' else mapping[field]
            projection.append(f'CAST(({expression}) AS {dtype}) AS {field}')
        selects.append('SELECT ' + ',\n       '.join(projection) + f'\nFROM enterprise.raw_{cloud}\nWHERE {scope}')
    if missing:
        raise ValueError('Mapping incomplete: ' + ', '.join(missing) + '. Fill the SQL expressions using the field hints in notebook 02.')
    # DISTINCT collapses identical repeated audit deliveries; the contract checks source-key uniqueness.
    return 'SELECT DISTINCT * FROM (\n' + '\nUNION ALL\n'.join(selects) + '\n) mapped'


def normalize_bindings(session, mappings):
    """Publish participant data only after every contract check passes; no reference fallback."""
    db = session.engine
    db.script('DROP TABLE IF EXISTS main.binding_events; DROP TABLE IF EXISTS main.binding_events_candidate; DROP TABLE IF EXISTS main.binding_events_practice;')
    sql = compile_mapping(mappings)
    print('Generated SQL (your expressions, not a supplied solution):\n' + sql)
    try:
        db.script('CREATE TABLE main.binding_events_candidate AS ' + sql)
    except RuntimeError as exc:
        # Diagnose individual expressions only after the combined query fails.
        failures = []
        for cloud, (_, scope) in SOURCES.items():
            for field, expression in mappings[cloud].items():
                try:
                    db.query(f'SELECT COUNT(CAST(({expression}) AS {BINDING_SCHEMA[field]})) AS checked '
                             f'FROM enterprise.raw_{cloud} WHERE {scope}')
                except RuntimeError as field_exc:
                    failures.append(f'{cloud.upper()} → {field}: {expression}\n{field_exc}')
        detail = '\n\n'.join(failures) or str(exc)
        raise ValueError('Mapping SQL failed:\n' + detail +
                         '\nUse event for EKS/AKS and entry for GKE. Quote JSON paths, e.g. '
                         '\"json_extract_string(event, \'$.verb\')\". '
                         'Rerun the edited mapping cell, then normalize again.') from exc
    prepare_binding_probes(db)
    practice_sql = sql
    for cloud in SOURCES:
        practice_sql = practice_sql.replace(f'enterprise.raw_{cloud}', f'main.binding_probe_{cloud}')
    db.script('CREATE TABLE main.binding_events_practice AS ' + practice_sql)
    fields = ', '.join(BINDING_SCHEMA)
    expected = f"SELECT {fields} FROM enterprise.k8s_ocsf WHERE resource_type='clusterrolebindings'"
    reports = []
    join = ' AND '.join(f'a.{field}=e.{field}' for field in KEYS)
    for dataset, actual, reference in (('log day', 'main.binding_events_candidate', expected),
                                       ('practice', 'main.binding_events_practice', f"SELECT {fields} FROM main.binding_probe_expected WHERE resource_type='clusterrolebindings'")):
        for _, (provider, _) in SOURCES.items():
            # Compute counts in SQL rather than fetching the entire log day into Python.
            prefix = (f'WITH e AS ({reference}), a AS (SELECT * FROM {actual}), '
                      f'ep AS (SELECT * FROM e WHERE provider={provider!r}), '
                      f'ap AS (SELECT * FROM a WHERE provider={provider!r}) ')
            stats = db.query(prefix + f"""SELECT
                (SELECT COUNT(*) FROM ep) AS expected_events,
                (SELECT COUNT(*) FROM ap) AS mapped_events,
                (SELECT COUNT(*) FROM (SELECT {', '.join(KEYS)} FROM ep EXCEPT SELECT {', '.join(KEYS)} FROM ap)) AS missing_keys,
                (SELECT COUNT(*) FROM (SELECT {', '.join(KEYS)} FROM ap EXCEPT SELECT {', '.join(KEYS)} FROM ep)) AS unexpected_keys,
                (SELECT COUNT(*) FROM (SELECT {', '.join(KEYS)} FROM ap GROUP BY {', '.join(KEYS)} HAVING COUNT(*) > 1)) AS duplicate_keys""")[0]
            mismatches = db.query(prefix + 'SELECT ' + ', '.join(
                f'COUNT(*) FILTER (WHERE a.{field} IS DISTINCT FROM e.{field}) AS {field}'
                for field in BINDING_SCHEMA if field not in KEYS) + f' FROM ap a JOIN ep e ON {join}')[0]
            bad = ', '.join(f'{field}={count}' for field, count in mismatches.items() if count)
            passed = not any(stats[k] for k in ('missing_keys', 'unexpected_keys', 'duplicate_keys')) and not bad
            reports.append({'dataset': dataset, 'provider': provider, **stats, 'field_mismatches': bad or 'none', 'contract': 'PASS' if passed else 'FAIL'})
    import pandas as pd
    from IPython.display import display
    display(pd.DataFrame(reports))
    if any(r['contract'] == 'FAIL' for r in reports):
        db.script('DROP TABLE main.binding_events_practice;')
        failures = []
        for report in reports:
            if report['contract'] == 'FAIL':
                keys = ', '.join(f'{name}={report[name]}' for name in
                                 ('missing_keys', 'unexpected_keys', 'duplicate_keys') if report[name])
                failures.append(f"{report['provider']} ({report['dataset']}): " +
                                '; '.join(part for part in (keys, report['field_mismatches']
                                          if report['field_mismatches'] != 'none' else '') if part))
        raise ValueError('Normalization contract failed:\n' + '\n'.join(failures) +
                         '\nCounts above show how many records differ, not their actual values. '
                         'For status_id, convert native codes to 0=unknown, 1=success, 2=failure; '
                         'do not copy HTTP codes directly. For role, check the requestObject path '
                         '(GKE: protoPayload.request). For key differences, check event and asset fields. '
                         'Rerun each edited mapping cell, then normalize again. '
                         'No participant table was published.')
    db.script('ALTER TABLE main.binding_events_candidate RENAME TO binding_events;')
    print('PASS: main.binding_events contains your normalized binding events. Continue to the unified detection.')
    return reports
