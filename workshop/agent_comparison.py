"""Self-service raw/normalized local-model comparison; reference evidence stays outside prompts."""
from agent.triage import run
from workshop.behavioral import literal
from workshop.exercises import save_records


def compare_evidence(session, alert_key, model, *, all_clouds=False, max_turns=12, normalized_first=False):
    """Run matched pairs and save partial progress, including transport failures."""
    session.refresh_rule()
    targets = session.execute('SELECT DISTINCT alert_key, provider, account_uid, cluster_name, subject '
                              'FROM main.workshop_alerts ORDER BY provider, alert_key, subject')
    if all_clouds:
        selected = {}
        for target in targets:
            selected.setdefault(target['provider'], target)
        targets = list(selected.values())
    else:
        targets = [target for target in targets if target['alert_key'] == alert_key][:1]
    if not targets:
        raise ValueError('No matching alert. Run your detection and select an alert first.')
    records = []
    for target in targets:
        filters = ' AND '.join(f'{key}={literal(target[key])}' for key in
                               ('alert_key', 'provider', 'account_uid', 'cluster_name', 'subject'))
        expected = session.execute('SELECT DISTINCT event_id FROM main.alert_evidence WHERE ' + filters)
        expected_ids = sorted(row['event_id'] for row in expected)
        order = ('ocsf', 'raw') if normalized_first else ('raw', 'ocsf')
        for representation in order:
            print(f"Running {target['provider']} / {representation} with {model} (up to {max_turns} turns)...", flush=True)
            try:
                record = run(session.engine, target['alert_key'], split='enterprise', model=model,
                             toolset='sql', representation=representation, max_turns=max_turns)
            except (RuntimeError, ValueError) as exc:
                record = {'alert_key': target['alert_key'], 'representation': representation,
                          'model': model, 'assessment': None, 'trace': [], 'error': str(exc)}
                print(f'Run failed: {exc}', flush=True)
            # Added AFTER the run; these reference IDs are never provided to the model.
            record['comparison_target'] = target
            record['comparison_expected_ids'] = expected_ids
            records.append(record)
            path = save_records('raw-vs-normalized.jsonl', records)
            print(f"Saved {len(records)} run(s) to {path}", flush=True)
    return records


def comparison_rows(records):
    """Report effort and reference-event coverage, without equating coverage with correctness."""
    rows = []
    for record in records:
        assessment = record.get('assessment') or {}
        expected = set(record['comparison_expected_ids'])
        retrieved = set(record.get('retrieved_event_ids', []))
        cited = {claim['event_id'] for claim in assessment.get('claims', [])}
        trace = record.get('trace', [])
        usage = record.get('usage') or {}
        rows.append({
            'provider': record['comparison_target']['provider'],
            'evidence': 'normalized' if record['representation'] == 'ocsf' else 'raw',
            'status': 'error' if record.get('error') else 'submitted' if assessment else 'incomplete',
            'SQL queries': sum(turn['tool'] == 'query_sql' for turn in trace),
            'tool errors': record.get('tool_errors'),
            'input tokens': usage.get('input_tokens'), 'output tokens': usage.get('output_tokens'),
            'investigation seconds': record.get('investigation_seconds'),
            'reference events retrieved': f'{len(expected & retrieved)}/{len(expected)}',
            'reference events cited': f'{len(expected & cited)}/{len(expected)}',
            'citations not retrieved': len(cited - retrieved),
            'disposition': assessment.get('disposition'),
        })
    return rows
