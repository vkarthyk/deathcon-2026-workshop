"""Generate synthetic delivery schedules and private semantic expectations.

Only practice.json is distributed to students. Expectations are constructed from
scenario intent, never by running the reference detection or pipeline.
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
import uuid

ROOT = Path(__file__).resolve().parents[1]
DAY = datetime(2026, 11, 12, 10, tzinfo=timezone.utc)


def build(seed='practice'):
    rng = random.Random(seed)
    batches = {minute: {'now': (DAY + timedelta(minutes=minute)).isoformat(),
                        'deliveries': [], 'health': []} for minute in range(0, 126, 5)}
    expected = {'alerts': {}, 'recovery_alerts': {}, 'recovery_events': set(), 'warnings': set()}
    approvals = []

    def stamp(minute):
        return (DAY + timedelta(minutes=minute)).isoformat()

    def uid():
        return str(uuid.UUID(int=rng.getrandbits(128)))

    def tick(minute):
        return ((minute + 4) // 5) * 5

    def deliver(event, minute):
        row = event | {'delivery_id': uid(), 'ingested_at': stamp(minute)}
        batches[tick(minute)]['deliveries'].append(row)
        return row

    cases = ['normal', 'grant_delayed', 'read_delayed', 'boundary', 'too_late',
             'outside_window', 'failed_grant', 'failed_read', 'namespaced',
             'actor_reads', 'wrong_asset', 'wrong_role', 'wrong_kind', 'service_account',
             'approved', 'near_approval', 'multiple_subjects', 'missing_reads', 'unknown_outcome']
    rng.shuffle(cases)
    # Reused IDs are legitimate on distinct full asset keys.
    shared_grant, shared_read = uid(), uid()
    for cloud_index, provider in enumerate(('AWS', 'GCP', 'Azure')):
        for index, case in enumerate(cases):
            minute = index * 2 + rng.randrange(2)
            subject = f'engineer-{cloud_index}-{index}@example.test'
            grant = dict(event_id=shared_grant if case == 'normal' else uid(), provider=provider,
                         account_uid=f'account-{cloud_index}', cluster_name='platform-prod',
                         time=stamp(minute), principal=f'admin-{cloud_index}@example.test',
                         operation='create', resource_type='clusterrolebindings', status_id=1,
                         namespace=None, role_kind='ClusterRole', role='cluster-admin',
                         subjects=[{'kind': 'User', 'name': f'observer-{index}@example.test'},
                                   {'kind': 'User', 'name': subject}])
            offset = 15 if case == 'boundary' else 16 if case == 'outside_window' else 7
            read = grant | dict(event_id=shared_read if case == 'normal' else uid(), time=stamp(minute + offset),
                                principal=subject, operation='list', resource_type='secrets',
                                role_kind=None, role=None, subjects=[])
            if case == 'failed_grant':
                grant['status_id'] = 2
            if case == 'failed_read':
                read['status_id'] = 2
            if case == 'unknown_outcome':
                read['status_id'] = 0
            if case == 'namespaced':
                read['namespace'] = 'payments'
            if case == 'actor_reads':
                read['principal'] = grant['principal']
            if case == 'wrong_asset':
                read['cluster_name'] = 'platform-dev'
            if case == 'wrong_role':
                grant['role'] = 'view'
            if case == 'wrong_kind':
                grant['role_kind'] = 'Role'
            if case == 'service_account':
                grant['subjects'][1]['kind'] = 'ServiceAccount'
            if case == 'missing_reads':
                grant['cluster_name'] = 'restricted-prod'
            grant_arrival = minute + (22 if case == 'grant_delayed' else 40 if case == 'too_late' else 1)
            read_arrival = minute + offset + (23 if case == 'read_delayed' else 1)
            delivered_grant = deliver(grant, grant_arrival)
            # Identical delivery replay, then a new delivery of the same source event.
            batches[tick(grant_arrival) + 5]['deliveries'].append(delivered_grant)
            deliver(grant, grant_arrival + 10)
            if case != 'missing_reads':
                deliver(read, read_arrival)
                deliver(read, read_arrival + 5)
            approval = dict(cloud_provider=provider, account_uid=grant['account_uid'],
                            cluster_name=grant['cluster_name'], grant_actor=grant['principal'],
                            subject=subject, role='cluster-admin', start_time=stamp(minute),
                            end_time=stamp(minute + 15), ticket=uid())
            if case in ('approved', 'near_approval'):
                approvals.append(approval if case == 'approved' else approval | {'account_uid': 'other-account'})
            matched = case in ('normal', 'grant_delayed', 'read_delayed', 'boundary',
                               'near_approval', 'multiple_subjects', 'too_late')

            def expect(g, recipient, read_time, ready, late=False):
                key = tuple(g[k] for k in ('provider', 'account_uid', 'cluster_name', 'event_id')) + (recipient,)
                expected['recovery_alerts' if late else 'alerts'][key] = {
                    'first_read': read_time, 'ready_at': stamp(tick(ready)), 'read_events': 1}

            if matched:
                expect(grant, subject, read['time'], max(grant_arrival, read_arrival), case == 'too_late')
            if case == 'too_late':
                expected['recovery_events'].add(tuple(grant[k] for k in
                                                      ('provider', 'account_uid', 'cluster_name', 'event_id')))
            if case == 'multiple_subjects':
                # One grant has two independently alerting recipients.
                other = grant['subjects'][0]['name']
                second_read = read | {'event_id': uid(), 'principal': other}
                deliver(second_read, read_arrival + 2)
                expect(grant, other, second_read['time'], max(grant_arrival, read_arrival + 2))
            if case == 'normal':
                # Same IDs AND provider, but different account or cluster: all are valid.
                for field, value in (('account_uid', 'second-account'), ('cluster_name', 'second-cluster')):
                    g, r = grant | {field: value}, read | {field: value}
                    deliver(g, grant_arrival)
                    deliver(r, read_arrival)
                    expect(g, subject, r['time'], max(grant_arrival, read_arrival))

        for cluster in ('platform-prod', 'restricted-prod'):
            health = dict(provider=provider, account_uid=f'account-{cloud_index}', cluster_name=cluster,
                          stream='secret_reads', observed_at=stamp(0), status='healthy', gap_since=None)
            batches[0]['health'].append(health)
            if cluster == 'restricted-prod':
                for m in (5, 10, 15):
                    batches[m]['health'].append(health | dict(observed_at=stamp(m), status='stalled', gap_since=stamp(3)))
                batches[100]['health'].append(health | dict(observed_at=stamp(100)))
                expected['warnings'].add((provider, health['account_uid'], cluster, 'secret_reads', stamp(3)))
        for _ in range(35):
            minute = rng.randrange(70)
            noise = dict(event_id=uid(), provider=provider, account_uid=f'account-{cloud_index}',
                         cluster_name='platform-prod', time=stamp(minute), principal='controller',
                         operation='list', resource_type='pods', status_id=1, namespace='apps',
                         role_kind=None, role=None, subjects=[])
            deliver(noise, minute + 1)
    for batch in batches.values():
        rng.shuffle(batch['deliveries'])
    return {'description': 'Synthetic delivery replay. All timestamps UTC; batch order is processing order.',
            'lateness_minutes': 30, 'approvals': approvals, 'batches': list(batches.values())}, expected


def main(root=None):
    root = Path(root or ROOT)
    schedule, _ = build()
    path = root / 'labs/scheduled_detection/practice.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(schedule, indent=2) + '\n')
    print(path)
    cells = []

    def add(kind, source):
        cell = dict(cell_type=kind, id=f'scheduled_detection-{len(cells)}', metadata={},
                    source=source.splitlines(keepends=True))
        if kind == 'code':
            cell.update(execution_count=None, outputs=[])
        cells.append(cell)

    add('markdown', '# 05 Run the detection in batches\n\n'
        'Extra lab · 60–90 minutes. Read [the lab guide](guides/05_Run_the_detection_in_batches.md) for the brief, table contracts '
        'and acceptance criteria. Work after notebooks 03–04. All evidence is synthetic and local. '
        'Edit `labs/scheduled_detection/pipeline.sql`; keep the behavioral rule unchanged.')
    add('code', '''from pathlib import Path
import sys
import tempfile

root = next((p for p in (Path.cwd(), *Path.cwd().parents)
             if (p / 'labs/scheduled_detection/practice.json').exists()), None)
if root is None:
    raise FileNotFoundError('Open this notebook inside the extracted workshop repository.')
sys.path.insert(0, str(root))
from workshop.scheduled_detection import Replay, SimulatedCrash, rows

# A fresh temporary database per attempt; durable across connection restarts.
attempt = tempfile.TemporaryDirectory(prefix='scheduled_detection-notebook-')
database = Path(attempt.name) / 'state.duckdb'
schedule = root / 'labs/scheduled_detection/practice.json'
pipeline = root / 'labs/scheduled_detection/pipeline.sql'
replay = Replay(database, schedule, pipeline)
''')
    add('markdown', '## Observe delivery order\n\nRun the next cell repeatedly to advance one batch. '
        'Compare event time and ingestion time. Only received evidence is visible to SQL.')
    add('code', '''replay.step()
rows(replay.db, """SELECT provider, account_uid, cluster_name, event_id,
    time, ingested_at, operation, resource_type
    FROM deliveries ORDER BY ingested_at DESC LIMIT 12""")''')
    add('markdown', '## Reproduce the incident\n\nFinish the replay and inspect the notification outbox. '
        'Find a missed sequence and a repeated notification. Explain the difference between '
        'event, ingestion and processing time before changing SQL.')
    add('code', 'report = replay.run()\nreport')
    add('markdown', 'Inspect repeated notifications by the full asset, grant and recipient key.')
    add('code', '''rows(replay.db, """SELECT provider, account_uid, cluster_name, alert_key,
    subject, count(*) AS notifications FROM notifications
    GROUP BY provider, account_uid, cluster_name, alert_key, subject
    HAVING count(*) > 1 ORDER BY notifications DESC""")''')
    add('markdown', '## Repair and rerun\n\nEdit `pipeline.sql` in JupyterLab. Follow steps 2–4 in '
        'the lab guide. Rerun the cell below for a fresh attempt after each edit. '
        'A new connection to the same database resumes existing progress; it does not erase prior output.')
    add('code', '''replay.close()
attempt.cleanup()
attempt = tempfile.TemporaryDirectory(prefix='scheduled_detection-notebook-')
database = Path(attempt.name) / 'state.duckdb'
replay = Replay(database, schedule, pipeline)
report = replay.run()
report''')
    add('markdown', '## Restart and recovery\n\nUse the CLI crash commands in the lab guide with fresh '
        'database paths to test both sides of a commit. After implementing recovery, run the '
        'next cell twice: the second backfill must add no notifications.')
    add('code', 'report = replay.recover()\nreport')
    add('markdown', '## Submit\n\nSave `pipeline.sql` and an incident note: explain a missed sequence, '
        'a duplicate notification, your lateness policy, recovery behavior and visibility limits. '
        'Practice targets: 27 initial notifications, 3 historical coverage warnings, 3 canonical '
        'late events, 30 notifications after recovery. Verify keys, evidence and timing as well '
        'as counts. The organizer uses a different replay schedule.\n\n'
        'When finished, close the connection and remove only this attempt’s temporary database.')
    add('code', 'replay.close()\nattempt.cleanup()')
    notebook = dict(cells=cells, metadata={'kernelspec': {'display_name': 'Python 3 (ipykernel)',
                    'language': 'python', 'name': 'python3'}, 'language_info': {'name': 'python'}},
                    nbformat=4, nbformat_minor=5)
    notebook_path = root / 'notebooks/05_Run_the_detection_in_batches.ipynb'
    notebook_path.parent.mkdir(parents=True, exist_ok=True)
    notebook_path.write_text(json.dumps(notebook, indent=1) + '\n')


if __name__ == '__main__':
    main()
