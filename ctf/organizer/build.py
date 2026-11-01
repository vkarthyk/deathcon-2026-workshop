"""Build player-only releases and private answers: python -m ctf.organizer.build."""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
import shutil
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = ('AWS', 'GCP', 'Azure')
DAY = datetime(2026, 11, 12, 9, tzinfo=timezone.utc)


def event_id(rng):
    return str(uuid.UUID(int=rng.getrandbits(128)))


def event(rng, provider, minute, **overrides):
    accounts = {'AWS': '484822220001', 'GCP': 'ctf-platform',
                'Azure': 'a65fd201-4889-4827-9e0f-c8a568952652'}
    row = dict(event_id=event_id(rng), provider=provider, account_uid=accounts[provider],
               cluster_name='platform-prod', time=DAY + timedelta(minutes=minute),
               principal='operator@example.test', operation='create', resource_type='clusterrolebindings',
               status_id=1, namespace=None, role_kind='ClusterRole', role='cluster-admin')
    row.update(overrides)
    return row


def raw_record(row, rng):
    request = {'metadata': {'name': 'access-' + event_id(rng)[:8]},
               'roleRef': {'kind': row['role_kind'], 'name': row['role']},
               'subjects': [{'kind': 'User', 'name': 'engineer@example.test'}]}
    if row.get('misleading_name'):
        request['metadata']['name'] = 'cluster-admin'
    if row['provider'] == 'GCP':
        payload = dict(methodName=f"io.k8s.authorization.rbac.v1.{row['resource_type']}.{row['operation']}",
                       authenticationInfo={'principalEmail': row['principal']}, request=request)
        if row['status_id'] == 2:
            payload['status'] = {'code': 7}
        elif row['status_id'] == 1 and rng.choice((True, False)):
            payload['status'] = {'code': 0}
        result = dict(operation={'id': row['event_id']}, timestamp=row['time'].isoformat(),
                      resource={'labels': {'project_id': row['account_uid'], 'cluster_name': row['cluster_name']}},
                      protoPayload=payload)
    else:
        result = dict(auditID=row['event_id'], requestReceivedTimestamp=row['time'].isoformat(),
                      user={'username': row['principal']}, verb=row['operation'],
                      objectRef={'resource': row['resource_type']}, requestObject=request)
        if row['status_id']:
            result['responseStatus'] = {'code': 201 if row['status_id'] == 1 else 403}
    if row.get('missing_body'):
        if row['provider'] == 'GCP':
            result['protoPayload'].pop('request')
        else:
            result.pop('requestObject')
    return result


def easy_rows(rng):
    rows = []
    # One valid grant per cloud; IDs and delivery order carry no challenge labels.
    for provider in PROVIDERS:
        rows.append(event(rng, provider, rng.randrange(240)))
        for changes in (
            {'status_id': 2}, {'role': 'view', 'misleading_name': True},
            {'role_kind': 'Role'}, {'operation': 'delete'},
            {'resource_type': 'rolebindings'}, {'missing_body': True},
        ):
            rows.append(event(rng, provider, rng.randrange(240), **changes))
        if provider != 'GCP':
            rows.append(event(rng, provider, rng.randrange(240), status_id=0))
        for _ in range(45):
            rows.append(event(rng, provider, rng.randrange(240), operation=rng.choice(('get', 'list', 'watch')),
                              resource_type=rng.choice(('pods', 'deployments', 'configmaps')),
                              role='view', principal='system:serviceaccount:platform:controller'))
    rng.shuffle(rows)
    return rows


def hard_rows(rng):
    events, subjects, approvals = [], [], []
    cases = ['target', 'actor', 'cluster', 'account', 'before', 'late', 'approved',
             'denied_grant', 'denied_read', 'namespace', 'wrong_kind', 'service_account', 'wrong_role']
    rng.shuffle(cases)
    for index, case in enumerate(cases):
        provider = rng.choice(PROVIDERS)
        minute = index * 25 + rng.randrange(5)
        recipient = f'engineer-{rng.randrange(1000, 9999)}@example.test'
        actor = f'admin-{rng.randrange(1000, 9999)}@example.test'
        grant = event(rng, provider, minute, principal=actor)
        subject_kind = 'ServiceAccount' if case == 'service_account' else 'User'
        if case == 'denied_grant':
            grant['status_id'] = 2
        if case == 'wrong_kind':
            grant['role_kind'] = 'Role'
        if case == 'wrong_role':
            grant['role'] = 'view'
        def subject(name, kind):
            return {key: grant[key] for key in ('provider', 'account_uid', 'cluster_name', 'event_id')} | dict(subject=name, subject_kind=kind)
        # Every binding has repeated subjects. The first subject never performs a secret list.
        subjects += [subject(f'observer-{index}@example.test', 'User'), subject(recipient, subject_kind)]
        offset = -1 if case == 'before' else 16 if case == 'late' else rng.randrange(1, 15)
        read = event(rng, provider, minute + offset, principal=recipient,
                     operation='list', resource_type='secrets', role_kind=None, role=None)
        if case == 'actor':
            read['principal'] = actor
        if case == 'cluster':
            read['cluster_name'] = 'platform-dev'
        if case == 'account':
            read['account_uid'] = grant['account_uid'] + '-other'
        if case == 'denied_read':
            read['status_id'] = 2
        if case == 'namespace':
            read['namespace'] = 'payments'
        events += [grant, read]
        approval = dict(cloud_provider=provider, account_uid=grant['account_uid'],
                        cluster_name=grant['cluster_name'], grant_actor=actor, subject=recipient,
                        role='cluster-admin', start_time=grant['time'] - timedelta(minutes=5),
                        end_time=grant['time'] + timedelta(minutes=20), ticket='CHG-' + event_id(rng)[:8])
        if case == 'approved':
            approvals.append(approval)
        if case == 'target':
            # Near-matching approvals must not suppress the real sequence.
            approvals += [approval | {'end_time': grant['time'] - timedelta(seconds=1)},
                          approval | {'grant_actor': 'other-admin@example.test'},
                          approval | {'subject': 'other-user@example.test'},
                          approval | {'cluster_name': 'platform-dev'},
                          approval | {'account_uid': grant['account_uid'] + '-other'},
                          approval | {'role': 'view'},
                          approval | {'cloud_provider': next(p for p in PROVIDERS if p != provider)}]
    for _ in range(450):
        events.append(event(rng, rng.choice(PROVIDERS), rng.randrange(400),
                            principal=rng.choice(('system:serviceaccount:apps:controller', 'developer@example.test')),
                            operation=rng.choice(('get', 'list', 'watch', 'patch')),
                            resource_type=rng.choice(('pods', 'deployments', 'configmaps')),
                            namespace='apps', role_kind=None, role=None))
    for rows in (events, subjects, approvals):
        rng.shuffle(rows)
    identities = [dict(cloud_provider=p, account_uid=event(rng, p, 0)['account_uid'],
                       principal_name='developer@example.test', person_id='person-024') for p in PROVIDERS]
    return events, subjects, approvals, identities


def write_jsonl(path, rows):
    path.write_text(''.join(json.dumps(row, default=str) + '\n' for row in rows))


def make_notebook(title, tables):
    cells = []
    def add(kind, text):
        cell = dict(cell_type=kind, metadata={}, id=f'ctf-{len(cells)}', source=text.splitlines(keepends=True))
        if kind == 'code':
            cell.update(execution_count=None, outputs=[])
        cells.append(cell)
    add('markdown', f'# {title}\n\nRead README.md for the objective and submission format. HINTS.md contains optional progressive hints. No workshop setup, credentials or LLM is needed.')
    add('markdown', '## Open the challenge\n\nRun this cell from the extracted challenge folder. The connection is read-only; edit SELECT queries freely.')
    add('code', 'from pathlib import Path\nimport duckdb\n\ndatabase = Path("challenge.duckdb")\nif not database.exists():\n    raise FileNotFoundError("Open this notebook from the extracted challenge folder.")\ncon = duckdb.connect(str(database), read_only=True)\ncon.sql("SHOW TABLES").df()')
    add('markdown', '## Inspect fields and records\n\nStart by reading the schema and a few records. Add code cells with `con.sql("""YOUR SQL""").df()` to investigate. SQL text values and JSON paths use single quotes.')
    add('code', f'con.sql("DESCRIBE {tables[0]}").df()')
    add('code', f'con.sql("SELECT * FROM {tables[0]} LIMIT 5").df()')
    add('markdown', '## Build your detection\n\nWrite your SELECT queries below. Check the challenge conditions and copy event IDs into the requested flag format. A result is evidence of matching behavior, not proof of malicious intent.')
    add('code', '# TODO: replace this preview with your detection.\ncon.sql("""\nSELECT * FROM '+tables[0]+' LIMIT 5\n""").df()')
    return dict(cells=cells, metadata={'kernelspec': {'display_name': 'Python 3 (ipykernel)', 'language': 'python', 'name': 'python3'},
                                    'language_info': {'name': 'python', 'version': '3.11'}}, nbformat=4, nbformat_minor=5)


def build(output, seed='practice'):
    import duckdb
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError('Output directory must be empty. Choose a new --output to preserve earlier releases.')
    output.mkdir(parents=True, exist_ok=True)
    private = output / 'organizer'
    private.mkdir()
    rng = random.Random(seed)
    answers = {}
    for name in ('easy', 'hard'):
        folder = output / 'players' / name
        folder.mkdir(parents=True)
        for filename in ('README.md', 'HINTS.md'):
            shutil.copyfile(ROOT / name / filename, folder / filename)
        with duckdb.connect(str(folder / 'challenge.duckdb')) as con:
            if name == 'easy':
                rows = easy_rows(rng)
                for provider, table, column in (('AWS', 'raw_eks', 'event'), ('GCP', 'raw_gke', 'entry'), ('Azure', 'raw_aks', 'event')):
                    path = folder / (table + '.jsonl')
                    records = [dict(account_uid=row['account_uid'], cluster_name=row['cluster_name'],
                                    **{column: raw_record(row, rng)}) for row in rows if row['provider'] == provider]
                    write_jsonl(path, records)
                    con.execute(f'CREATE TABLE {table} AS SELECT account_uid, cluster_name, {column}::JSON AS {column} FROM read_json_auto(?)', [str(path)])
                tables = ['raw_eks', 'raw_gke', 'raw_aks']
            else:
                events, subjects, approvals, identities = hard_rows(rng)
                tables = ['k8s_ocsf', 'k8s_subjects', 'approvals', 'identities']
                for table, records in zip(tables, (events, subjects, approvals, identities)):
                    path = folder / (table + '.jsonl')
                    write_jsonl(path, records)
                    projection = ('* REPLACE (event_id::VARCHAR AS event_id, time::TIMESTAMPTZ AS time)' if table == 'k8s_ocsf' else
                                  '* REPLACE (start_time::TIMESTAMPTZ AS start_time, end_time::TIMESTAMPTZ AS end_time)' if table == 'approvals' else '* REPLACE (event_id::VARCHAR AS event_id)' if table == 'k8s_subjects' else '*')
                    con.execute(f'CREATE TABLE {table} AS SELECT {projection} FROM read_json_auto(?)', [str(path)])
            result = con.sql((ROOT / 'organizer' / (name + '.sql')).read_text()).fetchall()
            if name == 'easy':
                found = dict(result)
                if len(result) != 3 or set(found) != set(PROVIDERS):
                    raise ValueError('Easy challenge must have exactly one solution per cloud.')
                answer = 'CTF{' + '_'.join(found[p] for p in PROVIDERS) + '}'
            else:
                if len(result) != 1:
                    raise ValueError('Hard challenge must have exactly one qualifying pair.')
                answer = 'CTF{' + '_'.join(map(str, result[0])) + '}'
            answers[name] = dict(flag=answer, solution_rows=[list(row) for row in result])
        notebook = make_notebook('Find the admin grant' if name == 'easy' else 'Follow the recipient', tables)
        (folder / 'Start.ipynb').write_text(json.dumps(notebook, indent=1) + '\n')
        with zipfile.ZipFile(output / (name + '.zip'), 'w', zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(folder.iterdir()):
                archive.write(path, arcname=name + '/' + path.name)
    (private / 'answers.json').write_text(json.dumps(answers, indent=2) + '\n')
    return answers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    parser.add_argument('--seed', default='practice', help='Use a private seed for competition releases; default is reproducible practice.')
    args = parser.parse_args()
    build(args.output, args.seed)
    print(f'Player downloads: {args.output}/easy.zip and {args.output}/hard.zip')
    print(f'PRIVATE answer key: {args.output}/organizer/answers.json')


if __name__ == '__main__':
    main()
