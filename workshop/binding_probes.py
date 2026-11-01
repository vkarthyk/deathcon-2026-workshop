"""Visible semantic practice records for the binding exercise, separate from the log day."""
import copy
import json

from workshop.behavioral import literal


def prepare_binding_probes(database):
    """Derive envelope-preserving examples with explicit expected behavior for edge cases."""
    if database.query("SELECT table_name FROM information_schema.tables WHERE table_schema='main' AND table_name='binding_probe_expected'"):
        return
    expected_rows = []
    # These cases are intentionally visible to participants, not incident/evaluation labels.
    variants = ('success', 'failure', 'other_role', 'wrong_kind', 'other_verb',
                'other_resource', 'missing_body', 'missing_status')
    for cloud in ('eks', 'gke', 'aks'):
        provider = {'eks': 'AWS', 'gke': 'GCP', 'aks': 'Azure'}[cloud]
        reference = database.query(f"""SELECT event_id, provider, account_uid, cluster_name,
            principal AS grant_actor FROM enterprise.k8s_ocsf
            WHERE provider={literal(provider)} AND operation='create'
              AND resource_type='clusterrolebindings' AND role_kind='ClusterRole'
              AND role='cluster-admin' ORDER BY event_id LIMIT 1""")[0]
        payload, id_path = ('entry', '$.operation.id') if cloud == 'gke' else ('event', '$.auditID')
        sample = database.query(f"SELECT * FROM enterprise.raw_{cloud} WHERE json_extract_string({payload}, {literal(id_path)}) = {literal(reference['event_id'])} LIMIT 1")[0]
        statements = [f'CREATE OR REPLACE TABLE main.binding_probe_{cloud} AS SELECT * FROM enterprise.raw_{cloud} WHERE FALSE']
        for variant in variants:
            row = copy.deepcopy(sample)
            event = json.loads(row[payload]) if isinstance(row[payload], str) else row[payload]
            event_id = f'practice-{cloud}-{variant}'
            operation = 'delete' if variant == 'other_verb' else 'create'
            resource = 'rolebindings' if variant == 'other_resource' else 'clusterrolebindings'
            role = 'view' if variant == 'other_role' else 'cluster-admin'
            kind = 'Role' if variant == 'wrong_kind' else 'ClusterRole'
            if cloud == 'gke':
                event['operation']['id'] = event_id
                p = event['protoPayload']
                p['methodName'] = f'io.k8s.authorization.rbac.v1.{resource}.{operation}'
                if variant == 'missing_status':
                    p.pop('status', None)
                else:
                    p['status'] = {'code': 7 if variant == 'failure' else 0}
                if variant == 'missing_body':
                    p.pop('request', None)
                else:
                    p.setdefault('request', {})['roleRef'] = {'kind': kind, 'name': role}
            else:
                event['auditID'], event['verb'] = event_id, operation
                event['objectRef']['resource'] = resource
                event['responseStatus'] = {} if variant == 'missing_status' else {'code': 403 if variant == 'failure' else 201}
                if variant == 'missing_body':
                    event.pop('requestObject', None)
                else:
                    event.setdefault('requestObject', {})['roleRef'] = {'kind': kind, 'name': role}
            status = 2 if variant == 'failure' else 0 if variant == 'missing_status' and cloud != 'gke' else 1
            row[payload] = json.dumps(event)
            values = ', '.join('NULL' if value is None else literal(value) for value in row.values())
            statements.append(f'INSERT INTO main.binding_probe_{cloud} VALUES ({values})')
            expected_rows.append((event_id, reference['provider'], reference['account_uid'],
                                  reference['cluster_name'], reference['grant_actor'], operation,
                                  resource, status, None if variant == 'missing_body' else kind,
                                  None if variant == 'missing_body' else role))
        database.script(';\n'.join(statements) + ';')
    columns = ('event_id VARCHAR, provider VARCHAR, account_uid VARCHAR, cluster_name VARCHAR, '
               'principal VARCHAR, operation VARCHAR, resource_type VARCHAR, status_id INTEGER, role_kind VARCHAR, role VARCHAR')
    values = ',\n'.join('(' + ', '.join('NULL' if value is None else literal(value) for value in row) + ')' for row in expected_rows)
    database.script('CREATE TABLE main.binding_probe_expected (' + columns + ');\nINSERT INTO main.binding_probe_expected VALUES ' + values + ';')
