"""Generate the service-account baseline lab: raw multi-cloud logs and private expectations.

Only the raw logs and action catalog are distributed to students. Expectations are
constructed from scenario intent, never by running the reference SQL.

Scenarios per cloud (AWS CloudTrail, GCP Cloud Audit Logs, Azure Activity Log):
  backup-agent   credential stolen on the detection day: new network, client and actions
  ci-deployer    legitimate new action; rotating NAT hosts; Terraform version bump
  monitoring     stolen token used with baseline behavior only (intentional blind spot)
  data-export    created two days before detection: insufficient baseline
  backup-agent   in a second account, where reading secrets is normal
  alice          a human whose new activity is out of scope for this rule
"""
from datetime import datetime, timedelta, timezone
import csv
import gzip
import io
import json
from pathlib import Path
import random
import uuid

ROOT = Path(__file__).resolve().parents[1]
BASELINE_START = datetime(2026, 10, 29, tzinfo=timezone.utc)
DETECTION_START = datetime(2026, 11, 12, tzinfo=timezone.utc)
DETECTION_END = DETECTION_START + timedelta(days=1)
MIN_BASELINE_DAYS = 7
BASELINE_DAYS = (DETECTION_START - BASELINE_START).days

# Shared action types -> raw provider operation. The catalog is supplied to students.
CATALOG = {
    'AWS': {
        'storage-read': ('s3.amazonaws.com', 'GetObject'),
        'storage-write': ('s3.amazonaws.com', 'PutObject'),
        'compute-list': ('ec2.amazonaws.com', 'DescribeInstances'),
        'compute-create': ('ec2.amazonaws.com', 'RunInstances'),
        'compute-modify': ('ec2.amazonaws.com', 'ModifyInstanceAttribute'),
        'secret-read': ('secretsmanager.amazonaws.com', 'GetSecretValue'),
        'iam-key-create': ('iam.amazonaws.com', 'CreateAccessKey'),
        'iam-user-create': ('iam.amazonaws.com', 'CreateUser'),
        'iam-role-assign': ('iam.amazonaws.com', 'AttachRolePolicy'),
        'deployment-create': ('cloudformation.amazonaws.com', 'CreateStack'),
    },
    'GCP': {
        'storage-read': ('storage.googleapis.com', 'storage.objects.get'),
        'storage-write': ('storage.googleapis.com', 'storage.objects.create'),
        'compute-list': ('compute.googleapis.com', 'v1.compute.instances.list'),
        'compute-create': ('compute.googleapis.com', 'v1.compute.instances.insert'),
        'compute-modify': ('compute.googleapis.com', 'v1.compute.instances.setMachineType'),
        'secret-read': ('secretmanager.googleapis.com',
                        'google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion'),
        'iam-key-create': ('iam.googleapis.com', 'google.iam.admin.v1.CreateServiceAccountKey'),
        'iam-user-create': ('iam.googleapis.com', 'google.iam.admin.v1.CreateServiceAccount'),
        'iam-role-assign': ('cloudresourcemanager.googleapis.com', 'SetIamPolicy'),
        'deployment-create': ('deploymentmanager.googleapis.com', 'v2.deploymentmanager.deployments.insert'),
    },
    'Azure': {
        'storage-read': ('', 'Microsoft.Storage/storageAccounts/read'),
        'storage-write': ('', 'Microsoft.Storage/storageAccounts/write'),
        'compute-list': ('', 'Microsoft.Compute/virtualMachines/read'),
        'compute-create': ('', 'Microsoft.Compute/virtualMachines/write'),
        'compute-modify': ('', 'Microsoft.Compute/virtualMachines/restart/action'),
        'secret-read': ('', 'Microsoft.Web/sites/config/list/action'),
        'iam-key-create': ('', 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write'),
        'iam-user-create': ('', 'Microsoft.ManagedIdentity/userAssignedIdentities/write'),
        'iam-role-assign': ('', 'Microsoft.Authorization/roleAssignments/write'),
        'deployment-create': ('', 'Microsoft.Resources/deployments/write'),
    },
}
CATEGORY = {'storage': 'storage', 'compute': 'compute', 'secret': 'secrets', 'iam': 'identity',
            'deployment': 'control_plane'}
# Operations deliberately absent from the catalog. They must not disappear from the baseline.
UNMAPPED = {'AWS': ('sts.amazonaws.com', 'GetCallerIdentity'),
            'GCP': ('iam.googleapis.com', 'google.iam.admin.v1.ListServiceAccounts'),
            'Azure': ('', 'Microsoft.Storage/storageAccounts/listKeys/action')}
USER_AGENTS = {
    'backup-agent': {'AWS': 'aws-sdk-go-v2/1.30.3 os/linux lang/go#1.22', 'GCP': 'google-cloud-storage-python/2.14.0 gccl'},
    'monitoring': {'AWS': 'aws-sdk-go/1.50.0 (go1.21; linux; amd64)', 'GCP': 'google-api-go-client/0.5 monitoring'},
    'data-export': {'AWS': 'Boto3/1.34.0 md/Botocore#1.34.0', 'GCP': 'gcloud-python/3.0 data-export'},
    'alice': {'AWS': 'aws-cli/2.15.0 Python/3.11.6 Darwin/23.0.0', 'GCP': 'google-cloud-sdk/470.0.0 command/gcloud'},
}
ATTACKER_UA = 'python-requests/2.31.0'


def catalog_rows():
    rows = []
    for provider, actions in CATALOG.items():
        for action, (_, api) in actions.items():
            rows.append(dict(cloud_provider=provider, cloud_api_action=api, action_type=action,
                             service_category=CATEGORY[action.split('-')[0]]))
    return rows


def build(seed='practice'):
    rng = random.Random(seed)
    raw = {'AWS': [], 'GCP': [], 'Azure': []}
    expected = {'alerts': {}, 'insufficient': {}, 'identities': set(), 'events': {}}

    def uid():
        return str(uuid.UUID(int=rng.getrandbits(128)))

    def digits(n):
        return ''.join(rng.choice('0123456789') for _ in range(n))

    def when(day_start, low=6, high=22):
        return day_start + timedelta(hours=rng.randrange(low, high), minutes=rng.randrange(60),
                                     seconds=rng.randrange(60))

    accounts = {
        'AWS': (digits(12), digits(12)),
        'GCP': (f'acme-prod-{digits(4)}', f'acme-data-{digits(4)}'),
        'Azure': (uid(), uid()),
    }
    app_ids = {name: uid() for name in ('backup-agent', 'ci-deployer', 'monitoring', 'data-export')}
    attacker_ip = f'198.51.100.{rng.randrange(2, 250)}'
    new_export_ip = f'203.0.113.{rng.randrange(100, 200)}'

    def identity(provider, name, primary, secondary):
        """Normalized principal string, per the lab's identity contract."""
        if name == 'alice':
            if provider == 'AWS':
                return f'arn:aws:sts::{secondary}:assumed-role/AWSReservedSSO_PlatformAdmin_0123abcd/alice@example.test'
            return 'alice@example.test'
        if provider == 'AWS':
            return f'arn:aws:iam::{secondary}:role/{name}'
        if provider == 'GCP':
            # Service accounts keep their home project's email in every project they act in.
            return f'{name}@{primary}.iam.gserviceaccount.com'
        return app_ids[name]

    def emit(provider, account, home, name, action, time, ip, ua, success=True, start_event=True,
             service_origin=None):
        """Append one provider-native record. Returns the number of records written."""
        if action in CATALOG[provider]:
            service, api = CATALOG[provider][action]
        else:
            service, api = UNMAPPED[provider]
        event_id = uid()
        if provider == 'AWS':
            if name == 'alice':
                issuer = 'AWSReservedSSO_PlatformAdmin_0123abcd'
                session = 'alice@example.test'
            else:
                issuer, session = name, f'{name}-{uid()[:8]}'
            record = {
                'eventVersion': '1.09', 'eventID': event_id,
                'eventTime': time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'eventSource': service, 'eventName': api, 'awsRegion': 'us-east-1',
                'sourceIPAddress': service_origin or ip,
                'userAgent': service_origin or ua,
                'userIdentity': {
                    'type': 'AssumedRole', 'principalId': f'AROA{digits(17)}:{session}',
                    'arn': f'arn:aws:sts::{account}:assumed-role/{issuer}/{session}',
                    'accountId': account,
                    'sessionContext': {'sessionIssuer': {
                        'type': 'Role', 'principalId': f'AROA{digits(17)}',
                        'arn': f'arn:aws:iam::{account}:role/{issuer}',
                        'accountId': account, 'userName': issuer}}},
                'recipientAccountId': account, 'eventType': 'AwsApiCall', 'readOnly': False,
            }
            if not success:
                record['errorCode'] = 'AccessDenied'
                record['errorMessage'] = 'User is not authorized to perform this operation'
            raw['AWS'].append(record)
            return 1
        if provider == 'GCP':
            email = 'alice@example.test' if name == 'alice' else f'{name}@{home}.iam.gserviceaccount.com'
            payload = {
                '@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                'serviceName': service, 'methodName': api,
                'authenticationInfo': {'principalEmail': email},
                'requestMetadata': {'callerIp': service_origin or ip, 'callerSuppliedUserAgent': ua},
                'resourceName': f'projects/{account}/resources/{uid()[:8]}',
            }
            if not success:
                payload['status'] = {'code': 7, 'message': 'PERMISSION_DENIED'}
            elif rng.random() < 0.3:
                payload['status'] = {}
            raw['GCP'].append({
                'insertId': event_id, 'logName': f'projects/{account}/logs/cloudaudit.googleapis.com%2Factivity',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S.%fZ'), 'severity': 'NOTICE' if success else 'ERROR',
                'resource': {'type': 'audited_resource', 'labels': {'project_id': account, 'service': service}},
                'protoPayload': payload})
            return 1
        # Azure Activity Log: each operation emits a Start event, then Success or Failure.
        correlation = uid()
        if name == 'alice':
            claims = {'idtyp': 'user', 'name': 'Alice', 'oid': uid()}
            caller = 'alice@example.test'
        else:
            claims = {'idtyp': 'app', 'appid': app_ids[name], 'oid': uid()}
            caller = claims['oid']
        resource = f'/subscriptions/{account}/resourceGroups/rg-{name}/providers/{api.rsplit("/", 1)[0]}/{name}-{uid()[:6]}'
        written = 0
        phases = (['Start'] if start_event else []) + ['Success' if success else 'Failure']
        for offset, phase in enumerate(phases, start=1 - len(phases)):
            # Start precedes the outcome; the outcome record carries the operation time.
            raw['Azure'].append({
                'time': (time + timedelta(milliseconds=400 * offset)).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                'eventDataId': event_id if phase != 'Start' else uid(),
                'correlationId': correlation, 'resourceId': resource, 'operationName': api,
                'category': 'Administrative', 'resultType': phase,
                'level': 'Error' if phase == 'Failure' else 'Informational',
                'callerIpAddress': ip, 'caller': caller,
                'identity': {'claims': claims},
                'properties': {'statusCode': 'Forbidden' if phase == 'Failure' else
                               'Created' if phase == 'Success' else 'Accepted'},
            })
            written += 1
        return written

    for provider in ('AWS', 'GCP', 'Azure'):
        primary, secondary = accounts[provider]
        counts = expected['events'][provider] = {'rows': 0, 'service_account': 0, 'success': 0}
        observed = {}

        def record(name, account, action, time, ip, ua, success=True, service_origin=None, start_event=True):
            n = emit(provider, account, primary, name, action, time, ip, ua, success, start_event, service_origin)
            counts['rows'] += n
            if name != 'alice':
                counts['service_account'] += n
                expected['identities'].add((provider, account, identity(provider, name, primary, account)))
            if success:
                counts['success'] += 1
            return time

        def ua_for(name):
            return None if provider == 'Azure' else USER_AGENTS[name][provider]

        def note(name, account, dimension, value, time):
            """Record an intended deviation: first observation time and successful event count."""
            key = (provider, account, identity(provider, name, primary, account), dimension, value)
            entry = observed.setdefault(key, {'first_seen': time, 'event_count': 0})
            entry['first_seen'] = min(entry['first_seen'], time)
            entry['event_count'] += 1

        for day in range(BASELINE_DAYS):
            start = BASELINE_START + timedelta(days=day)
            # Established service accounts: active every baseline day.
            for action in ('storage-read', 'storage-write') + (('storage-read',) * rng.randrange(3)):
                record('backup-agent', primary, action, when(start), '192.0.2.10', ua_for('backup-agent'))
            for action in ('storage-read', 'secret-read') + (('secret-read',) * rng.randrange(2)):
                record('backup-agent', secondary, action, when(start), '192.0.2.20', ua_for('backup-agent'))
            for action in ('compute-create', 'storage-write', 'deployment-create'):
                ci_ua = None if provider == 'Azure' else f'Terraform/1.9.{rng.randrange(6)} (+https://www.terraform.io)'
                record('ci-deployer', primary, action, when(start), f'203.0.113.{rng.randrange(10, 41)}', ci_ua)
            for _ in range(2 + rng.randrange(3)):
                record('monitoring', primary, 'compute-list', when(start, 0, 24), '198.18.0.5', ua_for('monitoring'))
            if day >= BASELINE_DAYS - 2:
                record('data-export', primary, 'storage-read', when(start), '192.0.2.30', ua_for('data-export'))
            if day % 3 != 2:
                record('alice', secondary if provider == 'AWS' else primary, 'compute-create', when(start),
                       '192.0.2.50', ua_for('alice'))

        day = DETECTION_START
        # Normal detection-day behavior for established accounts.
        for action in ('storage-read', 'storage-write', 'storage-read'):
            record('backup-agent', primary, action, when(day, 1, 6), '192.0.2.10', ua_for('backup-agent'))
        for action in ('storage-read', 'secret-read'):
            record('backup-agent', secondary, action, when(day), '192.0.2.20', ua_for('backup-agent'))
        # Stolen backup-agent credential, used from a new network with a scripting client.
        attack = when(day, 9, 10)
        attacker = [('storage-read', True)] * 2 + [('secret-read', True)] * 3 + [
            ('iam-key-create', True), ('unmapped', True), ('iam-user-create', False)]
        for index, (action, success) in enumerate(attacker):
            time = attack + timedelta(minutes=3 * index, seconds=rng.randrange(60))
            record('backup-agent', primary, action, time, attacker_ip,
                   None if provider == 'Azure' else ATTACKER_UA, success)
            if not success:
                continue  # Failed calls are out of scope for this rule.
            value = UNMAPPED[provider][1] if action == 'unmapped' else action
            if action != 'storage-read':
                note('backup-agent', primary, 'action', value, time)
            note('backup-agent', primary, 'source_network', '198.51.100.0/24', time)
            if provider != 'Azure':
                note('backup-agent', primary, 'user_agent', 'python-requests', time)
        # Legitimate change: new action, new NAT host in the same /24, newer Terraform.
        ci_ua = None if provider == 'Azure' else 'Terraform/1.10.0 (+https://www.terraform.io)'
        for action in ('compute-create', 'deployment-create', 'compute-modify', 'compute-modify'):
            time = record('ci-deployer', primary, action, when(day, 12, 14),
                          f'203.0.113.{rng.randrange(41, 61)}', ci_ua)
            if action == 'compute-modify':
                note('ci-deployer', primary, 'action', 'compute-modify', time)
        if provider == 'AWS':
            # CloudFormation acting with the deployer's credentials: the source is a service name.
            for _ in range(2):
                record('ci-deployer', primary, 'compute-create', when(day, 12, 14), None, None,
                       service_origin='cloudformation.amazonaws.com')
        # Stolen monitoring token, used exactly like the baseline: the rule cannot see it.
        for _ in range(25 + rng.randrange(15)):
            record('monitoring', primary, 'compute-list', when(day, 0, 24), '198.18.0.5', ua_for('monitoring'))
        if provider == 'GCP':
            for _ in range(3):
                record('monitoring', primary, 'compute-list', when(day), None, ua_for('monitoring'),
                       service_origin='private')
        # New service account: two baseline days is insufficient history.
        export_events = 0
        for action in ('storage-read', 'storage-write', 'storage-read'):
            record('data-export', primary, action, when(day), new_export_ip, ua_for('data-export'))
            export_events += 1
        expected['insufficient'][(provider, primary, identity(provider, 'data-export', primary, primary))] = {
            'baseline_days': 2, 'detection_events': export_events}
        # A human doing something new: out of scope for a service-account rule.
        record('alice', secondary if provider == 'AWS' else primary, 'iam-role-assign', when(day),
               '203.0.113.200', ua_for('alice'))
        for key, value in observed.items():
            expected['alerts'][key] = {'first_seen': value['first_seen'].isoformat(),
                                       'event_count': value['event_count']}
    for provider in raw:
        rng.shuffle(raw[provider])
    return raw, expected


FILES = {'AWS': 'aws_cloudtrail.jsonl.gz', 'GCP': 'gcp_audit.jsonl.gz', 'Azure': 'azure_activity.jsonl.gz'}


def write_raw(raw, folder):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for provider, name in FILES.items():
        text = ''.join(json.dumps(record, sort_keys=True) + '\n' for record in raw[provider])
        # mtime=0 keeps the compressed file byte-for-byte reproducible.
        with open(folder / name, 'wb') as handle, gzip.GzipFile(fileobj=handle, mode='wb', mtime=0) as archive:
            archive.write(text.encode())


def write_catalog(path):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=('cloud_provider', 'cloud_api_action', 'action_type',
                                                'service_category'), lineterminator='\n')
    writer.writeheader()
    writer.writerows(catalog_rows())
    Path(path).write_text(buffer.getvalue())


DETECTION_LINK = '[`labs/service_account_baseline/detection.sql`](../labs/service_account_baseline/detection.sql)'


def hint(title, body):
    return f'<details>\n<summary>Need a hint? {title}</summary>\n\n{body.strip()}\n\n</details>'


def notebook():
    cells = []

    def add(kind, source):
        cell = dict(cell_type=kind, id=f'service_account_baseline-{len(cells)}', metadata={},
                    source=source.strip('\n').splitlines(keepends=True))
        if kind == 'code':
            cell.update(execution_count=None, outputs=[])
        cells.append(cell)

    add('markdown', f'''# 05 Detect service account deviations

**Extra lab · about 60 minutes · after notebooks 01–04**

Notebooks 01–04 applied one schema to one Kubernetes behavior. This lab tests whether
the method transfers to a different log source and a different kind of detection.
You map AWS CloudTrail, GCP Cloud Audit Logs and Azure Activity Log records to one
contract, learn what each service account normally does, and flag what it has never
done before. The detection follows the "Service Account Activity Baseline Deviation"
example in [Multi-Cloud Detection at Scale](https://cloudnativedetection.substack.com/p/multi-cloud-detection-at-scale-a).

Everything runs locally on synthetic logs. No cloud access, credentials or model is needed.

**Where you work:** make all your changes in one file, {DETECTION_LINK}.
Paths are relative to the repository root. Keep the file's view names and columns.
Save the file, then rerun the notebook cells to see the effect.

| Step | Time | You edit |
|---|---|---|
| 1. Read the raw records | 10 min | Nothing; read the AWS worked example |
| 2. Map GCP and Azure | 15 min | `sa.gcp_events` and `sa.azure_events` |
| 3. Fix the baseline rule | 20 min | `sa.observations`, `sa.baseline`, `sa.deviations`, `sa.insufficient_baseline` |
| 4. Triage | 10 min | Nothing; answer the questions |''')
    add('markdown', '''## The brief

Service accounts are predictable: the same job calls the same APIs from the same
place with the same client every day. That makes "never done this before" a useful
signal when a credential is stolen.

The data covers a **14-day learning window** (29 October to 11 November 2026) and
**one detection day** (12 November). Your rule reports, for each service account in
each account or project, every action, source network or client it used on the
detection day that it never used in the learning window.

A deviation is a reason to investigate, not proof of compromise.''')
    add('markdown', '''## Set up

Run this cell once per kernel. It loads the raw logs into a fresh temporary DuckDB
database and shows the learning and detection windows.

<details>
<summary>Prefer the command line?</summary>

From the repository root:

```bash
.workshop-venv/bin/python -m workshop.service_account_baseline --database artifacts/sa_baseline.duckdb
```

On Windows use `.\\.workshop-venv\\Scripts\\python.exe`. Do not name the database file
`raw`, `ref`, `lab` or `sa`; DuckDB would confuse it with a lab schema.

</details>''')
    add('code', '''from pathlib import Path
import json
import sys
import tempfile

root = next((p for p in (Path.cwd(), *Path.cwd().parents)
             if (p / 'labs/service_account_baseline/detection.sql').exists()), None)
if root is None:
    raise FileNotFoundError('Open this notebook inside the extracted workshop repository.')
sys.path.insert(0, str(root))
from workshop.service_account_baseline import Lab, rows

# A fresh temporary database per attempt. The raw logs are loaded once.
attempt = tempfile.TemporaryDirectory(prefix='service_account_baseline-notebook-')
lab = Lab(Path(attempt.name) / 'state.duckdb')
detection = root / 'labs/service_account_baseline/detection.sql'
lab.window()''')
    add('markdown', f'''## 1. Read the raw records — 10 minutes

The next cell prints one `backup-agent` record from each cloud. For each, find the
**caller**, the **account**, the **operation**, the **source address**, the **client**
and the **outcome**. Each cloud names the same ideas differently.

Then open {DETECTION_LINK} and read the `sa.aws_events` view at the top. It is a
complete worked example. Notice:

- An AWS role session ARN changes with every session. The **issuing role ARN** is
  the stable identity.
- People also use roles in AWS, through IAM Identity Center (`AWSReservedSSO_*`).
  Those are humans.
- When an AWS service acts with the caller's credentials, the source address is a
  service name such as `cloudformation.amazonaws.com`, not an IP.
- Azure Activity Log has no user agent at all.''')
    add('code', '''for provider in ('AWS', 'GCP', 'Azure'):
    print(f'--- {provider}')
    print(json.dumps(lab.sample(provider, 'backup-agent', '192.0.2.10'), indent=2))''')
    add('markdown', f'''## 2. Map GCP and Azure — 15 minutes

**Edit:** {DETECTION_LINK}, views `sa.gcp_events` and `sa.azure_events`.

Replace each `NULL` placeholder marked `-- TODO` with an expression that reads the
field from the raw record `r`. Leave the supplied `sa.events` view below them unchanged.

| Column | GCP | Azure |
|---|---|---|
| `account_uid` | Project ID in the monitored resource labels | Subscription ID inside `resourceId` |
| `principal` | Authenticated principal email | `identity.claims.appid` when `idtyp = 'app'`, otherwise `caller` |
| `principal_type` | `service_account` if the email ends in `.gserviceaccount.com` | `service_account` if `idtyp = 'app'` |
| `source_ip` | `callerIp`, or NULL if it is not an IPv4 address (for example `private`) | `callerIpAddress`, same rule |
| `user_agent` | `callerSuppliedUserAgent` | Not recorded: NULL |
| `status_id` | 1 when `status.code` is missing or 0, else 2 | `Success` 1, `Failure` 2, `Start` 0 |

The supplied `sa.events` view joins `ref.action_catalog`, which translates raw
operations such as `GetSecretValue` and `AccessSecretVersion` into one shared
`action_type`, here `secret-read`.

**Done when:** after saving the file and running the next cell, every provider has
zero `missing_principal`, `missing_account` and `missing_status`, and zero
`invalid_principal_type`.''')
    add('markdown', hint('Where are the GCP and Azure fields?', '''
GCP: `r->>'$.resource.labels.project_id'`,
`r->>'$.protoPayload.authenticationInfo.principalEmail'`,
`r->>'$.protoPayload.requestMetadata.callerIp'` and `.callerSuppliedUserAgent`,
`r->>'$.protoPayload.status.code'`.

Azure: `split_part(r->>'$.resourceId', '/', 3)`, `r->>'$.identity.claims.idtyp'`,
`r->>'$.identity.claims.appid'`, `r->>'$.caller'`, `r->>'$.callerIpAddress'`,
`r->>'$.resultType'`. Reuse the AWS IPv4 `regexp_matches` test.'''))
    add('code', 'lab.run(detection)\nlab.quality()')
    add('markdown', f'''## 3. Fix the baseline rule — 20 minutes

**Edit:** {DETECTION_LINK}, views `sa.observations`, `sa.baseline`, `sa.deviations`
and `sa.insufficient_baseline` in the lower half of the file.

The starter is the simple version from the article: compare exact values with a
baseline keyed by principal. It runs, and it is wrong. Run the cells below to see
what it reports, then fix it so that:

1. **Only successful service-account calls count**, in both the baseline and the
   detection day. Failed calls and Azure `Start` events are not behavior the
   account completed.
2. **The baseline is scoped to provider, account and principal.** In GCP and Azure,
   one service account can act in several projects or subscriptions with different
   duties. Reading secrets may be normal in one and new in another.
3. **Actions missing from the catalog still count.** Use the raw `cloud_api_action`
   when `action_type` is NULL. Unknown operations must not disappear.
4. **Networks, not hosts.** Compare IPv4 sources as `/24` networks, written as
   `a.b.c.0/24`. NAT gateways and CI runners rotate hosts within a range.
5. **Client family, not version.** Compare user agents as the lower-case text before
   the first `/`, trimmed: `Terraform/1.10.0 (...)` becomes `terraform`.
6. **Missing values are not deviations.** Compare only non-NULL sources and clients.
7. **Insufficient history is reported separately.** A principal with fewer than
   `min_baseline_days` (7) distinct active days in the learning window belongs in
   `sa.insufficient_baseline` with its `baseline_days` and detection-day event
   count, and nowhere in `sa.deviations`.

Each row of `sa.deviations` is one new value for one principal, with `first_seen`,
`last_seen`, `event_count` (successful detection-day events with that value) and a
`sample_event_id`.

**After each edit:** save the file, rerun the `lab.run(detection)` cell in step 2,
then rerun the cells below.''')
    add('markdown', '\n\n'.join([
        hint('Why are some secret reads missing from the deviations?', '''
Look at the same GCP email or Azure application ID in both accounts. If the
baseline is keyed by principal alone, normal behavior in one account hides new
behavior in another. Add `cloud_provider` and `account_uid` to the baseline and
to the comparison.'''),
        hint('Why are there deviations with a NULL observed value?', '''
`NULL = NULL` is not true in SQL, so a NULL can never match the baseline. Filter
NULL sources and clients out of `sa.observations`, and use
`coalesce(action_type, cloud_api_action)` for actions.'''),
        hint('How do I turn values into networks and client families?', '''
`regexp_replace(source_ip, '\\.\\d+$', '.0/24')` and
`lower(trim(split_part(user_agent, '/', 1)))`.'''),
        hint('How do I require enough history?', '''
`sa.baseline_coverage` already counts distinct active days. Join it in
`sa.deviations` and keep principals with `baseline_days >= min_baseline_days`
from `lab.detection_window`. For `sa.insufficient_baseline`, start from the
detection-day observations, LEFT JOIN coverage, and keep principals below the
threshold, using `coalesce(baseline_days, 0)`. Count distinct `event_id`s.''')]))
    add('code', 'rows(lab.db, "SELECT * FROM sa.deviations ORDER BY cloud_provider, principal, dimension, observed_value")')
    add('markdown', 'Accounts without enough history cannot be baselined. They belong in this separate review list, '
        'not in the deviation alerts and not silently dropped.')
    add('code', 'rows(lab.db, "SELECT * FROM sa.insufficient_baseline ORDER BY cloud_provider, principal")')
    add('markdown', '''## 4. Triage — 10 minutes

For each principal with deviations, decide whether it looks like **credential
misuse**, a **legitimate change**, or **unknown**, and say what evidence you used.
The next cell lists every detection-day event for those principals.

Then find the attack this rule cannot see. Hint: compare detection-day volume with
the baseline. What other signals would reveal it?''')
    add('code', '''rows(lab.db, """SELECT e.cloud_provider, e.principal, e.time, e.cloud_api_action, e.action_type,
       e.source_ip, e.user_agent, e.status_id
FROM sa.events e JOIN sa.deviations d USING (cloud_provider, account_uid, principal)
WHERE e.time >= (SELECT detection_start FROM lab.detection_window)
GROUP BY ALL ORDER BY e.cloud_provider, e.principal, e.time""")''')
    add('markdown', '''## Practice targets

With the practice data, a correct solution reports:

- **17 deviations**: 6 AWS, 6 GCP and 5 Azure (12 actions, 3 networks, 2 clients).
  Azure has no user agents, so it has one fewer.
- **3 principals with insufficient history**, one per cloud, each with 2 baseline days.
- `lab.quality()` shows AWS 233 rows (222 service account), GCP 226 (215) and
  Azure 448 (426), with Azure's 224 `Start` events as status 0.

The organizer grades with a different data set, so follow the rules in step 3
instead of tuning to these counts.''')
    add('markdown', '''## Submit and debrief

Submit `labs/service_account_baseline/detection.sql` and a short note covering:

- your identity choices for each cloud
- one false positive you removed, and how
- one deviation you consider benign, and why
- the blind spot

Discuss before production use: how long the learning window should be, how to keep
an attacker from becoming part of the baseline, how to handle IPv6 and
cloud-provider address ranges, and who reviews new accounts.

When finished, run the next cell to remove only this attempt’s temporary database.''')
    add('code', 'attempt.cleanup()')
    return dict(cells=cells, metadata={'kernelspec': {'display_name': 'Python 3 (ipykernel)',
                'language': 'python', 'name': 'python3'}, 'language_info': {'name': 'python'}},
                nbformat=4, nbformat_minor=5)


def main(root=None):
    root = Path(root or ROOT)
    lab = root / 'labs/service_account_baseline'
    raw, _ = build()
    write_raw(raw, lab / 'raw')
    write_catalog(lab / 'action_catalog.csv')
    print(lab)
    path = root / 'notebooks/05_Detect_service_account_deviations.ipynb'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(notebook(), indent=1) + '\n')


if __name__ == '__main__':
    main()
