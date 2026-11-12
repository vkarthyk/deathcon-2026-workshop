"""Offline scheduled-detection replay: python -m workshop.scheduled_detection --help.

The SQL file is trusted participant code. Run it only against a disposable lab DB.
No network, model, real cluster or production scheduler is used.
"""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path

from workshop.engine import Database

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / 'labs/scheduled_detection'
KEY = ('provider', 'account_uid', 'cluster_name', 'alert_key', 'subject')

DDL = """
CREATE SCHEMA IF NOT EXISTS replay;
CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id VARCHAR PRIMARY KEY, event_id VARCHAR, provider VARCHAR,
    account_uid VARCHAR, cluster_name VARCHAR, time TIMESTAMPTZ,
    ingested_at TIMESTAMPTZ, principal VARCHAR, operation VARCHAR,
    resource_type VARCHAR, status_id INTEGER, namespace VARCHAR,
    role_kind VARCHAR, role VARCHAR, subjects JSON);
CREATE TABLE IF NOT EXISTS replay.identities (
    cloud_provider VARCHAR, account_uid VARCHAR, principal_name VARCHAR, person_id VARCHAR);
CREATE TABLE IF NOT EXISTS replay.approvals (
    cloud_provider VARCHAR, account_uid VARCHAR, cluster_name VARCHAR,
    grant_actor VARCHAR, subject VARCHAR, role VARCHAR, start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ, ticket VARCHAR);
CREATE TABLE IF NOT EXISTS collector_health (
    provider VARCHAR, account_uid VARCHAR, cluster_name VARCHAR, stream VARCHAR,
    observed_at TIMESTAMPTZ, status VARCHAR, gap_since TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS clock (now TIMESTAMPTZ, recover BOOLEAN);
CREATE TABLE IF NOT EXISTS progress (schedule_hash VARCHAR, next_batch INTEGER);
CREATE TABLE IF NOT EXISTS notifications (
    provider VARCHAR, account_uid VARCHAR, cluster_name VARCHAR,
    alert_key VARCHAR, subject VARCHAR, first_read TIMESTAMPTZ,
    read_events BIGINT, notified_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS coverage_warnings (
    provider VARCHAR, account_uid VARCHAR, cluster_name VARCHAR,
    stream VARCHAR, gap_since TIMESTAMPTZ, notified_at TIMESTAMPTZ);
"""


def rows(database, sql):
    return database.query("SET TimeZone='UTC';\n" + sql)


def literal(value):
    """Quote supplied fixture values as SQL literals, never shell commands."""
    if value is None:
        return 'NULL'
    if isinstance(value, int):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def insert(table, values):
    return f'INSERT INTO {table} VALUES (' + ','.join(literal(v) for v in values) + ');'


class SimulatedCrash(RuntimeError):
    pass


class Replay:
    """A single scheduler worker with an atomic local notification outbox.

    Committing an outbox row is the notification in this simulation. External
    delivery would additionally require an idempotent consumer; this is not a
    claim of exactly-once delivery to a real notification service.
    """
    def __init__(self, database, schedule, pipeline=LAB / 'pipeline.sql'):
        self.schedule = json.loads(Path(schedule).read_text())
        self.pipeline = Path(pipeline)
        self.db = Database(database)
        self.db.script(DDL)
        digest = hashlib.sha256(json.dumps(self.schedule, sort_keys=True).encode()).hexdigest()
        progress = rows(self.db, 'SELECT * FROM progress')
        if not progress:
            statements = ['BEGIN;']
            for a in self.schedule.get('approvals', []):
                statements.append(insert('replay.approvals', [a[k] for k in
                    ('cloud_provider', 'account_uid', 'cluster_name', 'grant_actor',
                     'subject', 'role', 'start_time', 'end_time', 'ticket')]))
            statements += [insert('progress', [digest, 0]), 'COMMIT;']
            self.db.script('\n'.join(statements))
        elif progress[0]['schedule_hash'] != digest:
            raise ValueError('This database belongs to a different schedule; choose a fresh database.')

    def close(self):
        # Database opens/closes its native connection for each complete script.
        # Kept as an explicit lifecycle hook for notebooks and replay callers.
        pass

    def pipeline_sql(self):
        detection = (ROOT / 'detection/privilege_to_secrets.sql').read_text().replace('enterprise.', 'replay.')
        sql = self.pipeline.read_text()
        if sql.count('{{DETECTION_SQL}}') != 1:
            raise ValueError('Keep exactly one {{DETECTION_SQL}} marker in the pipeline.')
        # Own transaction boundaries in the harness, not in participant SQL.
        return sql.replace('{{DETECTION_SQL}}', detection)

    def next_batch(self):
        return rows(self.db, 'SELECT next_batch FROM progress')[0]['next_batch']

    def step(self, fault=None):
        if fault not in (None, 'before_commit', 'after_commit'):
            raise ValueError('Unknown fault')
        index = self.next_batch()
        if index >= len(self.schedule['batches']):
            return False
        batch = self.schedule['batches'][index]
        now = datetime.fromisoformat(batch['now'])
        statements = ['BEGIN;', 'DELETE FROM clock;', insert('clock', [now, False])]
        for event in batch['deliveries']:
            if datetime.fromisoformat(event['ingested_at']) > now:
                raise ValueError('A batch cannot expose future deliveries')
            fields = ('delivery_id', 'event_id', 'provider', 'account_uid', 'cluster_name',
                      'time', 'ingested_at', 'principal', 'operation', 'resource_type',
                      'status_id', 'namespace', 'role_kind', 'role')
            statement = insert('deliveries', [event[k] for k in fields] + [json.dumps(event['subjects'])])
            statements.append(statement[:-1] + ' ON CONFLICT DO NOTHING;')
        for health in batch.get('health', []):
            if datetime.fromisoformat(health['observed_at']) > now:
                raise ValueError('A batch cannot expose future collector health')
            statements.append(insert('collector_health', [health[k] for k in
                ('provider', 'account_uid', 'cluster_name', 'stream', 'observed_at', 'status', 'gap_since')]))
        statements += [self.pipeline_sql(), f'UPDATE progress SET next_batch={index + 1};']
        if fault == 'before_commit':
            # A failing statement aborts the native connection before COMMIT.
            # Connection closure rolls back every write, including DDL and outbox.
            statements.append("SELECT error('scheduled_detection_simulated_before_commit');")
        statements.append('COMMIT;')
        try:
            self.db.script('\n'.join(statements))
        except Exception as exc:
            if fault == 'before_commit' and 'scheduled_detection_simulated_before_commit' in str(exc):
                raise SimulatedCrash('Crash before commit: this batch must be replayed.') from exc
            raise
        if fault == 'after_commit':
            raise SimulatedCrash('Crash after commit: resume at the next batch.')
        return True

    def run(self):
        while self.step():
            pass
        return self.report()

    def recover(self):
        """Explicit operator backfill, reconsidering all retained late evidence."""
        if rows(self.db, 'SELECT count(*) AS n FROM clock')[0]['n'] != 1:
            raise ValueError('Run at least one batch before requesting recovery.')
        self.db.script('BEGIN; UPDATE clock SET recover=true;\n' + self.pipeline_sql() +
                       '\nUPDATE clock SET recover=false; COMMIT;')
        return self.report()

    def report(self):
        report = {'next_batch': self.next_batch(),
                  'notifications': rows(self.db, 'SELECT * FROM notifications ORDER BY notified_at, provider, alert_key, subject'),
                  'coverage_warnings': rows(self.db, 'SELECT * FROM coverage_warnings ORDER BY notified_at, provider')}
        for view in ('recovery_queue', 'coverage_state', 'workshop_alerts'):
            if rows(self.db, f"SELECT count(*) AS n FROM information_schema.tables WHERE table_schema='main' AND table_name={literal(view)}")[0]['n']:
                report[view] = rows(self.db, f'SELECT * FROM main.{view}')
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schedule', type=Path, default=LAB / 'practice.json')
    parser.add_argument('--pipeline', type=Path, default=LAB / 'pipeline.sql')
    parser.add_argument('--database', type=Path, required=True, help='Disposable durable DuckDB lab database')
    parser.add_argument('--recover', action='store_true', help='After replay, explicitly backfill retained late evidence')
    parser.add_argument('--crash', choices=('before_commit', 'after_commit'))
    parser.add_argument('--crash-batch', type=int, default=3, help='Zero-based batch index, used with --crash')
    args = parser.parse_args()
    args.database.parent.mkdir(parents=True, exist_ok=True)
    replay = Replay(args.database, args.schedule, args.pipeline)
    try:
        while True:
            index = replay.next_batch()
            if not replay.step(args.crash if index == args.crash_batch else None):
                break
        print(json.dumps(replay.recover() if args.recover else replay.report(), default=str, indent=2))
    finally:
        replay.close()


if __name__ == '__main__':
    main()
