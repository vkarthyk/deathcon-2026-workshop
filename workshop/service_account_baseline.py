"""Offline service-account baseline lab: python -m workshop.service_account_baseline --help.

Loads synthetic AWS CloudTrail, GCP Cloud Audit Logs and Azure Activity Log records
into a disposable DuckDB database, runs the participant's detection.sql and reports
mapping quality, deviations and accounts with insufficient history. The SQL file is
trusted participant code. No network, cloud account or model is used.
"""
import argparse
import gzip
import json
from pathlib import Path

from workshop.engine import Database

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / 'labs/service_account_baseline'
FILES = {'AWS': ('raw.aws_cloudtrail', 'aws_cloudtrail.jsonl.gz'),
         'GCP': ('raw.gcp_audit', 'gcp_audit.jsonl.gz'),
         'Azure': ('raw.azure_activity', 'azure_activity.jsonl.gz')}
WINDOW = {'baseline_start': '2026-10-29T00:00:00+00:00', 'detection_start': '2026-11-12T00:00:00+00:00',
          'detection_end': '2026-11-13T00:00:00+00:00', 'min_baseline_days': 7}
SCHEMAS = ('raw', 'ref', 'lab', 'sa')
DEVIATION_KEY = ('cloud_provider', 'account_uid', 'principal', 'dimension', 'observed_value')
OUTPUTS = {
    'sa.events': ('event_id', 'time', 'cloud_provider', 'account_uid', 'principal', 'principal_type',
                  'cloud_api_action', 'action_type', 'service_category', 'source_ip', 'user_agent', 'status_id'),
    'sa.deviations': DEVIATION_KEY + ('first_seen', 'last_seen', 'event_count', 'sample_event_id'),
    'sa.insufficient_baseline': ('cloud_provider', 'account_uid', 'principal', 'baseline_days', 'detection_events'),
}


def literal(value):
    if value is None:
        return 'NULL'
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def rows(database, sql):
    return database.query("SET TimeZone='UTC';\n" + sql)


class Lab:
    def __init__(self, database, raw=LAB / 'raw', catalog=LAB / 'action_catalog.csv'):
        if Path(database).stem in SCHEMAS:
            # DuckDB names the catalog after the file; it would shadow a lab schema.
            raise ValueError(f'Choose a database file name other than {", ".join(SCHEMAS)}.')
        self.db = Database(database)
        self.raw = Path(raw)
        statements = ["SET TimeZone='UTC';", 'CREATE SCHEMA IF NOT EXISTS raw;', 'CREATE SCHEMA IF NOT EXISTS ref;',
                      'CREATE SCHEMA IF NOT EXISTS lab;', 'CREATE SCHEMA IF NOT EXISTS sa;']
        for table, name in FILES.values():
            statements.append(f'CREATE OR REPLACE TABLE {table} AS SELECT json AS record '
                              f'FROM read_ndjson_objects({literal(self.raw / name)});')
        statements.append('CREATE OR REPLACE TABLE ref.action_catalog AS SELECT * FROM '
                          f'read_csv({literal(catalog)}, header=true, all_varchar=true);')
        statements.append('CREATE OR REPLACE TABLE lab.detection_window AS SELECT '
                          f"{literal(WINDOW['baseline_start'])}::TIMESTAMPTZ AS baseline_start, "
                          f"{literal(WINDOW['detection_start'])}::TIMESTAMPTZ AS detection_start, "
                          f"{literal(WINDOW['detection_end'])}::TIMESTAMPTZ AS detection_end, "
                          f"{WINDOW['min_baseline_days']}::INTEGER AS min_baseline_days;")
        self.db.script('\n'.join(statements))

    def window(self):
        return rows(self.db, 'SELECT * FROM lab.detection_window')[0]

    def sample(self, provider, *contains, n=1):
        """Return n raw records for a provider whose JSON text contains every given string."""
        table = FILES[provider][0]
        where = ' AND '.join(f'contains(record::VARCHAR, {literal(text)})' for text in contains) or 'true'
        found = rows(self.db, f'SELECT record::VARCHAR AS r FROM {table} WHERE {where} '
                              f'ORDER BY record::VARCHAR LIMIT {int(n)}')
        records = [json.loads(row['r']) for row in found]
        return records[0] if n == 1 and records else records

    def run(self, sql_path):
        self.db.script("SET TimeZone='UTC';\n" + Path(sql_path).read_text())
        for view, columns in OUTPUTS.items():
            schema, name = view.split('.')
            present = {row['column_name'] for row in rows(self.db, (
                'SELECT column_name FROM information_schema.columns '
                f'WHERE table_schema={literal(schema)} AND table_name={literal(name)}'))}
            missing = [c for c in columns if c not in present]
            if missing:
                raise ValueError(f'{view} is missing required columns: {", ".join(missing)}')
        return self.report()

    def quality(self):
        """Per-provider mapping checks. Problems here make every later result unreliable."""
        return rows(self.db, '''
            SELECT cloud_provider, count(*) AS rows,
                   count(*) FILTER (WHERE principal IS NULL) AS missing_principal,
                   count(*) FILTER (WHERE account_uid IS NULL) AS missing_account,
                   count(*) FILTER (WHERE principal_type = 'service_account') AS service_account_rows,
                   count(*) FILTER (WHERE principal_type NOT IN ('service_account', 'human')
                                    OR principal_type IS NULL) AS invalid_principal_type,
                   count(*) FILTER (WHERE status_id = 1) AS success,
                   count(*) FILTER (WHERE status_id = 2) AS failure,
                   count(*) FILTER (WHERE status_id = 0) AS unknown,
                   count(*) FILTER (WHERE status_id IS NULL) AS missing_status,
                   count(*) FILTER (WHERE action_type IS NULL) AS unmapped_action,
                   count(*) FILTER (WHERE source_ip IS NULL) AS no_source_ip,
                   count(*) FILTER (WHERE user_agent IS NULL) AS no_user_agent
            FROM sa.events GROUP BY cloud_provider ORDER BY cloud_provider''')

    def report(self):
        return {'quality': self.quality(),
                'deviations': rows(self.db, 'SELECT * FROM sa.deviations ORDER BY ' + ', '.join(DEVIATION_KEY)),
                'insufficient_baseline': rows(self.db, 'SELECT * FROM sa.insufficient_baseline '
                                                       'ORDER BY cloud_provider, account_uid, principal')}


def load_raw(folder):
    """Read the raw lab files back as Python records, for tests and inspection."""
    result = {}
    for provider, (_, name) in FILES.items():
        with gzip.open(Path(folder) / name, 'rt') as handle:
            result[provider] = [json.loads(line) for line in handle]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, required=True, help='Disposable DuckDB lab database')
    parser.add_argument('--sql', type=Path, default=LAB / 'detection.sql')
    parser.add_argument('--raw', type=Path, default=LAB / 'raw')
    args = parser.parse_args()
    args.database.parent.mkdir(parents=True, exist_ok=True)
    lab = Lab(args.database, args.raw)
    print(json.dumps(lab.run(args.sql), default=str, indent=2))


if __name__ == '__main__':
    main()
