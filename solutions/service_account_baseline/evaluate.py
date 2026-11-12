"""Organizer-only evaluation on a withheld data set, independent of the reference SQL.

python -m solutions.service_account_baseline.evaluate --sql labs/service_account_baseline/detection.sql
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile

from datagen.make_service_account_baseline import build, write_catalog, write_raw
from workshop.service_account_baseline import DEVIATION_KEY, Lab, rows


def iso(value):
    return datetime.fromisoformat(str(value)).astimezone(timezone.utc).isoformat()


def evaluate(sql, seed='withheld-v1'):
    raw, expected = build(seed)
    with tempfile.TemporaryDirectory(prefix='service_account_baseline-grade-') as directory:
        directory = Path(directory)
        write_raw(raw, directory / 'raw')
        write_catalog(directory / 'action_catalog.csv')
        lab = Lab(directory / 'state.duckdb', directory / 'raw', directory / 'action_catalog.csv')
        try:
            report = lab.run(sql)
        except Exception as exc:  # A submission that does not run fails every check.
            return {'passed': False, 'error': str(exc)}

        mapping_errors = []
        quality = {row['cloud_provider']: row for row in report['quality']}
        for provider, target in expected['events'].items():
            actual = quality.get(provider, {})
            for field, value in (('rows', target['rows']), ('service_account_rows', target['service_account']),
                                 ('success', target['success']), ('missing_principal', 0),
                                 ('missing_account', 0), ('missing_status', 0), ('invalid_principal_type', 0)):
                if actual.get(field) != value:
                    mapping_errors.append({'provider': provider, 'field': field,
                                           'expected': value, 'actual': actual.get(field)})
        identities = {(r['cloud_provider'], r['account_uid'], r['principal']) for r in rows(lab.db, (
            "SELECT DISTINCT cloud_provider, account_uid, principal FROM sa.events "
            "WHERE principal_type = 'service_account'"))}

        found = {}
        for row in report['deviations']:
            found.setdefault(tuple(row[k] for k in DEVIATION_KEY), []).append(row)
        expected_keys, found_keys = set(expected['alerts']), set(found)
        evidence_errors = []
        for key in expected_keys & found_keys:
            row, target = found[key][0], expected['alerts'][key]
            if iso(row['first_seen']) != target['first_seen'] or row['event_count'] != target['event_count']:
                evidence_errors.append({'key': key, 'expected': target,
                                        'actual': {'first_seen': row['first_seen'], 'event_count': row['event_count']}})
        insufficient = {(r['cloud_provider'], r['account_uid'], r['principal']): r
                        for r in report['insufficient_baseline']}
        insufficient_correct = set(insufficient) == set(expected['insufficient']) and all(
            insufficient[k]['baseline_days'] == v['baseline_days'] and
            insufficient[k]['detection_events'] == v['detection_events']
            for k, v in expected['insufficient'].items() if k in insufficient)

        result = dict(
            expected_alerts=len(expected_keys), detected=len(expected_keys & found_keys),
            missed=sorted(expected_keys - found_keys, key=str), false_positives=sorted(found_keys - expected_keys, key=str),
            duplicate_rows=sum(len(v) - 1 for v in found.values()),
            evidence_errors=evidence_errors, mapping_errors=mapping_errors,
            identities_correct=identities == expected['identities'],
            insufficient_correct=insufficient_correct)
        result['passed'] = (not any(result[k] for k in ('missed', 'false_positives', 'duplicate_rows',
                                                       'evidence_errors', 'mapping_errors'))
                            and result['identities_correct'] and result['insufficient_correct'])
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sql', type=Path, required=True)
    parser.add_argument('--seed', default='withheld-v1')
    args = parser.parse_args()
    result = evaluate(args.sql, args.seed)
    print(json.dumps(result, indent=2, default=str))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
