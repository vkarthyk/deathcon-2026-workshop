"""Organizer-only withheld replay evaluation, independent of reference SQL.

python -m solutions.scheduled_detection.evaluate --pipeline labs/scheduled_detection/pipeline.sql
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile

from datagen.make_scheduled_detection import build
from workshop.scheduled_detection import KEY, Replay, SimulatedCrash


def iso(value):
    return datetime.fromisoformat(str(value)).astimezone(timezone.utc).isoformat()


def evaluate(pipeline, seed='withheld-v1'):
    schedule, expected = build(seed)
    with tempfile.TemporaryDirectory(prefix='scheduled_detection-grade-') as directory:
        directory = Path(directory)
        schedule_path = directory / 'schedule.json'
        schedule_path.write_text(json.dumps(schedule))
        database = directory / 'state.duckdb'
        replay = Replay(database, schedule_path, pipeline)
        timeline_errors = []
        coverage_errors = []
        attempts = set()
        try:
            while True:
                index = replay.next_batch()
                # Resume a fresh connection after failures on both sides of a commit.
                fault = {3: 'before_commit', 7: 'after_commit'}.get(index)
                if index in attempts:
                    fault = None
                attempts.add(index)
                try:
                    more = replay.step(fault)
                except SimulatedCrash:
                    replay.close()
                    replay = Replay(database, schedule_path, pipeline)
                    more = True
                if not more:
                    break
                report = replay.report()
                keys = {tuple(n[k] for k in KEY) for n in report['notifications']}
                progress = report['next_batch']
                if progress:
                    now = schedule['batches'][progress - 1]['now']
                    due = {key for key, value in expected['alerts'].items() if value['ready_at'] <= now}
                    if keys != due:
                        timeline_errors.append({'batch': progress - 1, 'missing': len(due - keys),
                                                'unexpected': len(keys - due)})
                    health_by_stream, warning_times = {}, {}
                    for batch in schedule['batches'][:progress]:
                        for health in batch.get('health', []):
                            scope = tuple(health[k] for k in ('provider', 'account_uid', 'cluster_name', 'stream'))
                            previous = health_by_stream.get(scope)
                            if previous is None or health['observed_at'] > previous['observed_at']:
                                health_by_stream[scope] = health
                            if health['status'] == 'stalled':
                                warning_times.setdefault(scope + (health['gap_since'],), batch['now'])
                    states = {tuple(h[k] for k in ('provider', 'account_uid', 'cluster_name', 'stream')): h
                              for h in report.get('coverage_state', [])}
                    state_correct = set(states) == set(health_by_stream)
                    for scope, target in health_by_stream.items():
                        actual = states.get(scope, {})
                        state_correct = state_correct and actual.get('status') == target['status']
                        state_correct = state_correct and iso(actual.get('observed_at')) == target['observed_at']
                        gap = actual.get('gap_since')
                        state_correct = state_correct and (iso(gap) if gap else None) == target['gap_since']
                    actual_warnings = {}
                    for warning in report['coverage_warnings']:
                        scope = tuple(warning[k] for k in ('provider', 'account_uid', 'cluster_name', 'stream'))
                        actual_warnings.setdefault(scope + (iso(warning['gap_since']),), []).append(iso(warning['notified_at']))
                    warning_correct = actual_warnings == {k: [v] for k, v in warning_times.items()}
                    if not state_correct or not warning_correct:
                        coverage_errors.append(progress - 1)
            report = replay.report()
            counts = Counter(tuple(n[k] for k in KEY) for n in report['notifications'])
            expected_keys, found = set(expected['alerts']), set(counts)
            evidence_errors, latencies = [], []
            for n in report['notifications']:
                key = tuple(n[k] for k in KEY)
                if key in expected['alerts']:
                    target = expected['alerts'][key]
                    if iso(n['first_read']) != target['first_read'] or n['read_events'] != target['read_events']:
                        evidence_errors.append(key)
                    latencies.append((datetime.fromisoformat(str(n['notified_at'])) -
                                      datetime.fromisoformat(target['ready_at'])).total_seconds())
            warning_counts = Counter(tuple(iso(w[k]) if k == 'gap_since' else w[k] for k in
                                           ('provider', 'account_uid', 'cluster_name', 'stream', 'gap_since'))
                                     for w in report['coverage_warnings'])
            queue = {tuple(r[k] for k in ('provider', 'account_uid', 'cluster_name', 'event_id'))
                     for r in report.get('recovery_queue', [])}
            result = dict(expected_alerts=len(expected_keys), detected=len(expected_keys & found),
                          false_positives=len(found - expected_keys), missed=len(expected_keys - found),
                          duplicate_notifications=sum(c - 1 for c in counts.values()),
                          evidence_errors=len(evidence_errors), timeline_errors=timeline_errors,
                          coverage_errors=coverage_errors,
                          max_latency_seconds=max(latencies, default=None),
                          recovery_queue_correct=queue == expected['recovery_events'],
                          coverage_correct=set(warning_counts) == expected['warnings'] and
                                           all(c == 1 for c in warning_counts.values()))
            recovered = replay.recover()
            recovery_counts = Counter(tuple(n[k] for k in KEY) for n in recovered['notifications'])
            result['backfill_correct'] = (set(recovery_counts) == expected_keys | set(expected['recovery_alerts'])
                                          and all(c == 1 for c in recovery_counts.values()))
            replay.recover()
            result['backfill_idempotent'] = len(replay.report()['notifications']) == len(recovered['notifications'])
            result['passed'] = (not any(result[k] for k in ('false_positives', 'missed', 'duplicate_notifications',
                                                          'evidence_errors', 'timeline_errors', 'coverage_errors')) and
                                all(result[k] for k in ('recovery_queue_correct', 'coverage_correct',
                                                       'backfill_correct', 'backfill_idempotent')))
            return result
        finally:
            replay.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pipeline', type=Path, required=True)
    parser.add_argument('--seed', default='withheld-v1')
    args = parser.parse_args()
    result = evaluate(args.pipeline, args.seed)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
