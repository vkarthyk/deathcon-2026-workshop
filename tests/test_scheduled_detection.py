"""Behavioral replay, atomic restart, private grading and notebook checks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


from datagen.make_scheduled_detection import build
from solutions.scheduled_detection.evaluate import evaluate
from workshop.scheduled_detection import LAB, ROOT, Replay, SimulatedCrash, rows

REFERENCE = ROOT / 'solutions/scheduled_detection/pipeline.sql'


class ScheduledDetectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='test-scheduled_detection-')
        self.folder = Path(self.temporary.name)
        self.schedule = self.folder / 'schedule.json'
        self.schedule.write_text(json.dumps(build('test-replay')[0]))
        self.database = self.folder / 'state.duckdb'

    def tearDown(self):
        self.temporary.cleanup()

    def test_reference_passes_independent_withheld_schedules(self):
        for seed in ('practice', 'withheld-v1', 'another-private-schedule'):
            with self.subTest(seed=seed):
                report = evaluate(REFERENCE, seed)
                self.assertTrue(report['passed'], report)
                self.assertEqual(report['expected_alerts'], 27)
                self.assertEqual(report['max_latency_seconds'], 0)

    def test_starter_runs_but_fails_detection_and_notification_requirements(self):
        report = evaluate(LAB / 'pipeline.sql', 'practice')
        self.assertFalse(report['passed'])
        self.assertGreater(report['missed'], 0)
        self.assertGreater(report['duplicate_notifications'], 0)
        self.assertFalse(report['coverage_correct'])
        self.assertFalse(report['recovery_queue_correct'])

    def test_failures_before_and_after_commit_preserve_atomic_progress(self):
        replay = Replay(self.database, self.schedule, REFERENCE)
        try:
            with self.assertRaises(SimulatedCrash):
                replay.step('before_commit')
            self.assertEqual(replay.report()['next_batch'], 0)
            self.assertEqual(rows(replay.db, 'SELECT count(*) AS n FROM deliveries')[0]['n'], 0)
            self.assertEqual(rows(replay.db, 'SELECT count(*) AS n FROM collector_health')[0]['n'], 0)
            with self.assertRaises(SimulatedCrash):
                replay.step('after_commit')
            self.assertEqual(replay.report()['next_batch'], 1)
        finally:
            replay.close()
        replay = Replay(self.database, self.schedule, REFERENCE)
        try:
            report = replay.run()
            self.assertEqual(len(report['notifications']), 27)
            self.assertEqual(len(report['coverage_warnings']), 3)
            self.assertEqual(len(report['recovery_queue']), 3)
            self.assertTrue(all(row['status'] == 'healthy' for row in report['coverage_state']))
            self.assertEqual(len(replay.recover()['notifications']), 30)
            self.assertEqual(len(replay.recover()['notifications']), 30)
        finally:
            replay.close()

    def test_sql_failure_rolls_back_ingestion_outbox_and_progress(self):
        broken = self.folder / 'broken.sql'
        broken.write_text(REFERENCE.read_text() + '\nSELECT * FROM deliberately_missing_table;')
        replay = Replay(self.database, self.schedule, broken)
        try:
            with self.assertRaises(Exception):
                replay.step()
            self.assertEqual(replay.report()['next_batch'], 0)
            self.assertEqual(rows(replay.db, 'SELECT count(*) AS n FROM notifications')[0]['n'], 0)
            self.assertEqual(rows(replay.db, 'SELECT count(*) AS n FROM collector_health')[0]['n'], 0)
            replay.pipeline = REFERENCE
            self.assertEqual(len(replay.run()['notifications']), 27)
        finally:
            replay.close()

    def test_database_cannot_resume_a_different_schedule(self):
        replay = Replay(self.database, self.schedule, REFERENCE)
        replay.step()
        replay.close()
        self.schedule.write_text(json.dumps(build('different')[0]))
        with self.assertRaisesRegex(ValueError, 'different schedule'):
            Replay(self.database, self.schedule, REFERENCE)

    def test_lateness_boundary_and_retry_use_earliest_source_arrival(self):
        schedule, _ = build('boundary-test')
        # Move one otherwise valid source grant to exactly 30 minutes late.
        # Its later retry must not replace the earliest canonical arrival.
        first = next(row for batch in schedule['batches'] for row in batch['deliveries']
                     if row['operation'] == 'create' and row['status_id'] == 1 and
                     row['role'] == 'cluster-admin' and row['role_kind'] == 'ClusterRole' and
                     row['subjects'][1]['kind'] == 'User')
        from datetime import datetime, timedelta
        event_time = datetime.fromisoformat(first['time'])
        first['ingested_at'] = (event_time + timedelta(minutes=30)).isoformat()
        # Construct a minimal independent schedule around this grant and its recipient.
        first['delivery_id'] = 'first'
        read = first | dict(delivery_id='read', event_id='read', subjects=[],
                            principal=first['subjects'][1]['name'], operation='list',
                            resource_type='secrets', role=None, role_kind=None,
                            time=(event_time + timedelta(minutes=7)).isoformat(),
                            ingested_at=(event_time + timedelta(minutes=8)).isoformat())
        retry = first | dict(delivery_id='retry', ingested_at=(event_time + timedelta(minutes=35)).isoformat())
        self.schedule.write_text(json.dumps({'batches': [
            {'now': read['ingested_at'], 'deliveries': [read]},
            {'now': first['ingested_at'], 'deliveries': [first]},
            {'now': retry['ingested_at'], 'deliveries': [retry]}]}))
        replay = Replay(self.database, self.schedule, REFERENCE)
        try:
            report = replay.run()
            self.assertEqual(len(report['notifications']), 1)
            self.assertEqual(report['recovery_queue'], [])
            self.assertEqual(report['notifications'][0]['read_events'], 1)
        finally:
            replay.close()

    def test_practice_is_reproducible_and_contains_no_evaluation_labels(self):
        schedule = json.loads((LAB / 'practice.json').read_text())
        self.assertEqual(schedule, build()[0])
        for batch in schedule['batches']:
            for event in batch['deliveries']:
                self.assertFalse({'expected', 'scenario', 'case', 'malicious', 'flag'} & event.keys())

    def test_notebook_validates_and_executes_with_only_student_runtime(self):
        notebook = json.loads((ROOT / 'notebooks/05_Run_the_detection_in_batches.ipynb').read_text())
        self.assertEqual(notebook['nbformat'], 4)
        namespace = {}
        try:
            for cell in notebook['cells']:
                if cell['cell_type'] == 'code':
                    self.assertFalse(cell['outputs'])
                    self.assertIsNone(cell['execution_count'])
                    self.assertNotIn('solutions.', ''.join(cell['source']))
                    exec(compile(''.join(cell['source']), 'scheduled_detection-notebook', 'exec'), namespace)
        finally:
            if 'replay' in namespace:
                namespace['replay'].close()
            if 'attempt' in namespace:
                namespace['attempt'].cleanup()

    def test_student_release_runs_in_isolation_without_organizer_assets(self):
        from release.build import student_tree
        student = self.folder / 'student'
        student_tree(student)
        self.assertFalse((student / 'solutions').exists())
        self.assertFalse((student / 'datagen').exists())
        self.assertTrue((student / 'labs/scheduled_detection/pipeline.sql').exists())
        self.assertEqual(json.loads((student / 'labs/scheduled_detection/practice.json').read_text()), build()[0])
        script = '''
import json
from pathlib import Path
import workshop.scheduled_detection
assert Path(workshop.scheduled_detection.__file__).resolve().parent.parent == Path.cwd()
namespace = {}
notebook = json.loads(Path('notebooks/05_Run_the_detection_in_batches.ipynb').read_text())
for cell in notebook['cells']:
    if cell['cell_type'] == 'code':
        assert cell['outputs'] == [] and cell['execution_count'] is None
        exec(compile(''.join(cell['source']), 'student-scheduled_detection', 'exec'), namespace)
print('PASS isolated student scheduled_detection lab')
'''
        result = subprocess.run([sys.executable, '-c', script], cwd=student,
                                env=dict(os.environ, PYTHONPATH=''), text=True,
                                capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PASS isolated', result.stdout)


if __name__ == '__main__':
    unittest.main()
