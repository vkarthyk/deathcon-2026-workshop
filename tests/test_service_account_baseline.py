"""Service-account baseline lab: reference grading, starter flaws, data and notebook checks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from datagen.make_service_account_baseline import build, catalog_rows
from solutions.service_account_baseline.evaluate import evaluate
from workshop.service_account_baseline import LAB, ROOT, Lab, load_raw

REFERENCE = ROOT / 'solutions/service_account_baseline/detection.sql'
NOTEBOOK = ROOT / 'notebooks/05_Detect_service_account_deviations.ipynb'
RULE_MARKER = '-- 2. Observations'


class ServiceAccountBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='test-service_account_baseline-')
        self.folder = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def variant(self, *replacements):
        """The reference with one deliberate regression, to prove the grader notices it."""
        sql = REFERENCE.read_text()
        for old, new in replacements:
            self.assertIn(old, sql)
            sql = sql.replace(old, new)
        path = self.folder / f'variant-{len(list(self.folder.iterdir()))}.sql'
        path.write_text(sql)
        return path

    def test_reference_passes_independent_withheld_data_sets(self):
        for seed in ('practice', 'withheld-v1', 'another-private-set'):
            with self.subTest(seed=seed):
                report = evaluate(REFERENCE, seed)
                self.assertTrue(report['passed'], report)
                self.assertEqual(report['expected_alerts'], 17)

    def test_starter_runs_but_fails(self):
        report = evaluate(LAB / 'detection.sql', 'practice')
        self.assertNotIn('error', report)
        self.assertFalse(report['passed'])
        self.assertTrue(report['mapping_errors'])

    def test_correct_mappings_with_starter_rule_still_fail(self):
        reference, starter = REFERENCE.read_text(), (LAB / 'detection.sql').read_text()
        rule = starter[starter.index('-- ---------------------------------------------------------------------------\n-- 2-5.'):]
        path = self.folder / 'mapped-starter.sql'
        path.write_text(reference[:reference.index(RULE_MARKER)] + rule)
        report = evaluate(path, 'practice')
        self.assertFalse(report['mapping_errors'])
        self.assertFalse(report['passed'])
        self.assertTrue(report['missed'])
        self.assertTrue(report['false_positives'])
        self.assertFalse(report['insufficient_correct'])

    def test_grader_catches_each_rule_regression(self):
        regressions = {
            'counts failed calls': ("WHERE principal_type = 'service_account' AND status_id = 1",
                                    "WHERE principal_type = 'service_account'"),
            'compares exact hosts': ("regexp_replace(source_ip, '\\.\\d+$', '.0/24')", 'source_ip'),
            'compares full user agents': ("lower(trim(split_part(user_agent, '/', 1)))", 'user_agent'),
            'drops unmapped actions': ('coalesce(action_type, cloud_api_action)', 'action_type'),
            'ignores the account': ('AND b.account_uid = d.account_uid', ''),
            'skips the history requirement': ('WHERE c.baseline_days >= w.min_baseline_days', 'WHERE true'),
        }
        for name, replacement in regressions.items():
            with self.subTest(name):
                self.assertFalse(evaluate(self.variant(replacement), 'practice')['passed'])

    def test_grader_catches_each_mapping_regression(self):
        regressions = {
            'AWS session ARN as identity': ("CASE WHEN is_workload THEN r->>'$.userIdentity.sessionContext.sessionIssuer.arn'",
                                            "CASE WHEN is_workload THEN r->>'$.userIdentity.arn'"),
            'Azure Start as success': ("WHEN 'Success' THEN 1 WHEN 'Failure' THEN 2 ELSE 0", "WHEN 'Failure' THEN 2 ELSE 1"),
            'Azure object ID as identity': ("THEN r->>'$.identity.claims.appid'", "THEN r->>'$.caller'"),
            'GCP non-IP sources kept': ("CASE WHEN regexp_matches(r->>'$.protoPayload.requestMetadata.callerIp', '^\\d{1,3}(\\.\\d{1,3}){3}$')\n         THEN r->>'$.protoPayload.requestMetadata.callerIp' END",
                                        "r->>'$.protoPayload.requestMetadata.callerIp'"),
        }
        for name, replacement in regressions.items():
            with self.subTest(name):
                self.assertFalse(evaluate(self.variant(replacement), 'practice')['passed'])

    def test_practice_files_are_reproducible_and_unlabelled(self):
        self.assertEqual(load_raw(LAB / 'raw'), build()[0])
        lines = (LAB / 'action_catalog.csv').read_text().splitlines()
        self.assertEqual(len(lines) - 1, len(catalog_rows()))
        for records in build()[0].values():
            for record in records:
                text = json.dumps(record).lower()
                for label in ('expected', 'scenario', 'malicious', 'attacker', 'compromised', 'flag'):
                    self.assertNotIn(label, text)

    def test_database_name_cannot_shadow_a_lab_schema(self):
        with self.assertRaisesRegex(ValueError, 'database file name'):
            Lab(self.folder / 'sa.duckdb')

    def test_notebook_executes_with_only_student_runtime(self):
        notebook = json.loads(NOTEBOOK.read_text())
        self.assertEqual(notebook['nbformat'], 4)
        namespace = {}
        try:
            for cell in notebook['cells']:
                if cell['cell_type'] == 'code':
                    self.assertFalse(cell['outputs'])
                    self.assertIsNone(cell['execution_count'])
                    self.assertNotIn('solutions.', ''.join(cell['source']))
                    exec(compile(''.join(cell['source']), 'service_account_baseline-notebook', 'exec'), namespace)
        finally:
            if 'attempt' in namespace:
                namespace['attempt'].cleanup()

    def test_student_release_runs_in_isolation_without_organizer_assets(self):
        from release.build import student_tree
        student = self.folder / 'student'
        student_tree(student)
        self.assertFalse((student / 'solutions').exists())
        self.assertFalse((student / 'datagen').exists())
        self.assertTrue((student / 'labs/service_account_baseline/detection.sql').exists())
        self.assertEqual(load_raw(student / 'labs/service_account_baseline/raw'), build()[0])
        script = '''
import json
from pathlib import Path
import workshop.service_account_baseline
assert Path(workshop.service_account_baseline.__file__).resolve().parent.parent == Path.cwd()
namespace = {}
notebook = json.loads(Path('notebooks/05_Detect_service_account_deviations.ipynb').read_text())
for cell in notebook['cells']:
    if cell['cell_type'] == 'code':
        assert cell['outputs'] == [] and cell['execution_count'] is None
        exec(compile(''.join(cell['source']), 'student-service_account_baseline', 'exec'), namespace)
print('PASS isolated student service_account_baseline lab')
'''
        result = subprocess.run([sys.executable, '-c', script], cwd=student,
                                env=dict(os.environ, PYTHONPATH=''), text=True,
                                capture_output=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PASS isolated', result.stdout)


if __name__ == '__main__':
    unittest.main()
