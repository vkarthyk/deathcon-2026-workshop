"""Integration checks for the participant log/enrichment/investigation workflow."""
import json
import copy
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from workshop.behavioral import ROOT, participant_view_sql
from workshop.engine import Database
from workshop.launch import setup_statements


class NotebookExerciseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='enterprise-workshop-tests-')
        cls.db = Database(Path(cls.directory.name) / 'workshop.duckdb')
        cls.db.script(';\n'.join(setup_statements()) + ';')

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_participant_database_excludes_regression_suites(self):
        tables = self.db.query("SELECT table_schema, table_name FROM information_schema.tables")
        self.assertFalse(any(r['table_schema'] in ('training', 'holdout', 'exercise') for r in tables))
        self.assertFalse(any(r['table_name'] in ('evaluation_labels', 'detection_metrics') for r in tables))
        stats = self.db.query("SELECT count(*) AS n, count(DISTINCT principal) AS users, count(DISTINCT resource_type) AS resources FROM enterprise.k8s_ocsf")[0]
        self.assertGreater(stats['n'], 100000)
        self.assertGreater(stats['users'], 50)
        self.assertGreater(stats['resources'], 10)
        self.assertEqual(self.db.query('SELECT COUNT(*) AS n FROM enterprise.k8s_ocsf'),
                         self.db.query('SELECT COUNT(*) AS n FROM enterprise.events'))
        self.assertEqual(self.db.query('''SELECT COUNT(*) AS n FROM (
            SELECT provider, account_uid, cluster_name, event_id
            FROM enterprise.k8s_ocsf GROUP BY provider, account_uid, cluster_name, event_id
            HAVING COUNT(*) > 1) duplicates'''), [{'n': 0}])

    def test_all_participant_sql_executes(self):
        from datagen.make_sql_notebooks import notebooks, explained_statements
        from datagen.binding_exercise import RAW_HEADINGS, NORMALIZED_HEADINGS
        from solutions.binding_exercise.mappings import MAPPINGS
        from solutions.binding_exercise.queries import detection
        from workshop.normalization import normalize_bindings, check_detection
        original = self.db.query('SELECT * FROM main.enriched_alerts ORDER BY alert_key')
        for name, cells in notebooks().items():
            if name == '02_Normalize_the_logs':
                with contextlib.redirect_stdout(io.StringIO()):
                    normalize_bindings(SimpleNamespace(engine=self.db), MAPPINGS)
            for (heading, *_), sql in explained_statements(name, cells):
                cloud = RAW_HEADINGS.get(heading, NORMALIZED_HEADINGS.get(heading))
                if cloud:
                    self.assertIn('__TODO_', sql)
                    check_detection(self.db, cloud, detection(cloud))
                else:
                    self.db.query(sql)
        self.assertEqual(len(self.db.query('SELECT * FROM enterprise.behavioral_alerts')), 3)
        self.assertEqual(self.db.query('SELECT * FROM main.enriched_alerts ORDER BY alert_key'), original)

    def test_normalization_rejects_incomplete_and_semantically_wrong_mappings(self):
        from solutions.binding_exercise.mappings import MAPPINGS
        from workshop.normalization import normalize_bindings
        session = SimpleNamespace(engine=self.db)
        with contextlib.redirect_stdout(io.StringIO()):
            normalize_bindings(session, MAPPINGS)
            incomplete = copy.deepcopy(MAPPINGS)
            incomplete['eks']['operation'] = None
            with self.assertRaisesRegex(ValueError, 'eks.operation'):
                normalize_bindings(session, incomplete)
            self.assertEqual(self.db.query("SELECT table_name FROM information_schema.tables WHERE table_schema='main' AND table_name='binding_events'"), [])
            for field, value in [('status_id', '1'), ('operation', "'create'"), ('role', "'cluster-admin'"), ('cluster_name', "'wrong-cluster'")]:
                wrong = copy.deepcopy(MAPPINGS)
                wrong['eks'][field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'contract failed'):
                    normalize_bindings(session, wrong)
            normalize_bindings(session, MAPPINGS)

    def test_detection_checks_reject_missing_and_extra_matches(self):
        from solutions.binding_exercise.queries import detection
        from workshop.normalization import check_detection
        query = detection('eks')
        with self.assertRaisesRegex(ValueError, 'Detection incomplete'):
            check_detection(self.db, 'eks', 'SELECT __TODO_OPERATION__')
        with self.assertRaisesRegex(ValueError, 'Detection needs work'):
            check_detection(self.db, 'eks', query.replace("= 'create'", "= 'delete'"))
        with self.assertRaisesRegex(ValueError, 'Detection needs work'):
            check_detection(self.db, 'eks', query.replace("AND json_extract_string(event, '$.requestObject.roleRef.name') = 'cluster-admin'", ''))
        # The raw exercise must include failed and unknown-outcome attempts too.
        restricted = query.rstrip().rstrip(';') + " AND CAST(json_extract_string(event, '$.responseStatus.code') AS INTEGER) BETWEEN 200 AND 299;"
        with self.assertRaisesRegex(ValueError, 'Detection needs work'):
            check_detection(self.db, 'eks', restricted)

    def test_participant_mapping_notebook_workflow(self):
        from solutions.binding_exercise.mappings import MAPPINGS
        from workshop.normalization import check_detection
        notebook = json.loads((ROOT / 'notebooks/02_Normalize_the_logs.ipynb').read_text())
        namespace = {'session': SimpleNamespace(engine=self.db)}
        queries = []
        with contextlib.redirect_stdout(io.StringIO()):
            for cell in notebook['cells']:
                source = ''.join(cell['source'])
                if cell['cell_type'] != 'code' or source.startswith('from pathlib import Path'):
                    continue
                if source.startswith('%%sql'):
                    queries.append((source.split('\n', 1)[0].split()[-1], source.split('\n', 1)[1]))
                    continue
                if source.startswith('from workshop.normalization import'):
                    # Participants may have filled the notebook; make this case explicitly incomplete.
                    namespace['eks_mapping']['operation'] = None
                    with self.assertRaisesRegex(ValueError, 'Mapping incomplete'):
                        exec(source, namespace)
                    for cloud in ('eks', 'gke', 'aks'):
                        namespace[cloud + '_mapping'].update(MAPPINGS[cloud])
                exec(source, namespace)
            self.assertTrue(all(r['contract'] == 'PASS' for r in namespace['normalization_report']))
            self.assertEqual([mode for mode, _ in queries], ['normalized', 'normalized-success'])
            for mode, query in queries:
                for name, value in {'OPERATION': 'create', 'RESOURCE': 'clusterrolebindings',
                                    'ROLE_KIND': 'ClusterRole', 'ROLE_NAME': 'cluster-admin',
                                    'SUCCESS_FILTER': 'status_id = 1'}.items():
                    query = query.replace('__TODO_' + name + '__', value)
                self.assertNotIn('json_extract', query)
                self.assertTrue(check_detection(self.db, mode, query))

    def test_success_only_update_changes_all_clouds(self):
        from solutions.binding_exercise.mappings import MAPPINGS
        from solutions.binding_exercise.queries import detection
        from workshop.normalization import normalize_bindings, check_detection
        with contextlib.redirect_stdout(io.StringIO()):
            normalize_bindings(SimpleNamespace(engine=self.db), MAPPINGS)
            attempts = detection('normalized')
            successful = detection('normalized-success')
            check_detection(self.db, 'normalized', attempts)
            check_detection(self.db, 'normalized-success', successful)
            with self.assertRaisesRegex(ValueError, 'practice records'):
                check_detection(self.db, 'normalized-success', attempts)
            with self.assertRaisesRegex(ValueError, 'practice records'):
                check_detection(self.db, 'normalized', successful)
        practice = lambda query: self.db.query(query.replace('main.binding_events', 'main.binding_events_practice'))
        self.assertEqual(len(practice(attempts)), 9)
        self.assertEqual(len(practice(successful)), 4)
        self.assertEqual({r['provider'] for r in practice(successful)}, {'AWS', 'GCP', 'Azure'})
        self.assertTrue(all('failure' not in r['event_id'] for r in practice(successful)))

    def test_simple_raw_and_normalized_detections_match(self):
        demo = ROOT / 'detection' / 'simple_cluster_admin'
        raw = []
        for cloud in ('eks', 'gke', 'aks'):
            rows = self.db.query((demo / f'{cloud}.sql').read_text())
            self.assertTrue(rows, cloud)
            raw.extend(rows)
        normalized = self.db.query((demo / 'normalized.sql').read_text())
        # Compare source-event identity and asset scope, not just matching row counts.
        as_set = lambda rows: {tuple(sorted(row.items())) for row in rows}
        self.assertEqual(as_set(raw), as_set(normalized))

    def test_alert_results_follow_participant_edits(self):
        query = "SELECT * FROM main.workshop_alerts"
        self.assertTrue(self.db.query(query))
        try:
            self.db.script(participant_view_sql().replace(
                'WHERE NOT EXISTS (', 'WHERE 1 = 0 AND NOT EXISTS ('))
            self.assertEqual(self.db.query(query), [])
        finally:
            self.db.script(participant_view_sql())

    def exercise_investigation(self, use_model=False):
        from workshop.jupyter import NotebookSession
        with tempfile.TemporaryDirectory() as directory:
            session = NotebookSession(Path(directory) / 'rule.sql', statements=[])
            self.addCleanup(session.close)
            session.engine = self.db
            namespace = {'session': session, 'display': lambda value: None}
            # Execute clean exercise sources, not a participant's saved model opt-in settings.
            from datagen.jupyter_exercises import EXERCISES
            notebook = {'cells': [{'cell_type': 'code', 'source': code.splitlines(keepends=True)}
                                  for _, _, code in EXERCISES['04_Investigate_alerts']]}
            with patch.dict('os.environ', {'WORKSHOP_ARTIFACT_DIR': directory}):
                for cell in notebook['cells']:
                    source = ''.join(cell['source'])
                    if cell['cell_type'] != 'code' or source.startswith(('%%sql', 'from pathlib import Path')):
                        continue
                    if use_model:
                        source = source.replace('RUN_LOCAL_MODEL = False', 'RUN_LOCAL_MODEL = True')
                    exec(compile(source, 'investigation-notebook', 'exec'), namespace)
                self.assertTrue((Path(directory) / 'my-notebook-alert.jsonl').exists())
            self.assertEqual(namespace['own_record']['split'], 'enterprise')
            self.assertTrue(namespace['own_record']['assessment']['claims'])
            self.assertNotIn('own_score', namespace)
            self.assertNotIn('EVALUATE_HOLDOUT', namespace)
            return namespace

    def test_investigation_cells_run_offline_without_scoring(self):
        namespace = self.exercise_investigation()
        self.assertFalse(namespace['RUN_LOCAL_MODEL'])

    def test_optional_model_keeps_incomplete_assessment_visible(self):
        with patch('agent.local_model.chat', return_value={'message': {'role': 'assistant', 'content': 'No submission'}}) as transport:
            namespace = self.exercise_investigation(use_model=True)
        self.assertTrue(transport.called)
        self.assertIsNone(namespace['model_record']['assessment'])


if __name__ == '__main__':
    unittest.main()
