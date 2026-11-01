"""Validate comparison controls and honest reporting without requiring a local LLM."""
import contextlib
import io
import unittest
from unittest.mock import Mock, patch

from workshop.agent_comparison import compare_evidence, comparison_rows


class AgentComparisonTests(unittest.TestCase):
    def setUp(self):
        self.session = Mock()
        self.targets = [dict(alert_key=f'grant-{p}', provider=p, account_uid='account',
                             cluster_name='cluster', subject='recipient') for p in ('AWS', 'Azure', 'GCP')]
        self.session.execute.side_effect = lambda sql: (self.targets if 'main.workshop_alerts' in sql
                                                        else [{'event_id': 'grant-AWS'}, {'event_id': 'read'}])

    def record(self, *args, **kwargs):
        return dict(assessment={'claims': [{'event_id': 'grant-AWS'}, {'event_id': 'invented'}],
                                'disposition': 'suspicious'},
                    representation=kwargs['representation'], retrieved_event_ids=['grant-AWS', 'read'],
                    trace=[dict(tool='query_sql')], tool_errors=0,
                    usage={'input_tokens': 20, 'output_tokens': 5}, investigation_seconds=1)

    def test_pair_uses_same_task_model_and_tools_and_saves_each_result(self):
        with patch('workshop.agent_comparison.run', side_effect=self.record) as run, \
             patch('workshop.agent_comparison.save_records') as save, \
             contextlib.redirect_stdout(io.StringIO()):
            records = compare_evidence(self.session, 'grant-AWS', 'local-model')
        self.assertEqual(len(records), 2)
        self.assertEqual(save.call_count, 2)
        first, second = run.call_args_list
        self.assertEqual(first.args, second.args)
        first_options, second_options = dict(first.kwargs), dict(second.kwargs)
        self.assertEqual(first_options.pop('representation'), 'raw')
        self.assertEqual(second_options.pop('representation'), 'ocsf')
        self.assertEqual(first_options, second_options)
        self.assertEqual(first_options['toolset'], 'sql')
        self.assertNotIn('comparison_expected_ids', first_options)
        row = comparison_rows(records)[0]
        self.assertEqual(row['status'], 'submitted')
        self.assertEqual(row['reference events retrieved'], '2/2')
        self.assertEqual(row['reference events cited'], '1/2')
        self.assertEqual(row['citations not retrieved'], 1)

    def test_all_clouds_reversed_order_and_transport_failure(self):
        def run(*args, **kwargs):
            if kwargs['representation'] == 'raw':
                raise RuntimeError('Start Ollama')
            return dict(representation='ocsf', assessment=None, trace=[])
        with patch('workshop.agent_comparison.run', side_effect=run) as model, \
             patch('workshop.agent_comparison.save_records'), contextlib.redirect_stdout(io.StringIO()):
            records = compare_evidence(self.session, None, 'local-model', all_clouds=True, normalized_first=True)
        self.assertEqual(len(records), 6)
        self.assertEqual([c.kwargs['representation'] for c in model.call_args_list], ['ocsf', 'raw'] * 3)
        self.assertEqual([r['status'] for r in comparison_rows(records)], ['incomplete', 'error'] * 3)
        self.assertIsNone(comparison_rows(records)[1]['input tokens'])

    def test_real_snapshots_expose_only_the_selected_event_representation(self):
        import tempfile
        from pathlib import Path
        from workshop.engine import Database
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / 'comparison.duckdb')
            tables = ('events', 'raw_eks', 'raw_gke', 'raw_aks', 'identities',
                      'ip_enrichment', 'user_enrichment', 'k8s_cluster_enrichment', 'approvals')
            db.script('CREATE SCHEMA enterprise; ' + '; '.join(
                f"CREATE TABLE enterprise.{name} AS SELECT 'grant-AWS' AS event_id" for name in tables) + ';')
            self.session.engine = db
            observed = []

            def assess(tools, *args):
                names = {row['table_name'] for row in tools.db.query(
                    'SELECT table_name FROM information_schema.tables')}
                observed.append(names)
                table = 'events' if 'events' in names else 'raw_eks'
                result = tools.call('query_sql', {'sql': f'SELECT * FROM {table}'})
                self.assertEqual(result['rows'][0]['event_id'], 'grant-AWS')
                return None, {'input_tokens': 1, 'output_tokens': 1}, []

            with patch('agent.local_model.assess', side_effect=assess), \
                 patch('workshop.agent_comparison.save_records'), contextlib.redirect_stdout(io.StringIO()):
                records = compare_evidence(self.session, 'grant-AWS', 'local-model')
            self.assertIn('raw_eks', observed[0])
            self.assertNotIn('events', observed[0])
            self.assertIn('events', observed[1])
            self.assertNotIn('raw_eks', observed[1])
            self.assertEqual(records[0]['system_prompt_sha256'], records[1]['system_prompt_sha256'])
            self.assertEqual(records[0]['tool_schema_sha256'], records[1]['tool_schema_sha256'])
            self.assertEqual(records[0]['retrieved_event_ids'], ['grant-AWS'])

    def test_no_alert_explains_prerequisite(self):
        with self.assertRaisesRegex(ValueError, 'select an alert'):
            compare_evidence(self.session, 'missing', 'model')
