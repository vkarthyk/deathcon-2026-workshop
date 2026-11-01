"""Test the local model protocol with fake model replies and real evidence tools."""
from pathlib import Path
import tempfile
import unittest

from agent.local_model import assess, chat
from agent.triage import Investigation
from workshop.engine import Database


class LocalModelTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        database = Database(Path(self.directory.name) / 'evidence.duckdb')
        database.script("CREATE TABLE events AS SELECT 'event-1' AS event_id;")
        self.tools = Investigation(database, toolset='sql')

    def test_real_query_then_structured_submission(self):
        assessment = dict(disposition='inconclusive', summary='Need more evidence', attribution='unknown',
                          claims=[], benign_alternatives=[], uncertainties=['Only one event retrieved'], follow_up_queries=[])
        requests = []
        def request(url, payload):
            requests.append(payload)
            if len(requests) == 1:
                function = dict(name='query_sql', arguments={'sql': 'SELECT * FROM events'})
            else:
                self.assertIn('event-1', payload['messages'][-1]['content'])
                self.assertEqual(payload['messages'][-1]['tool_name'], 'query_sql')
                function = dict(name='submit_assessment', arguments=assessment)
            return dict(message={'role': 'assistant', 'content': '', 'tool_calls': [{'function': function}]},
                        prompt_eval_count=10, eval_count=5, model='qwen3:8b')
        result, usage, turns = assess(self.tools, 'event-1', 'qwen3:8b', 3, 'system', request_fn=request)
        self.assertEqual(result, assessment)
        self.assertEqual(usage, {'input_tokens': 20, 'output_tokens': 10})
        self.assertEqual(len(turns), 2)
        self.assertEqual(self.tools.retrieved_ids, {'event-1'})
        self.assertEqual(requests[0]['tools'][0]['function']['parameters']['type'], 'object')

    def test_bad_arguments_and_invalid_assessment_stay_incomplete(self):
        def request(url, payload):
            return {'message': {'role': 'assistant', 'tool_calls': [
                {'function': {'name': 'query_sql', 'arguments': '{bad json'}},
                {'function': {'name': 'submit_assessment', 'arguments': {}}}]}}
        assessment, _, turns = assess(self.tools, 'event-1', 'qwen3:8b', 2, 'system', request_fn=request)
        self.assertIsNone(assessment)
        self.assertEqual(len(turns), 2)
        self.assertEqual(self.tools.errors, 4)

    def test_read_only_tools_still_reject_writes(self):
        def request(url, payload):
            return {'message': {'role': 'assistant', 'tool_calls': [
                {'function': {'name': 'query_sql', 'arguments': {'sql': 'DROP TABLE events'}}}]}}
        result, _, _ = assess(self.tools, 'event-1', 'qwen3:8b', 1, 'system', request_fn=request)
        self.assertIsNone(result)
        self.assertEqual(self.tools.errors, 1)
        self.assertEqual(self.tools.db.query('SELECT * FROM events'), [{'event_id': 'event-1'}])

    def test_no_tools_stops_at_turn_limit(self):
        result, _, turns = assess(self.tools, 'event-1', 'qwen3:8b', 2, 'system',
                                  request_fn=lambda *args: {'message': {'role': 'assistant', 'content': 'thinking'}})
        self.assertIsNone(result)
        self.assertEqual(len(turns), 2)

    def test_transport_failure_does_not_fallback(self):
        def request(*args):
            raise RuntimeError('Ollama unavailable')
        with self.assertRaisesRegex(RuntimeError, 'unavailable'):
            assess(self.tools, 'event-1', 'qwen3:8b', 2, 'system', request_fn=request)

    def test_only_local_model_servers_allowed(self):
        for url in ['https://example.com', 'http://example.com', 'http://localhost@evil.example',
                    'http://localhost:11434/other', 'http://localhost:11434?x=y']:
            with self.assertRaises(ValueError):
                chat(url, {})


if __name__ == '__main__':
    unittest.main()
