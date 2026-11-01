"""Exercise the notebook SQL path and saved rule across independent sessions."""
import json
import importlib
import sys
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from workshop.behavioral import ROOT
from workshop.jupyter import NotebookSession, json_result, load_ipython_extension


class JupyterTests(unittest.TestCase):
    def test_saved_rule_refresh_and_failed_save(self):
        with tempfile.TemporaryDirectory() as directory:
            rule = Path(directory) / "rule.sql"
            first = NotebookSession(rule, statements=[])
            second = NotebookSession(rule, statements=[])
            self.addCleanup(first.close)
            self.addCleanup(second.close)
            definition = "CREATE OR REPLACE VIEW main.workshop_alerts AS SELECT 42 AS n;"
            first.execute(definition, save_rule=True)
            self.assertEqual(second.execute("SELECT * FROM main.workshop_alerts"), [{"n": 42}])
            first.execute(definition.replace("42", "7"), save_rule=True)
            self.assertEqual(second.execute("SELECT * FROM main.workshop_alerts"), [{"n": 7}])
            saved = rule.read_text()
            with self.assertRaises(ValueError):
                first.execute("SELECT 1; SELECT 2;", save_rule=True)
            with self.assertRaises(RuntimeError):
                first.execute("CREATE OR REPLACE VIEW main.workshop_alerts AS SELECT missing_column;", save_rule=True)
            self.assertEqual(rule.read_text(), saved)
            first.execute("CREATE TABLE only_here AS SELECT 1 AS n")
            with self.assertRaises(RuntimeError):
                second.execute("SELECT * FROM only_here")

    def test_legacy_macro_artifact_is_not_silently_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            rule = Path(directory) / 'rule.sql'
            rule.write_text('CREATE OR REPLACE MACRO main.participant_rule() AS TABLE SELECT 1 AS n;')
            with self.assertRaisesRegex(ValueError, 'notebook 03'):
                NotebookSession(rule, statements=[])

    def test_nested_json_display_preserves_complete_source(self):
        event = {'kind': 'Event', 'requestObject': {'subjects': [{'name': 'alice', 'kind': 'User'}]}}
        self.assertEqual(json_result([{'event': event}]), (True, event))
        self.assertEqual(json_result([{'event': json.dumps(event)}]), (True, event))
        self.assertEqual(json_result([{'event': event}, {'event': event}]), (True, [event, event]))
        flat = [{'kind': 'Event', 'count': 1}]
        self.assertEqual(json_result(flat), (False, flat))
        self.assertEqual(json_result(flat, force=True), (True, flat))
        text = [{'message': 'not JSON'}]
        self.assertEqual(json_result(text), (False, text))

    def test_detection_todos_and_missing_normalization_fail_clearly(self):
        with tempfile.TemporaryDirectory() as directory:
            session = NotebookSession(Path(directory) / 'rule.sql', statements=[])
            self.addCleanup(session.close)
            with self.assertRaisesRegex(ValueError, 'Detection incomplete'):
                session.execute('SELECT __TODO_OPERATION__', check_binding='eks')
            with self.assertRaisesRegex(ValueError, 'Normalize and validate'):
                session.execute('SELECT 1', check_binding='normalized')

    def test_sql_magic_accepts_json_option(self):
        with tempfile.TemporaryDirectory() as directory:
            session = NotebookSession(Path(directory) / 'rule.sql', statements=[])
            self.addCleanup(session.close)
            registered = {}
            shell = SimpleNamespace(user_ns={'session': session}, register_magic_function=lambda function, **kwargs: registered.update(sql=function))
            load_ipython_extension(shell)
            display = SimpleNamespace(JSON=lambda payload, expanded: {'payload': payload, 'expanded': expanded})
            with patch.dict('sys.modules', {'IPython.display': display}):
                result = registered['sql']('--json', "SELECT {'kind': 'Event', 'requestObject': {'subject': 'alice'}} AS event")
            self.assertEqual(result, {'payload': {'kind': 'Event', 'requestObject': {'subject': 'alice'}}, 'expanded': True})

    def test_sql_magic_routes_binding_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            session = NotebookSession(Path(directory) / 'rule.sql', statements=[])
            self.addCleanup(session.close)
            registered = {}
            shell = SimpleNamespace(user_ns={'session': session}, register_magic_function=lambda function, **kwargs: registered.update(sql=function))
            load_ipython_extension(shell)
            for mode in ('eks', 'normalized-success'):
                with patch('workshop.normalization.check_detection', return_value=[{'n': 1}]) as check, patch('itables.show'):
                    registered['sql']('--check-binding ' + mode, 'SELECT 1 AS n')
                check.assert_called_once_with(session.engine, mode, 'SELECT 1 AS n')

    def test_sql_magic_interactive_table_keeps_rows_beyond_first_page(self):
        with tempfile.TemporaryDirectory() as directory:
            session = NotebookSession(Path(directory) / 'rule.sql', statements=[])
            self.addCleanup(session.close)
            registered = {}
            shell = SimpleNamespace(user_ns={'session': session}, register_magic_function=lambda function, **kwargs: registered.update(sql=function))
            with patch('itables.init_notebook_mode') as initialize:
                load_ipython_extension(shell)
            initialize.assert_called_once_with(all_interactive=True, connected=False)
            with patch('itables.show') as show:
                registered['sql']('', 'SELECT range AS n FROM range(125)')
            frame = show.call_args.args[0]
            self.assertEqual(frame['n'].tolist(), list(range(125)))
            self.assertEqual(show.call_args.kwargs['pageLength'], 25)
            self.assertFalse(show.call_args.kwargs['connected'])
            self.assertEqual(show.call_args.kwargs['maxBytes'], 0)
            from itables import to_html_datatable
            html = to_html_datatable(frame, **show.call_args.kwargs)
            self.assertIn('124', html)
            self.assertIn('"pageLength": 25', html)
            self.assertNotIn('https://www.unpkg.com', html)

    def test_sql_magic_empty_result_does_not_render_table(self):
        with tempfile.TemporaryDirectory() as directory:
            session = NotebookSession(Path(directory) / 'rule.sql', statements=[])
            self.addCleanup(session.close)
            registered = {}
            shell = SimpleNamespace(user_ns={'session': session}, register_magic_function=lambda function, **kwargs: registered.update(sql=function))
            load_ipython_extension(shell)
            with patch('itables.show') as show, contextlib.redirect_stdout(io.StringIO()) as output:
                registered['sql']('', 'SELECT 1 WHERE FALSE')
            show.assert_not_called()
            self.assertIn('no rows returned', output.getvalue())

    def test_generated_notebooks_explain_every_statement(self):
        # Validate fresh generator output, leaving participants' saved cells/results intact.
        with patch.object(sys, "path", [str(ROOT / "datagen")] + sys.path):
            generator = importlib.import_module("make_jupyter_notebooks")
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        output = Path(directory.name)
        (output / "notebooks").mkdir()
        with patch.object(generator, "ROOT", output), contextlib.redirect_stdout(io.StringIO()):
            generator.main()
        paths = sorted((output / "notebooks").glob("*.ipynb"))
        self.assertEqual(len(paths), 5)
        sql_count = 0
        for path in paths:
            notebook = json.loads(path.read_text())
            self.assertEqual(notebook["metadata"]["kernelspec"]["name"], "python3")
            for index, cell in enumerate(notebook["cells"]):
                if cell["cell_type"] == "code":
                    self.assertEqual(notebook["cells"][index-1]["cell_type"], "markdown")
                    source = "".join(cell["source"])
                    if source.startswith("%%sql"):
                        sql_count += 1
                        self.assertIn('-- TODO:', source)
                        self.assertNotIn('_preview', source)
                    else:
                        compile(source, str(path), "exec")
                    self.assertEqual(cell["outputs"], [])
        self.assertEqual(sql_count, 17)


if __name__ == "__main__":
    unittest.main()
