"""Keep participant-facing SQL diagnostics specific to the failing mapping."""
import contextlib
import copy
import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from solutions.binding_exercise.mappings import MAPPINGS
from workshop.normalization import normalize_bindings


class NormalizationErrorTests(unittest.TestCase):
    def test_sql_error_names_provider_field_and_expression(self):
        mappings = copy.deepcopy(MAPPINGS)
        mappings['aks']['operation'] = 'json_extract_string(entry, $verb)'
        db = Mock()
        db.script.side_effect = [None, RuntimeError('Parameters: verb')]

        def query(sql):
            if '$verb' in sql:
                raise RuntimeError('Parameters: verb')
            return [{'checked': 1}]

        db.query.side_effect = query
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError) as caught:
                normalize_bindings(SimpleNamespace(engine=db), mappings)
        message = str(caught.exception)
        self.assertIn('AKS → operation: json_extract_string(entry, $verb)', message)
        self.assertIn('Rerun the edited mapping cell', message)
        self.assertNotIn('EKS →', message)
