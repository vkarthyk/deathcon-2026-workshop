"""Check CTF solvability, standalone player releases and predicate-sensitive decoys."""
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

import duckdb
import nbformat

from ctf.organizer.build import ROOT, build
from ctf.organizer.check import check


class CTFTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='ctf-tests-')
        cls.output = Path(cls.directory.name) / 'release'
        cls.answers = build(cls.output, 'test-event')

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def query(self, challenge, sql):
        with duckdb.connect(str(self.output / 'players' / challenge / 'challenge.duckdb'), read_only=True) as con:
            return con.sql(sql).fetchall()

    def test_reference_solutions_are_unique_and_validator_checks_exact_order(self):
        easy = self.query('easy', (ROOT / 'organizer/easy.sql').read_text())
        self.assertEqual(len(easy), 3)
        self.assertEqual({row[0] for row in easy}, {'AWS', 'GCP', 'Azure'})
        hard = self.query('hard', (ROOT / 'organizer/hard.sql').read_text())
        self.assertEqual(len(hard), 1)
        for challenge in ('easy', 'hard'):
            flag = self.answers[challenge]['flag']
            self.assertTrue(check(self.answers, challenge, '  ' + flag + '\n'))
            self.assertFalse(check(self.answers, challenge, flag.replace('CTF{', 'ctf{')))
            self.assertFalse(check(self.answers, challenge, 'CTF{wrong}'))
        first, second = hard[0]
        self.assertFalse(check(self.answers, 'hard', f'CTF{{{second}_{first}}}'))

    def test_releases_are_player_only_and_no_answer_tables_exist(self):
        expected_tables = {'easy': {'raw_eks', 'raw_gke', 'raw_aks'},
                           'hard': {'k8s_ocsf', 'k8s_subjects', 'approvals', 'identities'}}
        for challenge in ('easy', 'hard'):
            with zipfile.ZipFile(self.output / (challenge + '.zip')) as archive:
                names = {Path(name).name for name in archive.namelist()}
                self.assertEqual(names, {'README.md', 'HINTS.md', 'Start.ipynb', 'challenge.duckdb'} |
                                 {table + '.jsonl' for table in expected_tables[challenge]})
                for name in archive.namelist():
                    content = archive.read(name)
                    self.assertNotIn(self.answers[challenge]['flag'].encode(), content)
                    self.assertNotIn(b'comparison_expected_ids', content)
            tables = self.query(challenge, 'SHOW TABLES')
            self.assertEqual({row[0] for row in tables}, expected_tables[challenge])
            for path in (self.output / 'players' / challenge).glob('*.jsonl'):
                for line in path.read_text().splitlines():
                    row = json.loads(line)
                    self.assertFalse({'case', 'target', 'flag', 'expected', 'malicious', 'misleading_name'} & row.keys())

    def test_notebooks_execute_without_the_workshop_runtime(self):
        previous = Path.cwd()
        try:
            for challenge in ('easy', 'hard'):
                folder = self.output / 'players' / challenge
                notebook = nbformat.read(folder / 'Start.ipynb', as_version=4)
                nbformat.validate(notebook)
                namespace = {}
                os.chdir(folder)
                try:
                    for cell in notebook.cells:
                        if cell.cell_type == 'code':
                            self.assertNotIn('workshop.', cell.source)
                            exec(compile(cell.source, 'ctf-starter', 'exec'), namespace)
                finally:
                    if 'con' in namespace:
                        namespace['con'].close()
        finally:
            os.chdir(previous)

    def test_easy_outcome_and_role_decoys(self):
        sql = (ROOT / 'organizer/easy.sql').read_text()
        broad = sql.replace("  AND CAST(json_extract_string(event, '$.responseStatus.code') AS INTEGER) BETWEEN 200 AND 299", '')
        self.assertGreater(len(self.query('easy', broad)), 3)
        broad = sql.replace("  AND json_extract_string(event, '$.requestObject.roleRef.name') = 'cluster-admin'", '')
        self.assertGreater(len(self.query('easy', broad)), 3)

    def test_hard_decoys_require_each_sequence_condition(self):
        sql = (ROOT / 'organizer/hard.sql').read_text()
        correct = self.query('hard', sql)
        clauses = (
            "AND e.status_id = 1", "AND e.role_kind = 'ClusterRole'", "AND e.role = 'cluster-admin'",
            "AND s.subject_kind = 'User'", 'AND r.account_uid = g.account_uid',
            'AND r.cluster_name = g.cluster_name', 'AND r.time >= g.time',
            "AND r.time <= g.time + INTERVAL '15' MINUTE", 'AND r.status_id = 1',
            'AND r.namespace IS NULL',
        )
        for clause in clauses:
            with self.subTest(clause=clause):
                self.assertIn(clause, sql)
                self.assertNotEqual(self.query('hard', sql.replace(clause, '')), correct)
        self.assertNotEqual(self.query('hard', sql.replace('r.principal = g.subject', 'r.principal = g.principal')), correct)
        self.assertNotEqual(self.query('hard', sql.replace('NOT EXISTS', 'EXISTS')), correct)

    def test_near_matching_approvals_do_not_suppress_target(self):
        sql = (ROOT / 'organizer/hard.sql').read_text()
        correct = self.query('hard', sql)
        for clause in (
            'AND a.account_uid = g.account_uid', 'AND a.cluster_name = g.cluster_name',
            'AND a.grant_actor = g.principal', 'AND a.subject = g.subject', 'AND a.role = g.role',
            'AND g.time BETWEEN a.start_time AND a.end_time',
        ):
            with self.subTest(clause=clause):
                self.assertNotEqual(self.query('hard', sql.replace(clause, '')), correct)
        self.assertNotEqual(self.query('hard', sql.replace('a.cloud_provider = g.provider AND ', '')), correct)

    def test_seeds_reproduce_answers_and_alternate_releases_remain_solvable(self):
        for index, seed in enumerate(('test-event', 'different-event', 'third-event')):
            answer = build(Path(self.directory.name) / f'variant-{index}', seed)
            if seed == 'test-event':
                self.assertEqual(answer, self.answers)
            else:
                self.assertNotEqual(answer['easy']['flag'], self.answers['easy']['flag'])
                self.assertNotEqual(answer['hard']['flag'], self.answers['hard']['flag'])

    def test_existing_release_is_not_overwritten(self):
        with self.assertRaisesRegex(ValueError, 'must be empty'):
            build(self.output, 'replacement')
        self.assertEqual(json.loads((self.output / 'organizer/answers.json').read_text()), self.answers)


if __name__ == '__main__':
    unittest.main()
