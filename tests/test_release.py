"""Validate the actual file-server archives, including an isolated extracted runtime."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

import nbformat

from release.build import build


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='release-tests-')
        cls.output = Path(cls.temporary.name) / 'uploads'
        build(cls.output, ctf_seed='release-test')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_upload_layout_checksums_and_private_permissions(self):
        public, private = self.output / 'students', self.output / 'organizers'
        self.assertEqual({p.name for p in public.iterdir()},
                         {'START-HERE.md', 'workshop-student.zip', 'ctf-easy.zip', 'ctf-hard.zip', 'SHA256SUMS'})
        self.assertEqual({p.name for p in private.iterdir()},
                         {'facilitator-solutions.zip', 'ctf-answers.json', 'release-notes.md', 'SHA256SUMS'})
        self.assertEqual(private.stat().st_mode & 0o777, 0o700)
        for folder in (public, private):
            for line in (folder / 'SHA256SUMS').read_text().splitlines():
                expected, filename = line.split('  ', 1)
                self.assertEqual(hashlib.sha256((folder / filename).read_bytes()).hexdigest(), expected)
        answers = json.loads((private / 'ctf-answers.json').read_text())
        for path in public.iterdir():
            for answer in answers.values():
                self.assertNotIn(answer['flag'].encode(), path.read_bytes())

    def test_student_archive_is_clean_complete_and_has_unfilled_exercises(self):
        with zipfile.ZipFile(self.output / 'students/workshop-student.zip') as archive:
            names = archive.namelist()
            forbidden = {'.git', '.aws', '.codex', '.agents', '.venv', '.workshop-venv',
                         'solutions', '__pycache__', 'transcripts', 'artifacts', 'organizer', 'tests'}
            for name in names:
                self.assertFalse(forbidden & set(Path(name).parts), name)
                self.assertNotIn('ground_truth', name)
                self.assertNotIn('detection/simple_cluster_admin', name)
            notebooks = [name for name in names if name.endswith('.ipynb')]
            self.assertEqual(len(notebooks), 6)
            self.assertIn('workshop-student/notebooks/05_Detect_service_account_deviations.ipynb', names)
            self.assertIn('workshop-student/workshop/service_account_baseline.py', names)
            self.assertNotIn('workshop-student/datagen/make_service_account_baseline.py', names)
            mapping_count = 0
            for name in notebooks:
                notebook = nbformat.reads(archive.read(name).decode(), as_version=4)
                nbformat.validate(notebook)
                for cell in notebook.cells:
                    if cell.cell_type == 'code':
                        self.assertEqual(cell.outputs, [])
                        self.assertIsNone(cell.execution_count)
                        if '_mapping = {' in cell.source:
                            namespace = {}
                            exec(cell.source, namespace)
                            mapping = next(v for k, v in namespace.items() if k.endswith('_mapping'))
                            self.assertTrue(all(mapping[field] is None for field in
                                                ('operation', 'resource_type', 'status_id', 'role')))
                            mapping_count += 1
                        self.assertNotIn('RUN_LOCAL_MODEL = True', cell.source)
                        self.assertNotIn('RUN_SCHEMA_COMPARISON = True', cell.source)
            self.assertEqual(mapping_count, 3)
            self.assertTrue(archive.getinfo('workshop-student/setup.sh').external_attr >> 16 & 0o111)
            self.assertIn('workshop-student/docs/windows-setup.md', names)
            self.assertIn('workshop-student/setup.ps1', names)
            self.assertIn('workshop-student/data/raw/NOTICE', names)
            self.assertIn('workshop-student/workshop/ingestion/eks.sql', names)

    def test_facilitator_overlay_contains_answers_without_execution_outputs(self):
        with zipfile.ZipFile(self.output / 'organizers/facilitator-solutions.zip') as archive:
            names = archive.namelist()
            self.assertIn('facilitator-solutions/solutions/binding_exercise/mappings.py', names)
            notebooks = [n for n in names if n.startswith('facilitator-solutions/notebooks/')]
            self.assertEqual(len(notebooks), 6)
            for name in notebooks:
                notebook = nbformat.reads(archive.read(name).decode(), as_version=4)
                nbformat.validate(notebook)
                for cell in notebook.cells:
                    if cell.cell_type == 'code':
                        self.assertEqual(cell.outputs, [])
                        self.assertNotIn('__TODO_', cell.source)

    def test_extracted_student_runtime_runs_without_facilitator_files(self):
        from solutions.binding_exercise.mappings import MAPPINGS
        from solutions.binding_exercise.queries import detection
        target = Path(self.temporary.name) / 'extracted'
        with zipfile.ZipFile(self.output / 'students/workshop-student.zip') as archive:
            archive.extractall(target)
        root = target / 'workshop-student'
        payload = json.dumps({'mappings': MAPPINGS, 'queries': {cloud: detection(cloud) for cloud in
                              ('eks', 'gke', 'aks', 'normalized', 'normalized-success')}})
        script = '''
import json, sys
from pathlib import Path
from workshop.jupyter import NotebookSession
from workshop.normalization import normalize_bindings
from agent.triage import run
answers = json.load(sys.stdin)
assert Path(__import__('workshop').__file__).resolve().parent.parent == Path.cwd()
assert not Path('solutions').exists()
assert not Path('detection/simple_cluster_admin').exists()
session = NotebookSession()
try:
    assert session.execute('SELECT count(*) AS n FROM enterprise.k8s_ocsf')[0]['n'] > 100000
    for cloud in ('eks', 'gke', 'aks'):
        session.execute(answers['queries'][cloud], check_binding=cloud)
    normalize_bindings(session, answers['mappings'])
    for mode in ('normalized', 'normalized-success'):
        session.execute(answers['queries'][mode], check_binding=mode)
    session.execute(Path('detection/privilege_to_secrets.sql').read_text(), save_rule=True)
    key = session.execute('SELECT alert_key FROM main.workshop_alerts LIMIT 1')[0]['alert_key']
    record = run(session.engine, key, split='enterprise')
    assert record['execution'] == 'scripted_replay'
    assert record['assessment']['claims']
finally:
    session.close()
print('PASS: isolated student runtime, all exercise checks and scripted investigator')
'''
        env = dict(os.environ)
        for key in ('WORKSHOP_DATA', 'WORKSHOP_RULE_FILE', 'WORKSHOP_ARTIFACT_DIR', 'LAB2_DIR'):
            env.pop(key, None)
        env['PYTHONPATH'] = ''
        result = subprocess.run([sys.executable, '-c', script], cwd=root, env=env,
                                input=payload, text=True, capture_output=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout[-3000:] + result.stderr)
        self.assertIn('PASS: isolated student runtime', result.stdout)

    def test_nonempty_output_is_preserved(self):
        with self.assertRaisesRegex(ValueError, 'must be empty'):
            build(self.output)


if __name__ == '__main__':
    unittest.main()
