"""Build file-server uploads: python -m release.build [--output PATH]."""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import importlib
import io
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch
import zipfile

from ctf.organizer.build import build as build_ctf

ROOT = Path(__file__).resolve().parents[1]
WORKSHOP_MODULES = ('__init__.py', 'agent_comparison.py', 'behavioral.py', 'binding_probes.py',
                    'db.py', 'engine.py', 'exercises.py', 'jupyter.py', 'launch.py',
                    'normalization.py', 'notebooks.py', 'service_account_baseline.py', 'ui.py', 'enterprise.sql')


def copy_file(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def zip_directory(folder, target):
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(folder.rglob('*')):
            if path.is_file():
                archive.write(path, arcname=str(Path(folder.name) / path.relative_to(folder)))


def checksums(folder):
    paths = sorted(p for p in folder.iterdir() if p.is_file() and p.name != 'SHA256SUMS')
    (folder / 'SHA256SUMS').write_text(''.join(
        hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n' for path in paths))


def generate_notebooks(folder):
    with patch.object(sys, 'path', [str(ROOT / 'datagen')] + sys.path):
        generator = importlib.import_module('make_jupyter_notebooks')
    sql_generator = importlib.import_module('make_sql_notebooks')
    (folder / 'notebooks').mkdir(parents=True, exist_ok=True)
    with contextlib.redirect_stdout(io.StringIO()), patch.object(generator, 'ROOT', folder):
        generator.main()
    # Query definitions read supplied detection assets from the staged student tree.
    with contextlib.redirect_stdout(io.StringIO()), patch.object(sql_generator, 'ROOT', folder):
        sql_generator.main()


def student_tree(folder):
    for name in ('setup.sh', 'setup.ps1', 'requirements.txt', 'requirements-notebooks.txt', 'LICENSE', 'WORKSHOP.md'):
        copy_file(ROOT / name, folder / name)
    copy_file(ROOT / 'release/START-HERE.md', folder / 'README.md')
    for name in WORKSHOP_MODULES:
        copy_file(ROOT / 'workshop' / name, folder / 'workshop' / name)
    for cloud in ('eks', 'gke', 'aks'):
        copy_file(ROOT / 'workshop/ingestion' / (cloud + '.sql'), folder / 'workshop/ingestion' / (cloud + '.sql'))
        copy_file(ROOT / 'data/raw' / cloud / (cloud + '_audit.jsonl.gz'),
                  folder / 'data/raw' / cloud / (cloud + '_audit.jsonl.gz'))
    for name in ('NOTICE', 'LICENSE.attack_data'):
        copy_file(ROOT / 'data/raw' / name, folder / 'data/raw' / name)
    for path in (ROOT / 'data/fixtures').glob('*.csv'):
        copy_file(path, folder / 'data/fixtures' / path.name)
    for name in ('__init__.py', 'local_model.py', 'triage.py'):
        copy_file(ROOT / 'agent' / name, folder / 'agent' / name)
    for name in ('privilege_to_secrets.sql', 'alert_evidence.sql', 'enrich_alerts.sql'):
        copy_file(ROOT / 'detection' / name, folder / 'detection' / name)
    for path in (ROOT / 'docs').glob('*.md'):
        copy_file(path, folder / 'docs' / path.name)
    for name in ('HINTS.md', 'detection.sql'):
        copy_file(ROOT / 'labs/service_account_baseline' / name, folder / 'labs/service_account_baseline' / name)
    copy_file(ROOT / 'notebooks/guides/05_Detect_service_account_deviations.md',
              folder / 'notebooks/guides/05_Detect_service_account_deviations.md')
    # Keep participant-guide CTF links valid, without bundling any organizer material.
    for challenge in ('easy', 'hard'):
        for name in ('README.md', 'HINTS.md'):
            copy_file(ROOT / 'ctf' / challenge / name, folder / 'ctf' / challenge / name)
    (folder / 'ctf/README.md').write_text('# CTF practice\n\nDownload ctf-easy.zip and ctf-hard.zip separately from the file server. Read the README in each extracted challenge and open Start.ipynb. Do not run a CTF builder from the student workshop edition.\n')
    generate_notebooks(folder)
    # Student-only guide removes commands/links for maintainer tools that are not shipped.
    guide = folder / 'WORKSHOP.md'
    text = guide.read_text().replace('See [ctf/README.md](ctf/README.md) to build and open the standalone challenges.',
                                    'Download the separate CTF ZIPs from the file server; see [ctf/README.md](ctf/README.md).')
    text = text.replace('Facilitator answers live in `solutions/binding_exercise/` and\n'
                        '`detection/simple_cluster_admin/`; they are not loaded into participant TODO cells.',
                        'Facilitator answers are provided separately to organizers; they are not bundled in this student edition.')
    text = text.replace(' The older `tutorials/` notebooks remain optional.', '')
    start, end = text.index('## Facilitator checks'), text.index('## Troubleshooting')
    text = text[:start] + text[end:]
    guide.write_text(text)


def facilitator_tree(student, folder):
    from datagen.check_tutorials import with_facilitator_answers
    for source in sorted((ROOT / 'solutions').rglob('*')):
        if source.is_file() and source.suffix in ('.py', '.sql', '.ipynb', '.md'):
            target = folder / 'solutions' / source.relative_to(ROOT / 'solutions')
            copy_file(source, target)
            if source.suffix == '.ipynb':
                notebook = json.loads(target.read_text())
                for cell in notebook['cells']:
                    if cell['cell_type'] == 'code':
                        cell.update(outputs=[], execution_count=None)
                target.write_text(json.dumps(notebook, indent=1) + '\n')
    copy_file(ROOT / 'datagen/make_service_account_baseline.py', folder / 'datagen/make_service_account_baseline.py')
    for source in (ROOT / 'detection/simple_cluster_admin').glob('*.sql'):
        copy_file(source, folder / 'detection/simple_cluster_admin' / source.name)
    for source in (student / 'notebooks').glob('*.ipynb'):
        notebook = with_facilitator_answers(json.loads(source.read_text()))
        title = notebook['cells'][0]['source']
        notebook['cells'][0]['source'] = ['**FACILITATOR EDITION — exercise answers included.**\n\n'] + title
        path = folder / 'notebooks' / source.name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(notebook, indent=1) + '\n')
    (folder / 'FACILITATOR-README.md').write_text('''# Facilitator answer overlay — restricted

Extract workshop-student.zip into a separate organizer working directory first.
Copy the contents of facilitator-solutions/ into that workshop-student/ directory,
merging solutions/ and detection/ and replacing notebooks/ with the answer versions.
Open the resulting notebooks using setup.sh on macOS/Linux/WSL or setup.ps1
on native Windows. The overlay is not a
standalone runtime and does not include a second copy of the datasets.

The notebooks have resolved raw detection and normalization TODOs but no saved
execution outputs. The local model and schema comparison remain opt-in; no model
assessment is pre-generated. The original solutions/ and raw query SQL are included
for review. Do not upload this overlay to the student download location.
''')


def build(output, ctf_seed=None):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError('Output directory must be empty; use a new --output to preserve prior releases.')
    seed = ctf_seed if ctf_seed is not None else secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix='workshop-release-') as temporary:
        temporary = Path(temporary)
        student = temporary / 'workshop-student'
        student_tree(student)
        facilitator = temporary / 'facilitator-solutions'
        facilitator_tree(student, facilitator)
        ctf = temporary / 'ctf'
        build_ctf(ctf, seed)
        staged = temporary / 'upload'
        public = staged / 'students'
        private = staged / 'organizers'
        public.mkdir(parents=True)
        private.mkdir(mode=0o700)
        copy_file(ROOT / 'release/START-HERE.md', public / 'START-HERE.md')
        zip_directory(student, public / 'workshop-student.zip')
        for challenge in ('easy', 'hard'):
            copy_file(ctf / (challenge + '.zip'), public / ('ctf-' + challenge + '.zip'))
        zip_directory(facilitator, private / 'facilitator-solutions.zip')
        copy_file(ctf / 'organizer/answers.json', private / 'ctf-answers.json')
        commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True)
        status = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT, capture_output=True, text=True)
        (private / 'release-notes.md').write_text(
            '# Restricted release notes\n\n'
            f'Built at: {datetime.now(timezone.utc).isoformat()}\n\n'
            f'Source commit: {commit.stdout.strip() or "unknown"}\n\n'
            f'Uncommitted source changes present: {bool(status.stdout.strip())}\n\n'
            f'Private CTF seed: `{seed}`\n\n'
            'Publish only students/. Configure file-server ACLs to restrict organizers/.\n'
            'Player notebooks are freshly generated and unexecuted; local working notebooks are untouched.\n'
            'Ingestion and validation code are runtime assets, not hidden grading.\n'
            'Python dependencies and optional Ollama/model weights are not bundled.\n'
            'No live LLM results or performance claims are included.\n'
            'The facilitator ZIP is an overlay for a private copy of the student workshop.\n'
            'The included SHA256SUMS files record the exact uploaded bytes.\n')
        for folder in (public, private):
            checksums(folder)
        for path in private.iterdir():
            path.chmod(0o600)
        shutil.copytree(staged, output, dirs_exist_ok=True)
        (output / 'organizers').chmod(0o700)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/file-server')
    parser.add_argument('--ctf-seed', help='Private competition seed; omitted generates a random seed stored only in organizer notes.')
    args = parser.parse_args()
    output = build(args.output, args.ctf_seed)
    print(f'Publish student files: {output / "students"}')
    print(f'Restrict organizer files: {output / "organizers"}')


if __name__ == '__main__':
    main()
