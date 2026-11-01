"""Artifact helpers for evidence-based notebook investigations."""
import json
import os
from pathlib import Path

from workshop.behavioral import ROOT


def artifacts():
    directory = Path(os.environ.get('WORKSHOP_ARTIFACT_DIR', ROOT / 'artifacts'))
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def save_records(filename, records):
    path = artifacts() / filename
    path.write_text(''.join(json.dumps(record, default=str) + '\n' for record in records))
    return path
