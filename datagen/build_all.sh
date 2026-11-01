#!/usr/bin/env bash
# Rebuild every generated artifact, in dependency order, then self-check.
set -euo pipefail
cd "$(dirname "$0")/.."
python3.11 -I datagen/build_k8s.py --attack-data vendor/attack_data --out data/raw
python3.11 -I datagen/make_fixtures.py
python3.11 datagen/make_scaffolds.py
python3.11 datagen/make_lab1.py
python3.11 datagen/make_tutorials.py
python3.11 datagen/build_behavioral.py
python3.11 datagen/make_sql_notebooks.py
python3.11 datagen/make_jupyter_notebooks.py
python3.11 datagen/build_replays.py
python3.11 datagen/make_expected.py
python3.11 datagen/check_raw_rules.py
LAB2_DIR=solutions/lab2_ocsf python3.11 -m pytest labs/lab2_ocsf -q -p no:cacheprovider
python3.11 datagen/check_enrichment.py
python3.11 -m unittest discover -s tests -v
python3.11 datagen/check_sql_workshop.py
