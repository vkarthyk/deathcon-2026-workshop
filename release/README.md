# File-server release builder

From the repository root, after workshop dependencies are installed:

```bash
.workshop-venv/bin/python -m release.build
```

The output defaults to `dist/file-server/`. Choose an empty directory with `--output PATH` to build another release. Each build generates a private random CTF seed unless `--ctf-seed` is supplied. Preserve the organizer release notes to reproduce the CTF answers.

```text
students/                       # publish this directory
  START-HERE.md
  workshop-student.zip
  ctf-easy.zip
  ctf-hard.zip
  SHA256SUMS
organizers/                     # restrict with file-server ACLs
  facilitator-solutions.zip
  ctf-answers.json
  release-notes.md
  SHA256SUMS
```

The builder uses an explicit file allowlist. It regenerates the six notebooks from scaffolds in a temporary folder, preserving the author's working notebooks. Outputs, execution counts, completed exercise mappings and saved local rules do not enter the student ZIP. It excludes `solutions/`, raw exercise reference-query files, test/evaluation labels, `.git/`, local environments, credentials, artifacts and transcripts. Prepared ingestion assets and transparent runtime checking logic are included because the core workshop needs them; self-service checks are not secret grading.

The student edition contains the supplied behavioral rule from notebook 03 by design; that lesson asks students to read, run and modify the supplied sequence. Its raw-detection and normalization TODOs remain incomplete. Facilitator answer notebooks resolve those TODOs in the restricted ZIP.

The extra notebook `notebooks/05_Detect_service_account_deviations.ipynb` includes
a flawed detection SQL file, synthetic AWS, GCP and Azure logs and an action catalog under `labs/service_account_baseline/`. Its reference answer, independent evaluator and scenario generator
are included only in the restricted facilitator overlay. The lab runtime works
with the native DuckDB CLI or the workshop's Python engine. The builder freshly
generates its notebook and practice logs, preserving local notebook edits.

Both `setup.sh` and the native Windows `setup.ps1` launcher are included, together
with the Windows setup guide. The PowerShell launcher does not require WSL or a
second VM; Windows runtime validation is defined in the Windows CI workflow.

The builder copies prepared ingestion SQL into runtime assets rather than relying on the `solutions/` directory. Runtime detection checks compare with normalized reference data, so the student package does not need facilitator cloud-query SQL files. It bundles raw data and fixtures with the required source license/notice; installation still downloads Python dependencies. It does not bundle Ollama, model weights or platform-specific wheels.

The CTF build happens independently with a private seed. Only its player ZIPs are published; the answer manifest and seed go into `organizers/`. The source repository contains CTF reference algorithms, so do not publish organizer source as a competition attachment.

The output directory's organizer permissions are restricted locally. You must separately restrict access when uploading to a file server; directory names and ZIPs are not access controls. The facilitator ZIP explains how organizers merge the answer overlay into a copy of the student folder. Never merge it into the student download you publish.

Run `tests.test_release` to validate archive boundaries and notebook resets. The integration test imports the runtime from an extracted student ZIP, checks the cloud detections and normalization using facilitator answers supplied only in memory, and runs the scripted checker without an LLM.
