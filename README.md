# One Schema to Rule Them All

A SQL-first workshop for intermediate and experienced detection engineers: write a
behavioral Kubernetes detection once across EKS, GKE and AKS,
and investigate its alerts with verifiable agent tools.

The main detection follows **a cluster-admin grant → secret collection by its
subject**, with asset scope, a 15-minute window, identity resolution and time-bound
change suppression. The participant workflow uses the larger synthetic enterprise log day. OCSF is the example schema, not the learning objective.

## Run the workshop

```bash
./setup.sh
```

Setup creates a local Python environment, installs DuckDB and JupyterLab, and opens
**`notebooks/00_Start_here.ipynb`**. Use the token-bearing URL printed in the terminal
(usually port 8888). Keep that terminal open. Python 3.10+ and initial package-index
access are required; supported paths are macOS/Linux, native Windows PowerShell, and Windows WSL2.

On Windows (including an existing Windows VM), use `setup.ps1`; follow the [Windows setup guide](docs/windows-setup.md). WSL2 is an alternative.

Five notebooks form a one-hour path: inspect logs, complete three raw-cloud binding
detections, build a normalization mapping and unified detection, extend to a
behavioral sequence, and investigate evidence. TODOs have
collapsed hints and checks with field-specific feedback.
Run each
cell with **Shift+Enter**. SQL cells start with `%%sql`; add your own cells the same
way. The setup cell is Python, and the detection queries are SQL executed by DuckDB.
Follow [WORKSHOP.md](WORKSHOP.md) one notebook at a time.

```bash
./setup.sh --port 8889                    # Another Jupyter port
./setup.sh --duckdb-ui                    # Optional native DuckDB UI on 4213
./setup.sh --duckdb-ui --prepare-only     # Build/validate without a server
```

Save notebook edits with Ctrl+S / Cmd+S. Running notebook 03's `%%sql --save-rule`
cell saves your edited SQL view to `artifacts/participant_rule.sql`; later notebooks reload
it automatically. Each notebook has an isolated temporary database, so separate
kernels do not contend for a database lock. Restarting a kernel requires rerunning
its setup. Other temporary SQL changes do not carry across notebooks.

## What participants build

- Three cloud-specific binding detections, a validated normalization mapping, and a shared rule updated to success-only with one condition.
- A portable sequence detection that follows the RBAC subject rather than the actor.
- An evidence-backed alert investigation with bounded tools.
- A reviewable SQL rule, source evidence and documented limitations.

Extra lab: [05 Run the detection in batches](notebooks/05_Run_the_detection_in_batches.ipynb)
adds late logs, duplicate deliveries, restarts and collector outages after the core
notebooks. Allow 60–90 minutes; see [the guide](notebooks/guides/05_Run_the_detection_in_batches.md).

## CTF practice

Two standalone challenges reinforce the workshop: find successful admin grants in
raw cloud logs (easy), then follow an unapproved grant-to-secret-list sequence
through normalized events (hard). See [ctf/README.md](ctf/README.md) for player
instructions, progressive hints and organizer release tools.

## File-server distribution

Build clean student downloads and separate restricted organizer files with:

```bash
.workshop-venv/bin/python -m release.build
```

See [release/README.md](release/README.md) for the upload layout, included assets,
checksums and organizer access requirements. The builder preserves working notebooks.

## Repository map

| Path | Purpose |
|---|---|
| `notebooks/*.ipynb` | Primary advanced Jupyter workshop: Markdown + DuckDB SQL |
| `notebooks/sql/` | Optional native DuckDB SQL exports |
| `detection/` | Shared behavioral SQL and review/deployment specification |
| `data/raw/`, `data/fixtures/` | Original synthetic multi-cloud day and enrichment |
| `data/behavioral/` | Internal automated-test inputs and evaluator artifacts; not participant data |
| `labs/behavioral/`, `solutions/behavioral/` | Agent tool repair and bring-your-own-schema adapter |
| `tests/` | Offline behavioral, uncertainty, evidence-isolation and native notebook tests |
| `agent/triage.py`, `agent/evaluate_triage.py` | New alert-scoped runner and separate evaluator |
| `docs/agent-lab.md` | Evidence investigation and optional local inference |
| `docs/source-validation.md` | Real-export validation status and release checklist |
| `tutorials/`, `labs/lab1_raw/`, `labs/lab2_ocsf/` | Optional earlier Jupyter/raw-log/mapper exercises |
| `agent/run.py`, `transcripts/` | Earlier full-chain agent harness and historical runs |

## Test and replay without a model

With an installed CLI, these use Python's standard library. With the Python-engine
install, use `.workshop-venv/bin/python` in place of `python3`.

```bash
python3 -m unittest discover -s tests -v
python3 datagen/check_sql_workshop.py
python3 datagen/build_behavioral.py --check
python3 -m agent.triage --split enterprise --suite --out artifacts/investigations.jsonl
```

Default replays are deterministic software executing real tools, **not LLM benchmark
results**. Model runs require explicit model selection and are never started by
setup. Local Ollama runs need no API key; paid Anthropic runs require credentials. Read [the agent lab](docs/agent-lab.md) before comparing runs.

## Evidence and scope

The original attacks derive from [splunk/attack_data](https://github.com/splunk/attack_data)
(Apache 2.0); see `data/raw/NOTICE`. Identities and traffic are synthetic. The original
chain has 14 attack events per cloud across 11 numbered steps. Internal automated-test cases are generated locally without upstream downloads.

**Provider envelopes are modeled, not independently validated against real exports.**
A real-source validation command and checklist are included; this remains a release
gate before authoritative format claims. Internal test results are not production detection efficacy. Missing evidence and unsupported
attribution remain first-class outcomes.

To regenerate the original data, the upstream seed files listed in
`datagen/build_k8s.py` are required; normal setup does not regenerate or download it.
`WORKSHOP_DATA` selects an alternate original dataset. The controlled behavioral
corpus remains under `data/behavioral` for automated software checks only.

## Free local agent

The advanced agent can run a real tool-calling model locally with Ollama and Qwen3,
without API keys or API charges. Install [Ollama](https://ollama.com/download), start
it, then run from the repository root:

```bash
ollama pull qwen3:8b
python3 -m agent.triage --provider ollama --model qwen3:8b --suite --out artifacts/local-agent.jsonl
```

Use `.workshop-venv/bin/python` if DuckDB was installed by setup. Start with one
`--alert-key ID` instead of `--suite` on a slower laptop. Without `--model`, the same
harness runs its free deterministic replay. See [the agent lab](docs/agent-lab.md)
for memory requirements, notebook integration and evidence review. Paid
Anthropic calls require explicit `--provider anthropic` and a separate optional SDK.

## License

Workshop code is available under the [MIT License](LICENSE). Third-party datasets,
software and model weights retain their respective licenses.
