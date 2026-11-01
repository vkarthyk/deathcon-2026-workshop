# Kubernetes detection CTF

Two standalone, synthetic challenges practice the workshop's detection skills. Neither requires an LLM, cloud account or prior workshop completion.

| Challenge | Difficulty | Time | Suggested points | Skill |
|---|---|---:|---:|---|
| [Find the admin grant](easy/README.md) | Easy | 10–15 min | 100 | Extract provider-specific fields and detect successful cluster-admin grants |
| [Follow the recipient](hard/README.md) | Hard | 30–45 min | 400 | Correlate normalized events by recipient, asset, outcome and time; check exact approvals |

## Practice locally

From the repository root, after installing workshop dependencies with `./setup.sh`:

```bash
.workshop-venv/bin/python -m ctf.organizer.build
```

Open `ctf/dist/players/easy/Start.ipynb` or `ctf/dist/players/hard/Start.ipynb` in JupyterLab. Read the challenge's README and open HINTS.md only as needed. The generated datasets contain fresh cases rather than the workshop's answers. SQL queries can also run in DuckDB CLI against each `challenge.duckdb`.

To start Jupyter without running setup again:

```bash
.workshop-venv/bin/python -m jupyterlab --notebook-dir=ctf/dist/players
```

For practice, check a submission locally:

```bash
.workshop-venv/bin/python -m ctf.organizer.check \
  --answers ctf/dist/organizer/answers.json --challenge easy \
  --flag 'CTF{YOUR_EVENT_IDS}'
```

The private answer key is a spoiler; do not open it before attempting the challenge.

## Host a competition

See [the organizer guide](organizer/README.md). Give participants **only** `easy.zip` and `hard.zip`, not the source repository, build output directory, organizer files or answer key. Each ZIP includes instructions, progressive hints, a blank starter notebook, a read-only-compatible DuckDB database and JSONL exports. The database contains no flags, solution views, challenge labels or ground-truth table.

This repository is public practice material, including solution SQL and generation logic. For a scored event, build with a private seed and keep the release and answers private until launch. These are introductory learning challenges, not resistant to someone using the public reference SQL. Ask for a short query or evidence explanation as an additional learning deliverable if your event supports it.
