# Organizer guide — spoilers

Do not distribute this directory or the source generator with competition downloads.

## Build and publish

From the repository root in the workshop environment:

```bash
.workshop-venv/bin/python -m ctf.organizer.build \
  --output /tmp/k8s-ctf-release --seed 'YOUR_PRIVATE_EVENT_SEED'
```

Choose an empty output directory. Reusing a nonempty directory is rejected to preserve earlier releases. The same seed reproduces IDs, cases and expected answers (ZIP bytes/database internals need not be identical). The default seed `practice` is public and intended only for local practice. Keep a competition seed private, including in shell history and deployment logs.

Publish **only** `/tmp/k8s-ctf-release/easy.zip` and `hard.zip`. Keep `organizer/answers.json` on the CTF server. Import its `easy.flag` and `hard.flag` values as static, case-sensitive flags in your CTF platform, or call `ctf.organizer.check.check` from your server-side integration. The CLI validator is also available; see the root CTF README. A full hosting service is not included.

Each player archive has an explicit set of files: the challenge README, HINTS, starter notebook, challenge database and JSONL source exports. It does not include SQL solutions, generated flags, labels or a checker. The answer-bearing event IDs necessarily exist in the evidence, but no row labels them as the intended answer. No workshop labels or existing malicious examples are reused. Identity and approval context appears only where required.

This source repository contains solutions and is a learning resource. A private seed changes the answer IDs and hard-case placement, but does not make the public solution algorithms secret. If leaderboard integrity depends on hiding solutions, distribute challenge archives through your platform rather than linking this organizer source during the event.

## Challenge design and answers

- **Easy, suggested 100 points:** one successful cluster-admin binding create per cloud. Decoys cover failed outcomes, HTTP unknown outcomes, another role with a misleading binding name, wrong role kind, wrong verb/resource and absent bodies. HTTP success is 200–299. Modeled GKE gRPC success is zero or absent status. [easy.sql](easy.sql) is the reference query. Submit AWS, GCP, Azure IDs in that order.
- **Hard, suggested 400 points:** exactly one unapproved sequence. Cases cover the grant actor acting instead of the recipient, another cluster/account, events before or after the allowed window, valid approvals, failed grants/reads, namespaced reads, wrong role/kind and ServiceAccount recipients. Every grant has multiple subjects, and the relevant recipient is not first. The real sequence has near-matching approvals with incorrect scope or expired validity. Missing identity mappings must not remove a match. [hard.sql](hard.sql) is the reference query. Submit grant ID then read ID.

The builder executes the reference queries and fails if easy does not have one answer per cloud or hard does not have exactly one pair. Noise, scenario ordering, providers, times and IDs are seeded and shuffled. Times and identifiers are separate from the workshop log day. There are no offensive actions to execute; every task analyzes supplied synthetic audit data.

## Hints and debrief

HINTS.md uses collapsed sections and is bundled for self-service use. Platforms can instead reveal the three hints at increasing point costs. Keep schema references free: this tests detection reasoning, not remembering field names.

For easy, ask why searching for `cluster-admin` or ignoring response codes admits decoys. For hard, ask why actor and recipient differ, why exact asset/time scope matters, and why an unrelated approval is insufficient. Show how normalized fields let the hard rule apply across all three clouds without provider branches.

For offline practice, learners can use the organizer validator after attempting the challenge. For competition, the platform must perform validation; do not give players the answer manifest. Ask for the submitted detection query and a short evidence explanation if your platform supports learning deliverables beyond flags.

## Verify changes

```bash
.workshop-venv/bin/python -m unittest tests.test_ctf
```

Tests build temporary releases, validate unique solutions, inspect player databases/archives for answer artifacts, exercise decoy predicates and test the checker. Generated practice/release data under `ctf/dist/` is ignored by Git.
