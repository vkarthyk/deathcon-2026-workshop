"""Lab 5: run the investigation agent against raw logs or the OCSF layer.

    python3.11 -m agent.run --mode raw  --out transcripts/raw.json
    python3.11 -m agent.run --mode ocsf --out transcripts/ocsf.json
    python3.11 -m agent.run --mode enriched --out transcripts/enriched.json
    python3.11 -m agent.score transcripts/raw.json transcripts/ocsf.json transcripts/enriched.json

Same model, prompt and evidence in both modes; only the data shape and tools differ.
"""

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import anthropic

from agent.tools import Tools

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"

INTEL_LEAD = (
    "Threat intel reports that credentials for jdoe@example.com appeared in an infostealer log on "
    "2026-10-13. Investigate this person's Kubernetes activity on 2026-10-14 in the payments-prod "
    "clusters across all clouds. Decide whether the account was misused, reconstruct what the actor did, "
    "and separate malicious activity from benign lookalikes."
)


def alert_lead():
    """A realistic detection alert: one event, one cloud, a native principal; no email, IP or other clouds."""
    import csv
    from workshop.db import RAW
    with open(RAW / "ground_truth.csv") as f:
        row = next(r for r in csv.DictReader(f) if r["cloud"] == "eks" and r["step"] == "11")
    return (
        "ALERT  k8s_cluster_wide_secret_enumeration  severity=high\n"
        "cluster: payments-prod (AWS EKS, account 111122223333)\n"
        "time: 2026-10-14T14:25:11Z\n"
        "principal: arn:aws:sts::111122223333:assumed-role/eks-developer/jdoe@example.com\n"
        f"event_id: {row['auditID']}\n"
        "detail: list secrets across all namespaces (GET /api/v1/secrets) succeeded\n\n"
        "Triage this alert. Determine whether it is malicious, who or what is behind it, everything the actor "
        "did, and the full scope of impact across the company's payments-prod clusters. Separate malicious "
        "activity from benign lookalikes."
    )


LEADS = {"alert": alert_lead, "intel": lambda: INTEL_LEAD}


SYSTEM_BASE = """You are a senior SOC analyst investigating Kubernetes activity. Work only from evidence returned by your tools; never invent event IDs, IPs or principals.

Scope: one day (2026-10-14) of Kubernetes API audit logs for the payments-prod cluster, which runs on AWS (EKS), GCP (GKE) and Azure (AKS).

{data}

Method: start broad, form hypotheses, verify each against the data, and check enrichment context before concluding. Cite every malicious event you rely on by its audit event ID. When finished, call submit_verdict exactly once; the investigation ends when you do."""

DATA = {
    "raw": "Data: tables raw_eks, raw_gke and raw_aks hold each cloud's audit log export exactly as that cloud delivers it. Enrichment tables (identities, identity_links, service_accounts, clusters, privileged_allowlist, approved_registries, ip_reputation) describe people, service accounts, assets and IP reputation.",
    "enriched": "Data: ocsf_enriched holds all three clouds normalized to the OCSF API Activity schema (one row per audit event; metadata.uid is the audit event ID), with context already joined onto every row in the `enrichment` struct: the person behind each principal (name, department, out-of-office, usual client OS and mismatch), service-account ownership and whether it called from outside its expected network, source IP reputation, asset classification, and for pod creates whether the workload is privileged, platform-allowlisted and from an approved registry. Tools search and summarize it directly; query_sql is available for anything else.",
    "ocsf": "Data: ocsf_api_activity holds all three clouds normalized to the OCSF API Activity schema (one row per audit event; metadata.uid is the audit event ID). Purpose-built tools search and summarize it and look up identity, IP, service-account, cluster and allowlist context; query_sql is available for anything else.",
}

# USD per million tokens (input, output, cache read); cache writes bill at 1.25x input.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
    "claude-fable-5-1": (10.00, 50.00, 0.25),
}


def estimate_cost(model, u):
    inp, out, read = PRICES.get(model.removeprefix("system.ai."), PRICES[DEFAULT_MODEL])
    return (u["input_tokens"] * inp + u["cache_creation_input_tokens"] * inp * 1.25
            + u["cache_read_input_tokens"] * read + u["output_tokens"] * out) / 1e6


def usage_dict(usage):
    return {k: getattr(usage, k, 0) or 0 for k in
            ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")}


def investigate(mode, client=None, model=DEFAULT_MODEL, effort="medium", max_turns=40, fallbacks=True,
                lead=None, log=print):
    client = client or anthropic.Anthropic()
    lead = lead or alert_lead()
    tools = Tools(mode)
    system = SYSTEM_BASE.format(data=DATA[mode])
    messages = [{"role": "user", "content": lead}]
    request = dict(model=model, max_tokens=16000, system=system, tools=tools.schemas,
                   output_config={"effort": effort}, cache_control={"type": "ephemeral"})
    if fallbacks:
        request.update(betas=[FALLBACK_BETA], fallbacks="default")

    record = {"config": {"mode": mode, "model": model, "effort": effort, "max_turns": max_turns,
                         "fallbacks": fallbacks, "started": datetime.now(timezone.utc).isoformat()},
              "lead": lead, "system": system, "turns": [], "verdict": None, "outcome": None}
    totals = {"input_tokens": 0, "output_tokens": 0, "cache_creation_input_tokens": 0,
              "cache_read_input_tokens": 0, "tool_calls": 0, "tool_errors": 0}
    nudged = 0
    t_start = time.time()

    for turn in range(1, max_turns + 1):
        if turn == max_turns:
            messages.append({"role": "user", "content": "Turn budget exhausted: call submit_verdict now "
                                                        "with what you have."})
        t0 = time.time()
        response = client.beta.messages.create(messages=messages, **request)
        u = usage_dict(response.usage)
        for k in u:
            totals[k] += u[k]
        entry = {"turn": turn, "stop_reason": response.stop_reason, "model": response.model, "usage": u,
                 "latency_s": round(time.time() - t0, 2),
                 "content": [b.to_dict() for b in response.content], "tool_calls": []}
        record["turns"].append(entry)
        # Append the full content, thinking blocks included: the API expects them back unchanged.
        messages.append({"role": "assistant", "content": response.content})
        for b in response.content:
            if b.type == "text" and b.text.strip():
                log(f"[{mode} t{turn}] {b.text.strip()[:300]}")

        if response.stop_reason == "refusal":
            record["outcome"] = f"refusal: {getattr(response.stop_details, 'category', None)}"
            break
        if response.stop_reason == "max_tokens":
            record["outcome"] = "max_tokens"
            break
        if response.stop_reason == "pause_turn":
            continue

        calls = [b for b in response.content if b.type == "tool_use"]
        if not calls:
            if nudged >= 2:
                record["outcome"] = "stopped without verdict"
                break
            nudged += 1
            messages.append({"role": "user", "content": "Call submit_verdict to finish the investigation."})
            continue

        results = []
        for call in calls:
            totals["tool_calls"] += 1
            t1 = time.time()
            try:
                out, is_error = tools.call(call.name, call.input), False
            except Exception as e:  # tool errors go back to the model, which can correct its query
                out, is_error = f"Error: {type(e).__name__}: {e}", True
                totals["tool_errors"] += 1
            if call.name == "submit_verdict" and not is_error:
                record["verdict"] = call.input
            entry["tool_calls"].append({"id": call.id, "name": call.name, "input": call.input, "result": out,
                                        "is_error": is_error, "ms": int((time.time() - t1) * 1000)})
            log(f"[{mode} t{turn}] -> {call.name}({json.dumps(call.input)[:160]}){' ERROR' if is_error else ''}")
            results.append({"type": "tool_result", "tool_use_id": call.id, "content": out, "is_error": is_error})
        if record["verdict"]:
            record["outcome"] = "verdict"
            break
        messages.append({"role": "user", "content": results})
    else:
        record["outcome"] = record["outcome"] or "turn budget exhausted"

    totals["turns"] = len(record["turns"])
    totals["wall_s"] = round(time.time() - t_start, 1)
    totals["est_cost_usd"] = round(estimate_cost(model, totals), 4)
    record["totals"] = totals
    return record


GATEWAY_TOKEN_FILE = Path.home() / ".databricks_gateway_token"


def make_client(gateway):
    if not gateway:
        # Org-level (unscoped) API keys must name the workspace to bill on every request.
        workspace = os.environ.get("ANTHROPIC_WORKSPACE_ID")
        return anthropic.Anthropic(default_headers={"anthropic-workspace-id": workspace} if workspace else None)
    # Databricks AI Gateway: Anthropic-compatible endpoint, authenticated with a Databricks bearer token.
    base_url = os.environ.get("DATABRICKS_GATEWAY_URL") or os.environ.get("ANTHROPIC_BASE_URL")
    if not base_url or "/ai-gateway/" not in base_url:
        raise SystemExit("set DATABRICKS_GATEWAY_URL to https://<workspace>/ai-gateway/anthropic")
    token = os.environ.get("DATABRICKS_TOKEN") or (
        GATEWAY_TOKEN_FILE.read_text().strip() if GATEWAY_TOKEN_FILE.exists() else None)
    if not token:
        raise SystemExit(f"no gateway token: set DATABRICKS_TOKEN or write one to {GATEWAY_TOKEN_FILE}")
    # A stalled gateway request should fail fast and retry, not block the run for the 10-minute SDK default.
    return anthropic.Anthropic(base_url=base_url, auth_token=token, api_key=None, timeout=180.0, max_retries=3)


def gateway_model(model):
    return model if model.startswith("system.ai.") else f"system.ai.{model}"


def probe(client, model):
    """One tiny request with the loop's request shape, to check auth and parameter support cheaply."""
    r = client.beta.messages.create(model=model, max_tokens=64, output_config={"effort": "low"},
                                    cache_control={"type": "ephemeral"},
                                    messages=[{"role": "user", "content": "Reply with the single word OK."}])
    text = "".join(b.text for b in r.content if b.type == "text")
    print(f"probe ok: model={r.model} stop={r.stop_reason} reply={text!r} usage={usage_dict(r.usage)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["raw", "ocsf", "enriched"])
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh", "max"])
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--no-fallbacks", action="store_true",
                    help="Disable server-side refusal fallbacks (needed behind proxies / non-Claude-API hosts)")
    ap.add_argument("--gateway", action="store_true",
                    help=f"Use the Databricks AI Gateway (token from DATABRICKS_TOKEN or {GATEWAY_TOKEN_FILE})")
    ap.add_argument("--lead", choices=list(LEADS), default="alert",
                    help="alert: a single EKS detection to triage (default); intel: a named-person tip")
    ap.add_argument("--probe", action="store_true", help="Send one tiny request to check connectivity, then exit")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    client = make_client(args.gateway)
    model = gateway_model(args.model) if args.gateway else args.model
    if args.probe:
        probe(client, model)
        return
    if not (args.mode and args.out):
        ap.error("--mode and --out are required unless --probe")
    # Gateways generally don't forward the server-side fallback beta.
    fallbacks = not (args.no_fallbacks or args.gateway or args.model.startswith("claude-haiku"))
    rec = investigate(args.mode, client=client, model=model, effort=args.effort, max_turns=args.max_turns,
                      fallbacks=fallbacks, lead=LEADS[args.lead]())
    rec["config"].update(gateway=args.gateway, lead=args.lead)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rec, indent=1, default=str))
    t = rec["totals"]
    print(f"\n{args.mode}: {rec['outcome']} in {t['turns']} turns, {t['tool_calls']} tool calls "
          f"({t['tool_errors']} errors), ~${t['est_cost_usd']} at list price, {t['wall_s']}s -> {args.out}")


if __name__ == "__main__":
    main()
