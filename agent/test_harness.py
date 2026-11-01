"""Offline tests for the agent harness: a scripted client drives the real loop, tools and scorer.

    python3.11 -m pytest agent -q
"""

import csv
from types import SimpleNamespace

from anthropic.types.beta import BetaMessage

from agent import score as scoring
from agent.run import investigate
from workshop.db import RAW


def message(content, stop_reason, n=1):
    return BetaMessage.model_validate({
        "id": f"msg_{n}", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
        "content": content, "stop_reason": stop_reason, "stop_sequence": None,
        "usage": {"input_tokens": 1000, "output_tokens": 200, "cache_creation_input_tokens": 0,
                  "cache_read_input_tokens": 500},
    })


def tool_use(i, name, inp):
    return {"type": "tool_use", "id": f"toolu_{i}", "name": name, "input": inp}


class ScriptedClient:
    """Replays canned responses and records every request the loop sends."""

    def __init__(self, responses):
        self.responses, self.requests = list(responses), []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs | {"messages": list(kwargs["messages"])})  # snapshot; the loop keeps appending
        return self.responses.pop(0)


def attack_ids(cloud=None):
    with open(RAW / "ground_truth.csv") as f:
        return [r["auditID"] for r in csv.DictReader(f) if cloud in (None, r["cloud"])]


def verdict(evidence, **over):
    v = {"verdict": "malicious", "confidence": "high", "summary": "x", "affected_clouds": ["AWS", "GCP", "Azure"],
         "attacker_ips": ["198.51.100.23"], "evidence": evidence, "benign_lookalikes": [],
         "compromised_principals": sorted(scoring.EXPECTED_PRINCIPALS)}
    return v | over


def test_ocsf_run_full_marks():
    evidence = [{"event_id": i, "cloud": "AWS", "description": "attack"} for i in attack_ids()]
    client = ScriptedClient([
        message([tool_use(1, "summarize_activity", {"group_by": ["src_ip", "cloud"], "email": "jdoe@example.com",
                                                     "src_ip": None})], "tool_use", 1),
        message([tool_use(2, "lookup_ip", {"ip": "198.51.100.23"}),
                 tool_use(3, "resolve_identity", {"query": "jdoe@example.com"})], "tool_use", 2),
        message([tool_use(4, "submit_verdict", verdict(evidence))], "tool_use", 3),
    ])
    rec = investigate("ocsf", client=client, log=lambda *_: None)
    assert rec["outcome"] == "verdict" and rec["totals"]["turns"] == 3 and rec["totals"]["tool_calls"] == 4
    # Parallel tool calls come back in one user message, in call order.
    results = client.requests[2]["messages"][-1]["content"]
    assert [r["tool_use_id"] for r in results] == ["toolu_2", "toolu_3"]
    assert "NIGHTOWL-HOSTING" in results[0]["content"] and "Jordan Doe" in results[1]["content"]
    assert client.requests[0]["fallbacks"] == "default" and client.requests[0]["output_config"] == {"effort": "medium"}
    s = scoring.score(rec, scoring.load_truth(), scoring.all_event_ids())
    assert s["score"] == 100 and s["attack_steps_cited"] == "33/33"


def test_raw_run_tool_error_nudge_and_penalties():
    benign = "not-an-event"
    client = ScriptedClient([
        message([tool_use(1, "query_sql", {"sql": "SELECT verb FROM raw_eks"})], "tool_use", 1),
        message([{"type": "text", "text": "I think I am done."}], "end_turn", 2),
        message([tool_use(2, "submit_verdict", verdict(
            [{"event_id": i, "cloud": "AWS", "description": "x"} for i in attack_ids("eks")]
            + [{"event_id": benign, "cloud": "GCP", "description": "made up"}],
            affected_clouds=["AWS"], verdict="suspicious"))], "tool_use", 3),
    ])
    rec = investigate("raw", client=client, log=lambda *_: None)
    assert rec["totals"]["tool_errors"] == 1, "selecting a non-existent column should surface as a tool error"
    assert client.requests[2]["messages"][-1]["content"].startswith("Call submit_verdict")
    s = scoring.score(rec, scoring.load_truth(), scoring.all_event_ids())
    assert s["clouds_found"] == "1/3" and s["attack_steps_cited"] == "11/33" and s["invented_event_ids"] == 1
    assert s["score"] < 50


def test_turn_budget_forces_submission():
    loop = [message([tool_use(i, "list_tables", {})], "tool_use", i) for i in range(1, 3)]
    client = ScriptedClient(loop + [message([tool_use(9, "submit_verdict", verdict([]))], "tool_use", 3)])
    rec = investigate("ocsf", client=client, max_turns=3, log=lambda *_: None)
    assert "Turn budget exhausted" in client.requests[2]["messages"][-1]["content"]
    assert rec["outcome"] == "verdict"


def test_raw_mode_cannot_see_ocsf_tools():
    client = ScriptedClient([message([tool_use(1, "search_activity", {})], "tool_use", 1),
                             message([tool_use(2, "submit_verdict", verdict([]))], "tool_use", 2)])
    rec = investigate("raw", client=client, log=lambda *_: None)
    assert rec["turns"][0]["tool_calls"][0]["is_error"]
    assert {t["name"] for t in client.requests[0]["tools"]} == {"query_sql", "list_tables", "submit_verdict"}
