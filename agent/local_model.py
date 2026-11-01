"""Ollama tool-calling adapter. Uses the standard library; no paid SDK or API key."""
import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener


def chat(base_url, payload):
    parsed = urlparse(base_url)
    if (parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise ValueError("Ollama URL must be a local HTTP server, e.g. http://localhost:11434")
    request = Request(base_url.rstrip("/") + "/api/chat", data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
    try:
        # Local model traffic must not be sent through an environment-configured proxy.
        with build_opener(ProxyHandler({})).open(request, timeout=300) as response:
            return json.load(response)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError("Local Ollama request failed. Start `ollama serve` and pull the selected model. "
                           "No paid provider was contacted.") from exc


def assess(tools, alert_key, model, max_turns, system, base_url="http://localhost:11434", request_fn=None):
    request_fn = request_fn or chat
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": f"Investigate RBAC grant event {alert_key}. Submit an assessment citing observed event IDs."}]
    schemas = [{"type": "function", "function": {"name": s["name"], "description": s["description"],
                                                "parameters": s["input_schema"]}} for s in tools.schemas]
    usage = {"input_tokens": 0, "output_tokens": 0}
    turns = []
    for turn in range(1, max_turns + 1):
        started = time.monotonic()
        response = request_fn(base_url, {"model": model, "messages": messages, "tools": schemas,
                                        "stream": False, "think": False,
                                        "options": {"temperature": 0, "num_ctx": 16384, "num_predict": 3000}})
        message = response.get("message")
        if not isinstance(message, dict) or message.get("role") != "assistant":
            raise RuntimeError("Ollama returned no assistant message; check model tool-calling support.")
        counts = {"input_tokens": response.get("prompt_eval_count", 0), "output_tokens": response.get("eval_count", 0)}
        for key, count in counts.items():
            usage[key] += count
        turns.append({"turn": turn, "model": response.get("model", model),
                      "stop_reason": response.get("done_reason"), "latency_seconds": round(time.monotonic()-started, 3), **counts})
        messages.append(message)
        for call in message.get("tool_calls") or []:
            function = call.get("function", {})
            name, arguments = function.get("name", ""), function.get("arguments", {})
            try:
                if isinstance(arguments, str):
                    arguments = json.loads(arguments)
                if not isinstance(arguments, dict):
                    raise ValueError("Tool arguments must be a JSON object")
                result = tools.call(name, arguments)
            except (ValueError, TypeError) as exc:
                result = {"error": str(exc)}
                tools.errors += 1
                tools.trace.append({"tool": name, "input": arguments, "result": result,
                                    "is_error": True, "latency_ms": 0})
            if name == "submit_assessment" and not tools.trace[-1]["is_error"]:
                return result, usage, turns
            messages.append({"role": "tool", "tool_name": name, "content": json.dumps(result, default=str)})
        if not message.get("tool_calls"):
            messages.append({"role": "user", "content": "Use the evidence tools, then submit_assessment. Unsupported claims are not evidence."})
    return None, usage, turns
