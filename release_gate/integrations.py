"""
Lightweight integration hooks — send audit results to Slack, Datadog, or
any OpenTelemetry-compatible collector.

Usage (CLI):
  release-gate audit . --notify slack://hooks.slack.com/services/T.../B.../xxx
  release-gate audit . --notify datadog://api.datadoghq.com?api_key=KEY
  release-gate audit . --notify otlp://localhost:4318
  release-gate audit . --notify file://path/to/output.json  # write JSON (for testing)

Environment variables (alternative to inline URLs):
  RELEASE_GATE_SLACK_WEBHOOK
  RELEASE_GATE_DATADOG_API_KEY
  RELEASE_GATE_OTEL_ENDPOINT
"""

import json
import os
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional


def _get_repo_name(report: Dict[str, Any]) -> str:
    return report.get("repo", report.get("project", {}).get("name", "unknown"))


def _get_decision(report: Dict[str, Any]) -> str:
    return report.get("decision", "UNKNOWN").upper()


def _get_score(report: Dict[str, Any]) -> float:
    return float(report.get("score", 0))


def _get_safeguards_passing(report: Dict[str, Any]) -> int:
    safeguards = report.get("safeguards", {})
    if isinstance(safeguards, dict):
        return sum(1 for v in safeguards.values() if isinstance(v, dict) and v.get("present", False))
    return 0


def _get_code_risks(report: Dict[str, Any]) -> list:
    return report.get("code_risks", report.get("findings", []))


def notify_slack(report: Dict[str, Any], webhook_url: str) -> None:
    """POST a rich Slack Block Kit message with audit results."""
    repo_name = _get_repo_name(report)
    decision = _get_decision(report)
    score = _get_score(report)
    safeguards_passing = _get_safeguards_passing(report)
    code_risks = _get_code_risks(report)

    decision_emoji = {"PROMOTE": "✅", "HOLD": "⚠️", "BLOCK": "🚫"}.get(decision, "❓")
    color = {"PROMOTE": "#36a64f", "HOLD": "#ffcc00", "BLOCK": "#cc0000"}.get(decision, "#888888")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🚪 release-gate | {repo_name}", "emoji": True},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Score:* {score:.0f}/100   {decision_emoji} *{decision}*\n*Safeguards passing:* {safeguards_passing}",
            },
        },
    ]

    # Failing safeguards block
    if decision in ("BLOCK", "HOLD"):
        safeguards = report.get("safeguards", {})
        failing = []
        if isinstance(safeguards, dict):
            for name, info in safeguards.items():
                if isinstance(info, dict) and not info.get("present", True):
                    risk = info.get("risk", "unknown")
                    failing.append({"type": "mrkdwn", "text": f"*{name}*\nRisk: {risk}"})
                    if len(failing) >= 3:
                        break
        if failing:
            blocks.append({"type": "section", "fields": failing})

    # Code findings context block
    high_risks = [r for r in code_risks if isinstance(r, dict) and r.get("severity", "").lower() == "high"]
    if code_risks:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"🔍 {len(code_risks)} code risks ({len(high_risks)} high)"}],
        })

    payload = {
        "attachments": [{"color": color, "blocks": blocks}],
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def notify_datadog(report: Dict[str, Any], api_key: str, site: str = "datadoghq.com") -> None:
    """POST metrics to Datadog metrics API."""
    repo_name = _get_repo_name(report)
    decision = _get_decision(report)
    score = _get_score(report)
    safeguards_passing = _get_safeguards_passing(report)
    code_risks = _get_code_risks(report)
    high_risks = [r for r in code_risks if isinstance(r, dict) and r.get("severity", "").lower() == "high"]

    model = report.get("project", {}).get("model", "unknown") if isinstance(report.get("project"), dict) else "unknown"
    decision_value = {"PROMOTE": 1.0, "HOLD": 0.5, "BLOCK": 0.0}.get(decision, 0.0)

    now = int(time.time())
    tags = [f"repo:{repo_name}", f"decision:{decision.lower()}", f"model:{model}"]

    series = [
        {"metric": "release_gate.score", "type": "gauge", "points": [[now, score]], "tags": tags},
        {"metric": "release_gate.safeguards_passing", "type": "gauge", "points": [[now, safeguards_passing]], "tags": tags},
        {"metric": "release_gate.code_risks_high", "type": "gauge", "points": [[now, len(high_risks)]], "tags": tags},
        {"metric": "release_gate.decision", "type": "gauge", "points": [[now, decision_value]], "tags": tags},
    ]

    payload = {"series": series}
    url = f"https://api.{site}/api/v1/series"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "DD-API-KEY": api_key},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def notify_otlp(report: Dict[str, Any], endpoint: str) -> None:
    """Emit an OpenTelemetry span via HTTP OTLP (JSON)."""
    import random
    repo_name = _get_repo_name(report)
    decision = _get_decision(report)
    score = _get_score(report)
    safeguards_passing = _get_safeguards_passing(report)
    code_risks = _get_code_risks(report)

    now_ns = int(time.time() * 1e9)
    trace_id = format(random.getrandbits(128), "032x")
    span_id = format(random.getrandbits(64), "016x")

    def attr(key, value, vtype="stringValue"):
        if vtype == "intValue":
            return {"key": key, "value": {"intValue": str(value)}}
        if vtype == "doubleValue":
            return {"key": key, "value": {"doubleValue": value}}
        return {"key": key, "value": {"stringValue": str(value)}}

    spans = [{
        "traceId": trace_id,
        "spanId": span_id,
        "name": "release-gate.audit",
        "kind": 1,
        "startTimeUnixNano": str(now_ns - 1_000_000),
        "endTimeUnixNano": str(now_ns),
        "attributes": [
            attr("release_gate.score", score, "doubleValue"),
            attr("release_gate.decision", decision),
            attr("release_gate.repo", repo_name),
            attr("release_gate.safeguards_passing", safeguards_passing, "intValue"),
            attr("release_gate.code_risks", len(code_risks), "intValue"),
        ],
        "status": {"code": 1},
    }]

    payload = {
        "resourceSpans": [{
            "resource": {
                "attributes": [attr("service.name", "release-gate")]
            },
            "scopeSpans": [{
                "scope": {"name": "release-gate", "version": "0.1.0"},
                "spans": spans,
            }],
        }]
    }

    # Normalize endpoint
    if not endpoint.startswith("http"):
        endpoint = "http://" + endpoint
    if not endpoint.endswith("/v1/traces"):
        endpoint = endpoint.rstrip("/") + "/v1/traces"

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def dispatch_notify(report: Dict[str, Any], target: Optional[str] = None) -> None:
    """Parse the target URL scheme and dispatch to the right notification function.

    Falls back to environment variables when target is None.
    """
    dispatched = False

    if target is not None:
        parsed = urllib.parse.urlparse(target)
        scheme = parsed.scheme.lower()

        if scheme == "slack":
            # Reconstruct as https://
            webhook_url = "https://" + parsed.netloc + parsed.path
            if parsed.query:
                webhook_url += "?" + parsed.query
            notify_slack(report, webhook_url)
            dispatched = True

        elif scheme == "datadog":
            qs = urllib.parse.parse_qs(parsed.query)
            api_key = (qs.get("api_key", [None])[0] or os.environ.get("RELEASE_GATE_DATADOG_API_KEY", ""))
            site = parsed.netloc if parsed.netloc else "datadoghq.com"
            notify_datadog(report, api_key, site)
            dispatched = True

        elif scheme == "otlp":
            endpoint = "http://" + parsed.netloc + parsed.path
            notify_otlp(report, endpoint)
            dispatched = True

        elif scheme == "file":
            path = parsed.netloc + parsed.path
            with open(path, "w") as f:
                json.dump(report, f, indent=2)
            dispatched = True

        else:
            raise ValueError(f"Unknown notify scheme: {scheme!r}. Supported: slack, datadog, otlp, file")

    if not dispatched:
        # Fall back to environment variables
        slack_webhook = os.environ.get("RELEASE_GATE_SLACK_WEBHOOK")
        if slack_webhook and (target is None or "slack" in (target or "")):
            notify_slack(report, slack_webhook)

        dd_api_key = os.environ.get("RELEASE_GATE_DATADOG_API_KEY")
        if dd_api_key and (target is None or "datadog" in (target or "")):
            notify_datadog(report, dd_api_key)

        otel_endpoint = os.environ.get("RELEASE_GATE_OTEL_ENDPOINT")
        if otel_endpoint and (target is None or "otlp" in (target or "")):
            notify_otlp(report, otel_endpoint)
