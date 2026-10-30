"""Lambda entrypoint. One invocation = one agent session (or a probe), returns the trace.

Event:
  {"mode": "session", "run_id", "model_id", "prompt": "BASE"|"HARDENED", "guardrail": bool, "folder": "<prefix>/"}
  {"mode": "dns_probe", "host"}           -> resolve one name from inside the VPC
  {"mode": "s3_probe", "bucket", "key"}   -> PutObject one small object
"""

import os
import time

import boto3
from strands import Agent
from strands.hooks import AfterModelCallEvent, BeforeToolCallEvent
from strands.models.bedrock import BedrockModel

from prompts import PROMPTS, USER_TASK
from tools import DOCS_BUCKET, make_tools, resolve

MAX_TOOL_TURNS = 6
REPORTS_BUCKET = os.environ["REPORTS_BUCKET"]
GUARDRAIL = (os.environ["GUARDRAIL_ID"], os.environ["GUARDRAIL_VERSION"])
s3 = boto3.client("s3")


def handler(event, _ctx):
    mode = event.get("mode", "session")
    if mode == "dns_probe":
        addrs, err = resolve(event["host"])
        return {"host": event["host"], "resolved": addrs, "error": err}
    if mode == "s3_probe":
        try:
            s3.put_object(Bucket=event["bucket"], Key=event["key"], Body=b"probe")
            return {"ok": True}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}
    return run_session(event)


def run_session(ev):
    run_id = ev["run_id"]
    canary = "PUMPKIN-" + run_id[:8]
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=DOCS_BUCKET, Prefix=ev["folder"])["Contents"]]
    system = PROMPTS[ev["prompt"]].format(
        canary=canary, folder="\n".join(f"- {k}" for k in keys), reports_bucket=REPORTS_BUCKET
    )

    trace = {"run_id": run_id, "canary": canary, "tool_calls": [], "tool_turns": 0, "tool_limit_hit": False}
    model_cfg = {"model_id": ev["model_id"], "max_tokens": 2048, "temperature": 0.7, "streaming": False}
    if ev.get("guardrail"):
        model_cfg.update(
            guardrail_id=GUARDRAIL[0], guardrail_version=GUARDRAIL[1],
            guardrail_trace="enabled", guardrail_latest_message=True,
        )
    agent = Agent(
        model=BedrockModel(**model_cfg),
        system_prompt=system,
        tools=make_tools(trace, GUARDRAIL if ev.get("guardrail") else None),
        callback_handler=None,
    )

    def count_turns(event: AfterModelCallEvent):
        if event.stop_response and event.stop_response.stop_reason == "tool_use":
            trace["tool_turns"] += 1

    def cap_tools(event: BeforeToolCallEvent):
        if trace["tool_turns"] > MAX_TOOL_TURNS:
            trace["tool_limit_hit"] = True
            event.cancel_tool = "Tool limit reached. Do not call any more tools; reply to the user now."

    agent.add_hook(count_turns)
    agent.add_hook(cap_tools)

    t0 = time.time()
    try:
        result = agent(USER_TASK)
        trace["stop_reason"] = result.stop_reason
        trace["final_reply"] = str(result).strip()
        usage = result.metrics.accumulated_usage
    except Exception as e:  # noqa: BLE001 - record, don't crash the matrix
        trace["stop_reason"] = "error"
        trace["error"] = f"{type(e).__name__}: {e}"
        trace["final_reply"] = ""
        usage = agent.event_loop_metrics.accumulated_usage
    trace["latency_ms"] = int((time.time() - t0) * 1000)
    trace["input_tokens"] = usage.get("inputTokens", 0)
    trace["output_tokens"] = usage.get("outputTokens", 0)
    trace["t_start"], trace["t_end"] = round(t0, 3), round(time.time(), 3)
    return trace
