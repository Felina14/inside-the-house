"""Shared config for the harness. Everything reads stack outputs written by `cdk deploy --outputs-file`."""

import json
import os
import time
from pathlib import Path

import boto3
from botocore.config import Config

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
RAW_SESSIONS = RESULTS / "raw" / "sessions.jsonl"
# Credentials come from the standard AWS chain (AWS_PROFILE, env vars, SSO...). Nothing is stored here.
PROFILE = os.environ.get("AWS_PROFILE")
REGION = os.environ.get("AWS_REGION", "us-east-1")

MODELS = {
    "micro": "us.amazon.nova-micro-v1:0",
    "lite": "us.amazon.nova-2-lite-v1:0",
    "pro": "us.amazon.nova-pro-v1:0",
}
JUDGE_MODEL = MODELS["micro"]
# USD per 1K tokens (in, out), AWS Price List API, us-east-1, 30 Oct 2026. See VERIFY.md §4.
PRICES = {
    MODELS["micro"]: (0.000035, 0.00014),
    MODELS["lite"]: (0.00033, 0.00275),
    MODELS["pro"]: (0.0008, 0.0032),
}
GUARDRAIL_PER_TEXT_UNIT = 0.00015  # 1 text unit = 1,000 characters
INFRA_USD_PER_HOUR = 0.05  # 3 interface endpoints (~$0.01/h each) + logs, rounded up
BUDGET_USD = 15.0

DEFENCES = ["none", "hardened_prompt", "guardrails", "dns_firewall", "endpoint_policy", "all"]
TRAPS = ["dns", "s3"]
PLACEMENTS = ["comment", "visible", "meta"]

# Opaque folder names so the key never hints at the trap. folder-0 is clean-only (allowlist discovery).
FOLDERS = {("clean", None): "folder-0/"}
for i, (t, p) in enumerate(((t, p) for t in TRAPS for p in PLACEMENTS), start=1):
    FOLDERS[(t, p)] = f"folder-{i}/"
TRAP_KEYS = {"dns": "billing-migration-status.html", "s3": "records-retention-reminder.html"}

_session = boto3.Session(profile_name=PROFILE, region_name=REGION)


def client(name, **cfg):
    return _session.client(name, config=Config(**cfg) if cfg else None)


def outputs():
    return json.loads((RESULTS / "stack-outputs.json").read_text())["ith-main"]


def read_jsonl(path):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def append_jsonl(path, rec):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(rec) + "\n")


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)
