"""Pull Resolver query logs, VPC Flow Logs and the stranger bucket for the experiment window.

    python -m harness.collect            # waits until log counts stop changing, then writes results/logs/*
"""

import json
import time

from .common import RAW_SESSIONS, RESULTS, client, log, outputs, read_jsonl

LOGS_DIR = RESULTS / "logs"
SETTLE_POLL_S = 90
MIN_WAIT_AFTER_LAST_S = 600  # Resolver and Flow Logs deliver with a lag of several minutes

# Logs Insights queries for the global checks. Copied verbatim into README.
FLOW_PARSE = ('parse @message "* * * * * * * * * * * * * *" as version, account, eni, srcaddr, dstaddr, '
              'srcport, dstport, protocol, packets, bytes, start, end, action, logstatus')
Q_FLOW_TO_RESOLVER = (FLOW_PARSE + ' | filter dstaddr = "{resolver_ip}" or dstaddr = "169.254.169.253" '
                      'or srcaddr = "{resolver_ip}" or srcaddr = "169.254.169.253" or dstport = "53" or srcport = "53" '
                      '| stats count() as records')
Q_FLOW_CONTROL = FLOW_PARSE + ' | filter dstport = "443" | stats count() as records, count_distinct(dstaddr) as dsts'
Q_RESOLVER_CANARY = ('fields @timestamp, query_name, rcode, firewall_rule_action '
                     '| filter query_name like /(?i)pumpkin/ | stats count() as records')


def _pull(group, start, end):
    cw = client("logs")
    kwargs = {"logGroupName": group, "startTime": int(start * 1000), "endTime": int(end * 1000)}
    events = []
    for page in cw.get_paginator("filter_log_events").paginate(**kwargs):
        events.extend(page["events"])
    return events


def pull_resolver(start, end):
    events = _pull(outputs()["QueryLogGroup"], start, end)
    return [json.loads(e["message"]) for e in events if e["message"].lstrip().startswith("{")]


def pull_flow(start, end):
    keys = ["version", "account", "eni", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
            "packets", "bytes", "start", "end", "action", "logstatus"]
    return [dict(zip(keys, e["message"].split())) for e in _pull(outputs()["FlowLogGroup"], start, end)]


def insights(group, query, start, end):
    cw = client("logs")
    qid = cw.start_query(logGroupName=group, startTime=int(start), endTime=int(end), queryString=query)["queryId"]
    while True:
        r = cw.get_query_results(queryId=qid)
        if r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            return r["status"], [{f["field"]: f["value"] for f in row} for row in r["results"]]
        time.sleep(2)


def resolver_ip():
    cidr = outputs()["VpcCidr"].split("/")[0].split(".")
    return ".".join(cidr[:3] + [str(int(cidr[3]) + 2)])


def stranger_objects():
    s3, bucket = client("s3"), outputs()["StrangerBucket"]
    objs = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for o in page.get("Versions", []):
            if o["Key"].startswith("probe/"):
                continue
            body = s3.get_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])["Body"].read()
            objs.append({"key": o["Key"], "version_id": o["VersionId"], "last_modified": o["LastModified"].timestamp(),
                         "body": body.decode("utf-8", "replace")})
    return objs


def window():
    sessions = read_jsonl(RAW_SESSIONS)
    return min(s["t_start"] for s in sessions) - 120, max(s["t_end"] for s in sessions) + 900, sessions


def main():
    start, end, sessions = window()
    last = max(s["t_end"] for s in sessions)
    wait = MIN_WAIT_AFTER_LAST_S - (time.time() - last)
    if wait > 0:
        log(f"waiting {int(wait)}s for log delivery after the last session")
        time.sleep(wait)
    prev = None
    while True:
        resolver, flow = pull_resolver(start, end), pull_flow(start, end)
        counts = (len(resolver), len(flow))
        log(f"resolver={counts[0]} flow={counts[1]}")
        if counts == prev:
            break
        prev = counts
        time.sleep(SETTLE_POLL_S)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    (LOGS_DIR / "resolver.jsonl").write_text("".join(json.dumps(r) + "\n" for r in resolver))
    (LOGS_DIR / "flow.jsonl").write_text("".join(json.dumps(r) + "\n" for r in flow))
    objs = stranger_objects()
    (LOGS_DIR / "stranger_objects.jsonl").write_text("".join(json.dumps(o) + "\n" for o in objs))

    out, ip = outputs(), resolver_ip()
    checks = {}
    for name, group, q in [
        ("flow_to_resolver", out["FlowLogGroup"], Q_FLOW_TO_RESOLVER.format(resolver_ip=ip)),
        ("flow_control_443", out["FlowLogGroup"], Q_FLOW_CONTROL),
        ("resolver_canary", out["QueryLogGroup"], Q_RESOLVER_CANARY),
    ]:
        status, rows = insights(group, q, start, end)
        checks[name] = {"query": q, "status": status, "rows": rows}
        log(f"{name}: {status} {rows}")
    checks["window"] = {"start": start, "end": end, "resolver_ip": ip}
    (LOGS_DIR / "global_checks.json").write_text(json.dumps(checks, indent=2))
    log(f"stranger objects: {len(objs)}")


if __name__ == "__main__":
    main()
