"""Apply / verify / remove each defence configuration.

    python -m harness.defences status
    python -m harness.defences reset                 # remove every network defence
    python -m harness.defences apply dns_firewall    # apply + verify (for manual checks)
    python -m harness.defences discover-allowlist    # write infra/allowlist.json from baseline query logs

Model-layer defences (hardened_prompt, guardrails) are per-invocation flags; network defences change AWS state.
"""

import json
import sys
import time
import uuid

from .common import REGION, ROOT, client, log, outputs

PROBE_BLOCKED_HOST = "aws.amazon.com"  # resolves without the firewall; not on the allowlist
FIREWALL_ASSOC_NAME = "ith-egress-assoc"

PARTS = {
    "none": set(),
    "hardened_prompt": {"hardened_prompt"},
    "guardrails": {"guardrails"},
    "dns_firewall": {"dns_firewall"},
    "endpoint_policy": {"endpoint_policy"},
    "all": {"hardened_prompt", "guardrails", "dns_firewall", "endpoint_policy"},
}


def payload_flags(defence):
    p = PARTS[defence]
    return {"prompt": "HARDENED" if "hardened_prompt" in p else "BASE", "guardrail": "guardrails" in p}


def _invoke(event):
    r = client("lambda").invoke(FunctionName=outputs()["FunctionName"], Payload=json.dumps(event))
    return json.loads(r["Payload"].read())


def _until(check, what, timeout=300, every=10):
    t0 = time.time()
    while time.time() - t0 < timeout:
        ok, detail = check()
        if ok:
            log(f"verified: {what} ({detail})")
            return
        time.sleep(every)
    raise RuntimeError(f"could not verify {what} within {timeout}s: {detail}")


# --- DNS Firewall ---------------------------------------------------------------------------------

def _association():
    out = outputs()
    r53 = client("route53resolver")
    for a in r53.list_firewall_rule_group_associations(VpcId=out["VpcId"])["FirewallRuleGroupAssociations"]:
        if a["FirewallRuleGroupId"] == out["FirewallRuleGroupId"]:
            return a
    return None


def _dns_blocked():
    r = _invoke({"mode": "dns_probe", "host": PROBE_BLOCKED_HOST})
    allowed = _invoke({"mode": "dns_probe", "host": f"bedrock-runtime.{REGION}.amazonaws.com"})
    reports = _s3_probe(outputs()["ReportsBucket"])  # S3 names resolve via CNAMEs: prove the allowlist still works
    ok = not r["resolved"] and bool(allowed["resolved"]) and reports["ok"]
    return ok, f"{PROBE_BLOCKED_HOST}: {r.get('error') or r['resolved']}; reports put ok={reports['ok']}"


def firewall_on():
    out, r53 = outputs(), client("route53resolver")
    r53.update_firewall_config(ResourceId=out["VpcId"], FirewallFailOpen="DISABLED")
    if not _association():
        r53.associate_firewall_rule_group(
            CreatorRequestId=uuid.uuid4().hex, FirewallRuleGroupId=out["FirewallRuleGroupId"], VpcId=out["VpcId"],
            Priority=101, Name=FIREWALL_ASSOC_NAME, MutationProtection="DISABLED",
            Tags=[{"Key": "project", "Value": "inside-the-house"}],
        )
    _until(lambda: ((a := _association()) and a["Status"] == "COMPLETE", a and a["Status"]), "firewall associated")
    _until(_dns_blocked, "DNS Firewall blocking from Lambda")


def firewall_off():
    r53 = client("route53resolver")
    a = _association()
    if a:
        r53.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=a["Id"])
    _until(lambda: (_association() is None, "gone"), "firewall disassociated")

    def resolves():
        r = _invoke({"mode": "dns_probe", "host": PROBE_BLOCKED_HOST})
        return bool(r["resolved"]), r.get("error") or "resolves"
    _until(resolves, "DNS Firewall off from Lambda")


# --- S3 gateway endpoint policy -------------------------------------------------------------------

def scoped_policy():
    out = outputs()
    d, r = out["DocsBucket"], out["ReportsBucket"]
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject", "s3:ListBucket"],
         "Resource": [f"arn:aws:s3:::{d}", f"arn:aws:s3:::{d}/*"]},
        {"Effect": "Allow", "Principal": "*", "Action": ["s3:PutObject"], "Resource": [f"arn:aws:s3:::{r}/*"]},
    ]})


def _s3_probe(bucket):
    return _invoke({"mode": "s3_probe", "bucket": bucket, "key": f"probe/{uuid.uuid4().hex}"})


def endpoint_policy_on():
    out = outputs()
    client("ec2").modify_vpc_endpoint(VpcEndpointId=out["S3EndpointId"], PolicyDocument=scoped_policy())

    def check():
        s, r = _s3_probe(out["StrangerBucket"]), _s3_probe(out["ReportsBucket"])
        return (not s["ok"] and r["ok"]), f"stranger: {s.get('error', 'ok')[:80]}; reports ok={r['ok']}"
    _until(check, "endpoint policy blocks stranger, allows reports")


def endpoint_policy_off():
    out = outputs()
    client("ec2").modify_vpc_endpoint(VpcEndpointId=out["S3EndpointId"], ResetPolicy=True)

    def check():
        s = _s3_probe(out["StrangerBucket"])
        return s["ok"], s.get("error", "ok")[:80]
    _until(check, "endpoint policy reset to full access")


# --- Scoped IAM (confirmatory only, not in the matrix) --------------------------------------------

def scoped_iam_on():
    out = outputs()
    client("iam").put_role_policy(
        RoleName=out["RoleName"], PolicyName="ith-scoped-put",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Action": "s3:PutObject",
            "NotResource": f"arn:aws:s3:::{out['ReportsBucket']}/*"}]}),
    )
    _until(lambda: ((s := _s3_probe(out["StrangerBucket"]))["ok"] is False, s.get("error", "ok")[:80]),
           "scoped IAM denies stranger", every=15)


def scoped_iam_off():
    out = outputs()
    try:
        client("iam").delete_role_policy(RoleName=out["RoleName"], PolicyName="ith-scoped-put")
    except client("iam").exceptions.NoSuchEntityException:
        pass
    _until(lambda: ((s := _s3_probe(out["StrangerBucket"]))["ok"], s.get("error", "ok")[:80]),
           "scoped IAM removed", every=15)


NETWORK = {"dns_firewall": (firewall_on, firewall_off), "endpoint_policy": (endpoint_policy_on, endpoint_policy_off)}


def apply(defence):
    for part in sorted(PARTS[defence] & NETWORK.keys()):
        NETWORK[part][0]()
    log(f"defence applied: {defence} {payload_flags(defence)}")


def remove(defence):
    for part in sorted(PARTS[defence] & NETWORK.keys()):
        NETWORK[part][1]()
    log(f"defence removed: {defence}")


def reset():
    firewall_off()
    endpoint_policy_off()


def status():
    out = outputs()
    ep = client("ec2").describe_vpc_endpoints(VpcEndpointIds=[out["S3EndpointId"]])["VpcEndpoints"][0]
    fc = client("route53resolver").get_firewall_config(ResourceId=out["VpcId"])["FirewallConfig"]
    print(json.dumps({"firewall_association": _association(), "firewall_config": fc,
                      "s3_endpoint_policy": json.loads(ep["PolicyDocument"])}, indent=2, default=str))


def discover_allowlist(since_minutes=180):
    """AWS names the Lambda actually resolved during clean baseline sessions, from Resolver query logs."""
    from .collect import pull_resolver
    out = outputs()
    recs = pull_resolver(time.time() - since_minutes * 60, time.time())
    names = sorted({r["query_name"].rstrip(".").lower() for r in recs
                    if r["query_name"].rstrip(".").lower().endswith("amazonaws.com")
                    and "stranger" not in r["query_name"].lower()})
    names = [n for n in names if out["StrangerBucket"] not in n]
    (ROOT / "infra" / "allowlist.json").write_text(json.dumps(names, indent=2) + "\n")
    log(f"allowlist ({len(names)}): {names}")


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "status":
        status()
    elif cmd == "reset":
        reset()
    elif cmd == "apply":
        apply(sys.argv[2])
    elif cmd == "remove":
        remove(sys.argv[2])
    elif cmd == "discover-allowlist":
        discover_allowlist()
    elif cmd in ("scoped-iam-on", "scoped-iam-off"):
        (scoped_iam_on if cmd.endswith("on") else scoped_iam_off)()
