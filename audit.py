#!/usr/bin/env python3
"""Five checks on an AgentCore Gateway in front of a Bedrock Knowledge Base.

Companion to the talk "Filter What the LLM Reads: RAG Governance with
AgentCore Gateway" (AWS Community Day Hong Kong, 2026-10-24).

The talk's point is that the three ways this setup fails are all quiet: they
return HTTP 200 and leave nothing useful in the logs. This script looks for
them in your own account.

  1. Which tools the Gateway actually exposes
  2. Whether the REQUEST interceptor's code mentions every one of them
  3. Whether the decision log contains a single DENY
  4. Whether the Knowledge Base has a resource policy
  5. Whether the interceptor code swallows exceptions

Read-only. It creates nothing and deletes nothing.

Usage:
    python audit.py --gateway <gateway-id> --region us-west-2 \
                    [--kb <kb-id>] [--token <JWT>] [--days 30]

    --token makes check 1 call tools/list for real (any token your Gateway's
    inbound authorizer accepts). Without it, checks 1 and 2 fall back to
    deriving tool names from the target definitions, which is close but not
    identical: the policy engine may be hiding tools from tools/list, and
    that is exactly finding 2 (see docs/findings.md).

IAM permissions needed, all read-only:
    bedrock-agentcore:GetGateway, ListGatewayTargets, GetGatewayTarget
    lambda:GetFunction
    logs:FilterLogEvents
    bedrock:GetKnowledgeBase, bedrock:GetResourcePolicy
"""

import argparse
import io
import json
import re
import sys
import time
import urllib.request
import zipfile
from collections import Counter

import boto3

OK, NG, INFO = "  ok  ", "  NG  ", "  --  "

# `except ...:` whose body only logs or passes. The response then continues
# on its way, unfiltered, with a 200.
SWALLOW = re.compile(
    r"^(\s*)except\b[^\n]*:\s*\n"          # except line
    r"(?:\s*#[^\n]*\n|\s*\n)*"             # comments / blank lines
    r"\s*(?:pass\b|print\(|logger\.|logging\.|\.\.\.)",
    re.MULTILINE)


def tools_from_list(url, token):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream",
                 "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read().decode()
    for line in raw.splitlines():                     # SSE or plain JSON
        if line.startswith("data:"):
            raw = line[5:].strip()
            break
    return [t["name"] for t in json.loads(raw)["result"]["tools"]]


def tools_from_targets(ac, gid):
    names = []
    for t in ac.list_gateway_targets(gatewayIdentifier=gid).get("items", []):
        d = ac.get_gateway_target(gatewayIdentifier=gid, targetId=t["targetId"])
        mcp = (d.get("targetConfiguration") or {}).get("mcp", {})
        if "connector" in mcp:
            for c in mcp["connector"].get("configurations", []):
                names.append(f"{d['name']}___{c['name']}")
        elif "lambda" in mcp:
            for s in mcp["lambda"].get("toolSchema", {}).get("inlinePayload", []):
                names.append(f"{d['name']}___{s['name']}")
    return names


def lambda_source(lam, arn):
    """Download the function's code and concatenate its .py files."""
    loc = lam.get_function(FunctionName=arn)["Code"].get("Location")
    if not loc:
        return None                                   # image-based function
    with urllib.request.urlopen(loc, timeout=60) as r:
        blob = r.read()
    out = []
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for n in sorted(z.namelist()):
            if n.endswith(".py"):
                out.append(z.read(n).decode("utf-8", "replace"))
    return "\n".join(out)


def check_interceptors(gw, lam, tools):
    icfg = gw.get("interceptorConfigurations") or []
    print(f"\n2. Interceptors ({len(icfg)})")
    if not icfg:
        print(f"{NG} none attached -- nothing rewrites the arguments the model sent")
        return
    for c in icfg:
        arn = c["interceptor"]["lambda"]["arn"]
        name = arn.split(":")[-1]
        points = ",".join(c.get("interceptionPoints", []))
        src = lambda_source(lam, arn)
        if src is None:
            print(f"{INFO} {name} ({points}): code not downloadable, inspect by hand")
            continue

        missing = [t for t in tools
                   if t not in src and t.split("___")[-1] not in src]
        if missing:
            print(f"{NG} {name} ({points}) never mentions: {', '.join(missing)}")
            print("        If that is deliberate, say so in a comment. If it is not,")
            print("        those calls pass through unconstrained with a 200.")
        else:
            print(f"{OK} {name} ({points}) mentions every exposed tool")

        swallows = [src[:m.start()].count("\n") + 1 for m in SWALLOW.finditer(src)]
        if swallows:
            print(f"{NG}   swallowed exceptions at line(s) "
                  f"{', '.join(map(str, swallows))} -- on that path the response")
            print("        continues unfiltered, and the caller still sees 200")
        else:
            print(f"{OK}   no exception is logged-and-forgotten")


def check_log(logs, gid, days):
    print(f"\n3. Policy decisions, last {days} days")
    grp = ("/aws/vendedlogs/bedrock-agentcore/gateway/APPLICATION_LOGS/" + gid)
    try:
        ev = logs.filter_log_events(
            logGroupName=grp,
            startTime=int(time.time() * 1000) - days * 86400 * 1000)["events"]
    except logs.exceptions.ResourceNotFoundException:
        print(f"{NG} no log delivery configured for this Gateway")
        print(f"        expected group: {grp}")
        return
    if not ev:
        print(f"{NG} the log group exists but holds nothing in this window")
        print("        either the Gateway is idle, or delivery stopped")
        return

    newest = time.strftime("%Y-%m-%d %H:%M", time.localtime(ev[-1]["timestamp"] / 1000))
    dec = Counter()
    for e in ev:
        try:
            dec[json.loads(e["message"])["body"]["policy"]["decision"]] += 1
        except (KeyError, ValueError, TypeError):
            continue
    print(f"{INFO} {len(ev)} log events, newest {newest}")
    if not dec:
        print(f"{NG} not one policy decision recorded")
        print("        no policy engine attached, or no tools/call traffic yet")
    elif "DENY" not in dec:
        print(f"{NG} {dec.get('ALLOW', 0)} ALLOW, 0 DENY")
        print("        a policy that has never refused anything is untested")
    else:
        print(f"{OK} {dict(dec)}")
    print(f"{INFO} tools/list narrowing is not recorded here at all --")
    print("        a tool that vanished from the list leaves no decision line")


def check_kb_policy(region, kb):
    print("\n4. Knowledge Base resource policy")
    if not kb:
        print(f"{INFO} pass --kb <id> to check this")
        return
    ba = boto3.client("bedrock-agent", region_name=region)
    arn = ba.get_knowledge_base(knowledgeBaseId=kb)["knowledgeBase"]["knowledgeBaseArn"]
    try:
        pol = json.loads(ba.get_resource_policy(resourceArn=arn)["policy"])
    except Exception as e:                            # noqa: BLE001 -- several types
        print(f"{NG} none ({type(e).__name__})")
        print("        any principal holding bedrock:Retrieve reads the KB directly,")
        print("        and the Gateway, the policy engine and the interceptor are")
        print("        all simply not in the path")
        return
    print(f"{OK} present")
    for st in pol.get("Statement", []):
        print(f"      {st.get('Effect')} {st.get('Action')} "
              f"{json.dumps(st.get('Condition', {}), ensure_ascii=False)[:120]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", required=True, help="gateway id, not the ARN")
    ap.add_argument("--region", default="us-west-2")
    ap.add_argument("--kb", help="knowledge base id, for check 4")
    ap.add_argument("--token", help="JWT, to call tools/list for real")
    ap.add_argument("--days", type=int, default=30)
    a = ap.parse_args()

    ac = boto3.client("bedrock-agentcore-control", region_name=a.region)
    gw = ac.get_gateway(gatewayIdentifier=a.gateway)
    pe = (gw.get("policyEngineConfiguration") or {}).get("mode", "none")
    print(f"Gateway {gw['name']} ({a.gateway}) in {a.region}")
    print(f"  inbound auth: {gw.get('authorizerType')}   policy engine: {pe}\n")

    if a.token:
        tools, how = tools_from_list(gw["gatewayUrl"], a.token), "tools/list"
    else:
        tools, how = tools_from_targets(ac, a.gateway), "derived from targets"
    print(f"1. Exposed tools ({how})")
    for t in tools:
        print(f"     {t}")
    if not tools:
        print(f"{NG} none -- check your token's permits, or the targets")

    check_interceptors(gw, boto3.client("lambda", region_name=a.region), tools)
    check_log(boto3.client("logs", region_name=a.region), a.gateway, a.days)
    check_kb_policy(a.region, a.kb)

    print("\nFinding nothing is not evidence that nothing is wrong.")
    print("All three failures in the talk return HTTP 200.")


if __name__ == "__main__":
    sys.exit(main())
