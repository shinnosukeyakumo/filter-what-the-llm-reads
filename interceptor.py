"""A REQUEST interceptor for Amazon Bedrock AgentCore Gateway.

It takes the role from the *verified* token and overwrites the data-layer
constraint on the way in, before the knowledge base is ever read.

Two target shapes are handled:

  <target>___kb_search  (Lambda target)
      Overwrite the `user_role` argument. The Lambda narrows the result.
      This still fetches and then discards, so the one below is preferable.

  <target>___Retrieve   (Bedrock Managed Knowledge Base connector)
      Inject `retrievalConfiguration.managedSearchConfiguration.filter`.
      The KB returns only matching chunks, so nothing is fetched and dropped.

The design rule is the same for both: **overwrite, do not validate.**
Whatever the model sent is replaced with the correct value before it is read.
Validation only tells you a lie arrived; it does not stop the lie from working
when you forget one branch.

This interceptor does not verify the signature itself. The Gateway's inbound
JWT authorizer has already verified it against the IdP's public keys, so
reading the claims is enough. Do not copy this file to a place where that is
not true.

Measured against AgentCore Gateway in us-west-2, September-October 2026.
"""

import base64
import json

# role -> clearance values the role may read
ALLOWED_CLEARANCE = {
    "hr-manager": ["public", "staff"],
    "contractor": ["public"],
}

# An unknown role sees nothing (fail-closed).
#
# Do NOT use an empty list here. The KB rejects it with
#   ValidationException: The filter value must not be empty
# which makes the call fail, and the Gateway does stop the request --
# but that is safety by accident, not by design. A later change that
# catches the exception turns it into an open door.
#
# Use a clearance value that cannot exist, so the filter matches 0 chunks.
DEFAULT_CLEARANCE = ["__no_access__"]

# Tools this interceptor knows how to constrain. Anything else is refused.
#
# This is the part people get wrong. The obvious shape is
#     if tool.endswith("___kb_search"): ...
#     elif tool.endswith("___Retrieve"): ...
#     else: pass          # <-- the request goes through untouched
#
# Adding one more tool to the Gateway later then silently returns an
# unconstrained request, with HTTP 200 and nothing in the logs to read.
# Listing the known suffixes and denying the rest makes that a visible error.
KNOWN_SUFFIXES = ("___kb_search", "___Retrieve")


def _decode_jwt_payload(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _get_header(headers, name):
    """The Gateway lower-cases header names on the way in (measured)."""
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return ""


def _verified_role(request):
    auth = _get_header(request.get("headers", {}), "Authorization")
    if not auth.startswith("Bearer "):
        return "unknown", "-"
    claims = _decode_jwt_payload(auth[len("Bearer "):])
    groups = claims.get("cognito:groups") or []
    return (groups[0] if groups else "unknown"), claims.get("sub", "-")


def _passthrough(body):
    return {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayRequest": {"body": body}}}


def _deny(message):
    """Refuse the request. The Gateway turns a raised error into a failure,
    so the caller gets an error instead of unconstrained data."""
    raise RuntimeError(message)


def lambda_handler(event, context):
    mcp = (event or {}).get("mcp", {})
    request = mcp.get("gatewayRequest", {})
    body = request.get("body", {})

    # tools/list is NOT routed through here in a way you can filter;
    # list-time narrowing is the policy engine's job, and it leaves no
    # decision record of its own. See README, finding 2.
    if body.get("method") != "tools/call":
        return _passthrough(body)

    params = body.setdefault("params", {})
    tool = params.get("name", "")
    arguments = params.setdefault("arguments", {})

    role, sub = _verified_role(request)
    clearance = ALLOWED_CLEARANCE.get(role, DEFAULT_CLEARANCE)
    print(f"ROLE     {role} (sub={sub[:8]}...) -> clearance={clearance}")

    if not tool.endswith(KNOWN_SUFFIXES):
        # Loud on purpose. See KNOWN_SUFFIXES above.
        _deny(f"interceptor has no constraint for tool {tool!r}")

    if tool.endswith("___kb_search"):
        claimed = arguments.get("user_role")
        arguments["user_role"] = role
        print(f"CLAIMED  user_role={json.dumps(claimed)}")
        print(f"INJECTED user_role={json.dumps(role)}")

    elif tool.endswith("___Retrieve"):
        cfg = arguments.setdefault("retrievalConfiguration", {})
        search = cfg.setdefault("managedSearchConfiguration", {})
        claimed = search.get("filter")
        search["filter"] = {"in": {"key": "clearance", "value": clearance}}
        print(f"CLAIMED  filter={json.dumps(claimed)}")
        print(f"INJECTED filter={json.dumps(search['filter'])}")

    return _passthrough(body)
