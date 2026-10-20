# What I measured

Seven things that broke, and two about asking the model to behave. All of it is behind the talk *"Filter What the LLM Reads"* (AWS Community Day Hong Kong, 2026-10-24).

Back to the [README](../README.md).

All measured in **us-west-2**, September–October 2026, against AgentCore
Gateway with a Bedrock Managed Knowledge Base holding 30 documents
(15 `clearance=public`, 15 `clearance=staff`), two Cognito groups
(`hr-manager`, `contractor`). The data-plane results were repeated in
`ap-northeast-1` with the same corpus and matched on all twelve sets.

**1. A single Cedar permit is not access control.**
With the policy engine in `ENFORCE` and zero policies, both roles get
`DENY — No policy applies to the request (denied by default)`. Add one
`permit` for `managedkb___Retrieve` and both roles get 5 documents — including
the 2 `staff` documents, to the contractor. Cedar decides *whether the tool
may be called*. It does not decide *what the tool may read*.

**2. Removing a permit makes the tool vanish, and logs nothing.**
`PartiallyAuthorizeActions` filters `tools/list`. The denied tool is simply
absent from the list. The agent then has no tool for the job and says so in
prose, or calls a tool that does not exist. Either way the decision log
contains no line for it: the narrowing happens at list time and is not
recorded as a decision. You cannot tell "the policy is working" from
"the policy deleted a tool you needed" by reading the log.

**3. Adding a tool makes the interceptor pass it through, silently.**
The natural shape is `if tool.endswith(A) / elif endswith(B) / else: pass`.
Attach a third tool to the Gateway later and its arguments reach the data
layer untouched, with HTTP 200 and no error anywhere.

Both versions were deployed and measured. Calling an unhandled tool name as
`contractor`:

| | HTTP | interceptor log |
|---|---|---|
| `else: pass` | **200** | `ROLE contractor` → `PASSTHROUGH tool=kbtools___unknown_tool` |
| `KNOWN_SUFFIXES` + raise | **500** | `ROLE contractor` → `[ERROR] RuntimeError: interceptor has no constraint for tool 'kbtools___unknown_tool'` |

A handled tool behaves identically under both, injecting the same filter, so
the only difference is the refusal. The 500 comes from the raise, not from the
Gateway: with `else: pass` the same call returns HTTP 200 and the error only
appears as JSON-RPC `-32602 Unknown tool`.

One honest limitation: the caller sees `An internal error occurred. Please
retry later.` It fails closed, but it does not say why. If you need a
meaningful error, return a transformed request that the target will reject
with a message you control, rather than raising.

**4. Swallowing one exception re-opens the door, at 200.**
In a RESPONSE interceptor that drops out-of-role documents, a
`except json.JSONDecodeError: print(...)` on the parse of the KB payload
means the unfiltered response continues on its way. The caller sees 200 and
the right shape. `audit.py` check 2 found exactly this in my own code.

**5. The Gateway is not in the path unless you put it there.**
Any principal holding `bedrock:Retrieve` on the Knowledge Base reads it
directly — no Gateway, no policy engine, no interceptor. A resource policy on
the KB that denies every principal except the Gateway's execution role closes
it. The same policy also covers `AgenticRetrieveStream`, which is a separate
API and worth checking separately.

**6. The cost is the Lambda round trip, not your code.**
Adding the interceptor costs +145 ms at p50 and +173 ms at p95 (50 runs each,
after 5 warmups). But the handler itself runs in **2.4 ms**. The other 142 ms
is the Gateway invoking Lambda. Writing a faster interceptor will not help.
Cold start adds 87.6 ms (p95 94.9, n=8) — less than the warm overhead. At 20
concurrent calls, end-to-end p50 was 1061 ms against 1166 ms at 1 concurrent:
no degradation, and only one or two new execution environments were created,
because a 2 ms invocation reuses the one it has.

**7. Revoking access does not stop an issued token.**
I took one `hr-manager` token and kept using it while stripping the account:
removed it from the group, forced a global sign-out, then disabled the user.
**All three times the same token still returned 5 `staff` documents.** Only
requesting a *new* token failed. The access token's lifetime was 60 minutes,
so for up to an hour after you revoke someone, they keep reading. This is how
stateless JWTs work, not an AgentCore defect — but the interceptor reads
`cognito:groups` from the token, so your authorisation is as fresh as that
token and no fresher. Shorten the lifetime, or query the IdP from the
interceptor and accept the round trip you just saw costs more than your code.

### Two more, on asking the model to behave

**Never pass the role as a tool argument.** Add a required `user_role`
argument and ask an ordinary question — no attack, no prompt injection. Over
18 runs while logged in as `contractor`, the model wrote `employee` 14 times
and `一般社員` 4 times. It never once wrote `contractor`. Make the argument
optional and all 10 runs left it `null`. The model does not know your role
and will not leave the field alone. Overwrite it; do not validate it.

**Filtering after retrieval costs you answers.** A RESPONSE interceptor that
drops `staff` documents competes with top-k. A contractor asking for engineer
salary bands gets:

| k | filter before | drop after |
|---|---|---|
| 1 | 1 doc | **0** |
| 3 | 3 docs | **0** |
| 5 | 5 docs | **0** |

The entire top-5 is `staff`, so raising k changes nothing. With a 4-document
corpus the gap was 3 against 1; at 30 documents it is 5 against 0.
**The bigger the index, the worse post-filtering gets.** And those `staff`
documents crossed the trust boundary before being thrown away.

## What these numbers are not

Being straight about the limits, because they bound what you should take away.

- **Single account, single Knowledge Base, 30 documents.** A real corpus is
  larger still. The direction holds — post-filtering got worse going from 4 to
  30 — but the size of the effect will differ.
- **Data-plane behaviour was measured in two regions and matched.** The same
  30-document KB in `us-west-2` and `ap-northeast-1` returned identical counts
  for raw, filter-before and drop-after at k = 1, 3 and 5: twelve sets, no
  difference. The *validation* layer was checked in three, adding `us-east-1`:
  the `AgenticRetrieveStream` override allowlist is identical
  (`$.userContext` accepted; `$.messages`, `$.retrievers` and
  `$.agenticRetrieveConfiguration.maxAgentIteration` rejected as
  "not a recognized override").
- **Model behaviour was measured on `us.anthropic.claude-sonnet-4-6` and
  `us.amazon.nova-2-lite-v1:0`.** The role-fabrication counts above are from
  18 and 10 runs respectively — enough to show it is not a fluke, not enough
  to be a rate. A different model will produce different wrong values, not
  a correct one.
- **AgentCore moves.** Two things I recorded in August were already stale by
  October: administrator-set `parameterValues` are no longer overwritten by
  the model, and the Agentic path does accept an administrator-fixed filter.
  Re-measure before you rely on any of this.
