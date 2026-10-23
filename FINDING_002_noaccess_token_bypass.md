# FINDING_002 — API tokens with `basePermissions: no_access` can read account-level resources (members, audit log, token inventory, webhooks, custom roles)

- **Severity proposal**: P2 (Broken Access Control / Sensitive Data Exposure)
- **Target**: app.launchdarkly.com (in scope)
- **Account**: org A (`zeno0+org@bugcrowdninja.com`), account `_id 6ac28fd11c28fb07516cf361`
- **Status**: CONFIRMED, fully reproducible (2026-10-22)

## Summary

An API access token created with `basePermissions: "no_access"` (the strictest
least-privilege mode — "no access except explicitly granted by policy") is able
to **read account-level resources it was never granted**: the full member list
(e-mail addresses, roles, member IDs, lastSeen), the complete audit log (all
account activity incl. other members' actions), the full API token inventory
(names, IDs, roles, lastUsed), the webhook list (target URLs), the custom role
policy documents, and the project list.

Write operations are correctly denied (403), and project-scoped resources
(flags, segments, metrics, environments, project detail) are correctly denied —
the bypass affects the **account-level endpoints only**.

## Impact

Tokens with `basePermissions: no_access` are the intended way to hand a
zero-privilege, explicitly-scoped credential to third parties (CI jobs,
integrations, contractors). Each such token can be used to enumerate:

1. **`/api/v2/members`** — every member's e-mail, role, member `_id`, last-seen timestamp
2. **`/api/v2/auditlog`** (+ per-entry detail) — full account activity history:
   who changed which flag/token/role, when, with member e-mail addresses
3. **`/api/v2/tokens`** — inventory of ALL access tokens: names, `_id`s, roles,
   `lastUsed` timestamps (recon for targeted token attacks; `_id`s are the
   identifiers needed for any future token-focused bug)
4. **`/api/v2/webhooks`** — webhook endpoint URLs (may embed secrets in query strings)
5. **`/api/v2/roles`** — custom role policy documents (security logic disclosure)
6. **`/api/v2/projects`** — project list

The leak defeats the purpose of least-privilege tokens and enables
reconnaissance for follow-on attacks (phishing with real member e-mails,
targeting the most recently used admin tokens, etc.).

## Steps to reproduce (copy-paste)

```bash
# 1. As account owner: create a custom role with NO base permissions
curl -s -X POST "https://app.launchdarkly.com/api/v2/roles" \
  -H "Cookie: ldso=<owner session>" -H "Content-Type: application/json" \
  -d '{"key":"zeno-flag-viewer-noaccess","name":"scoped","description":"scoped",
       "policy":[{"effect":"allow","resources":["proj/default:env/test:flag/zeno-webhook-fixture"],"actions":["*"]}],
       "basePermissions":"no_access"}'
# -> 201

# 2. Create an API token with that custom role (via app UI:
#    /settings/authorization/tokens -> Create token -> Role: Custom -> pick the role)

# 3. Use ONLY that token (zero effective permissions):
TOK="api-<the token value>"

curl -s "https://app.launchdarkly.com/api/v2/members" -H "Authorization: $TOK"
# -> 200, full member list (email/role/_id/lastSeen) — EXPECTED 403

curl -s "https://app.launchdarkly.com/api/v2/auditlog?limit=10" -H "Authorization: $TOK"
# -> 200, complete audit trail — EXPECTED 403

curl -s "https://app.launchdarkly.com/api/v2/tokens?limit=20" -H "Authorization: $TOK"
# -> 200, all access tokens (names, _ids, roles, lastUsed) — EXPECTED 403

curl -s "https://app.launchdarkly.com/api/v2/webhooks" -H "Authorization: $TOK"
curl -s "https://app.launchdarkly.com/api/v2/roles" -H "Authorization: $TOK"
curl -s "https://app.launchdarkly.com/api/v2/projects" -H "Authorization: $TOK"
# -> all 200 — EXPECTED 403
```

## Control results (proving the token really has no permissions)

| Endpoint | no_access token | Expected |
|---|---|---|
| GET /api/v2/flags/default/{in-policy flag} | **403** (even the policy grant fails to apply) | 200 |
| GET /api/v2/flags/default/{other flag} | 403 ✓ | 403 |
| GET /api/v2/projects/default | 403 ✓ | 403 |
| GET /api/v2/projects/default/environments (SDK keys) | 403 ✓ | 403 |
| GET /api/v2/segments/default | 403 ✓ | 403 |
| GET /api/v2/metrics/default | 403 ✓ | 403 |
| GET /api/v2/teams | 403 ✓ | 403 |
| **GET /api/v2/members** | **200 — BYPASS** | 403 |
| **GET /api/v2/members/{id}** | **200 — BYPASS** | 403 |
| **GET /api/v2/auditlog + /{id}** | **200 — BYPASS** | 403 |
| **GET /api/v2/tokens** | **200 — BYPASS** | 403 |
| **GET /api/v2/webhooks + /{id}** | **200 — BYPASS** | 403 |
| **GET /api/v2/roles + /{key}** | **200 — BYPASS** | 403 |
| **GET /api/v2/projects (list)** | **200 — BYPASS** | 403 |
| PATCH member role | 403 ✓ (deny) | 403 |
| PATCH token | 403 ✓ (deny) | 403 |
| POST webhook | 403 ✓ (deny) | 403 |

Sample leaked data (this account):

```
member: zeno0+org@bugcrowdninja.com | role: owner | id: 6ac28fd11c28fb07516cf363
tokens: idor-probe-token (6ad9fbdd…), zeno-scoped-ui (6ada110…), … with lastUsed timestamps
audit:  "[zeno test](mailto:zeno0+org@…) created the role [zeno flag viewer noaccess]…"
```

## Additional anomaly observed (same area, lower confidence)

While testing a custom role with the DEFAULT `basePermissions: "reader"`, a
policy granting only `proj/default:env/test:flag/zeno-webhook-fixture`:
- the flag **list** endpoint returned all flags (expected for reader base), but
- flags whose variations have **mixed JSON types** (e.g. `[{"value":"s"},{"value":false}]`)
  disappeared from both list and item reads for that token (404), while
  boolean-variation flags were all readable — suggesting the token-policy
  filter implementation drops flags with non-uniform variation types rather
  than evaluating policy correctly. Not fully root-caused; flag-level READ
  enforcement for custom-role tokens looks unreliable in this version.


## R5 update (2026-10-23) — expanded bypass surface (re-verified with fresh no_access token)

Additional account-level GET endpoints that also return **200 under the same
zero-privilege token** (beyond the original matrix):

| Endpoint | Leaks |
|---|---|
| `GET /api/v2/account` | org name, `requireMfa`, session config (duration/refresh) |
| `GET /api/v2/account/relay-auto-configs` + `/{id}` | relay proxy configs **incl. full policy documents** (`proj/*:env/*` actions `*`) and creator identity (name/email/role) |
| `GET /api/v2/usage` + `/usage/streams[/server|/client]`, `/usage/data-export-events`, `/usage/warehouse-export` | account usage series/metadata |
| `GET /api/v2/code-refs/repositories` | code-refs repository inventory |
| `GET /internal/entitlements/release-guardian` | internal entitlement state (`{"state":"enabled",...}`) — also notable as the first `/internal/*` endpoint reachable by a pure API token |

Write verbs on this endpoint class remain correctly denied (403 `createCodeRefsRepository`,
`createAccessToken`, `createWebhook`, `updateAccessTokenName`) — the bypass is
**strictly read-only**. Cross-org isolation is unaffected (this is intra-account
least-privilege failure only).

S3 files behind segment exports are properly presigned (SigV4, 10-min expiry);
bucket listing denied. Segment exports are org-fenced (uniform 500, no oracle).


## R6 update (2026-10-23) — WEBHOOK SIGNING SECRET disclosure (impact upgrade)

`GET /api/v2/webhooks/{id}` under the zero-privilege token returns the webhook's
HMAC signing secret in the `secret` field (re-verified twice with fresh
no_access tokens):

```json
{"_id":"6adaa3b0db707e0735880977","name":"zeno-sign-wh-b",
 "url":"https://example.com/zx-b","secret":"44dd62dafded4ec4a6ea7f74dc0712f4","on":false}
```

The same response leaks the webhook target URL. LaunchDarkly signs deliveries
with `X-LD-Signature: sha256=HMAC-SHA256(secret, body)` — a zero-privilege
token holder can therefore **forge validly-signed LaunchDarkly webhook events**
against any endpoint configured in the account (CI/CD auto-deploy hooks,
incident tooling, chat bots that verify LD signatures).

Baseline comparison: the built-in `reader` role also sees the secret (LD models
reader as "view everything"), which makes the correct framing: **a token whose
effective permissions are explicitly NOTHING still discloses a signing secret
and the full account recon surface**. List view (`GET /api/v2/webhooks`) does
not include the secret — only the detail GET does.

Cross-org scoping check (re-verified R6): the no_access token's account-level
reads are account-scoped — cross-org member/webhook IDs return 404; auditlog /
tokens / roles / relay / account responses contain only the token's own org
data. This is an intra-account least-privilege failure (P2), not cross-org (P1).

## Notes

- Sessions/cookies and all write paths tested were correctly enforced — this is
  NOT a cross-org issue; it is intra-account least-privilege enforcement
  failing on account-level reads.
- ~~No SDK keys, mobile keys, or flag data are exposed by this bypass.~~
  **SUPERSEDED by the R10 update: full SDK + mobile keys ARE exposed via
  /api/v2/projects/{key}/environments (list and detail) — see the R10 update
  section below.**

## R9 update (2026-10-23) — integrations + destinations: new no_access-readable families

Re-verified with a fresh `no_access` token (R9 methodology: role with
`basePermissions: no_access` + dangling-flag policy, API token minted from it):

| Endpoint (GET) | no_access | Notes |
|---|---|---|
| /api/v2/integrations/datadog | 200 | `config.apiKey` returned **masked** `zen**************123` (first/last 3 chars) |
| /api/v2/integrations/{splunk,elastic,dynatrace,msteams,grafana} | 200 | config lists readable |
| /api/v2/integration-manifests | 200 | full manifest schema set |
| /api/v2/destinations | 200 | member-session GET of this route TIMED OUT server-side in R6 — the zero-priv token gets a fast 200 |
| /api/v2/flag-statuses | 200 | org project-key listing |
| /api/v2/tags, /api/v2/versions | 200 | |
| /internal/metric-data-sources | 200 | |
| /internal/warehouse-integrations-health | 200 | |
| /api/v2/approval-requests | 200 | items policy-filtered to empty (member session sees items) |

New impact notes:
- Integration API keys are returned masked to ANY caller (including the
  zero-privilege token) — partial disclosure only (P5), unlike the webhook
  signing secret which is returned in full (P2 driver).
- `code-refs/repositories` create accepts a `pat` field but never stores or
  returns it (checked create + detail under no_access) — no PAT leak.
- relay-auto-config `fullKey` appears ONLY in the creation response (owner);
  detail GET under no_access exposes `displayKey` + full policy documents but
  not the relay key (re-confirmed R9).
- Correctly DENIED under no_access: the entire generic query engine
  (`POST /api/v2/chart/data`, `/api/v2/list/data` — uniform 403 viewProject for
  every domain incl. observability.traces / context.* / sdk.* / metrics.*),
  `sdk-keys` route (403), `/internal/account/{invoices,accrued-invoices,card,
  new-hires}` (legacy fence rejects API tokens with "Invalid account ID header").
- Legacy account-header fence differential (R9): 12 candidate header names
  (`LD-Account`, `Account-Id`, `X-Tenant-Id`, …) injected with a FOREIGN
  account id changed nothing — TST session + ORG header returned TST's own
  invoice data, and headers are ignored entirely (account always resolves from
  the session). No cross-org billing read. DEFENDED.

## R10 update (2026-10-24) — SDK KEYS + MOBILE KEYS disclosed (impact upgrade to P1 boundary)

**CRITICAL correction to earlier R9 state:** re-testing on 2026-10-24 shows the
zero-privilege (`basePermissions: no_access`) token CAN now read environment
objects **including full SDK key and mobile key values** — the exact secret
class LaunchDarkly documents as confidential (SDK keys grant full flag-evaluation
read on the whole environment via stream.launchdarkly.com).

Verified twice in the same session, both the LIST and DETAIL routes:

```
GET /api/v2/projects/default/environments                    -> 200, items[] each with apiKey + mobileKey
GET /api/v2/projects/default/environments/test               -> 200, apiKey: "sdk-c6ce7a15-4f85-4db1-a938-4c7378ddd667"
GET /api/v2/projects/default/environments/production         -> 200, apiKey: "sdk-bbf7c59b-0ce5-4184-ab0a-b67224d455f3"
GET /api/v2/projects/zxorg-proj-7f3a/environments[/test]     -> 200, apiKey: "sdk-a4bbbb2b-7223-4ecf-b290-91d30c505754"
                                                              + mobileKey: "mob-14194779-…" (40-char values, not masked)
```

Byte-identity proof: the values returned to the no_access token were compared
against the same endpoints fetched with the account owner's token — **all four
environments across both projects matched exactly** (`NA == owner: True` for
every `apiKey` and `mobileKey`). A full 40-character `sdk-…` / `mob-…` value is
returned — not a masked preview.

Impact escalation: with an SDK key the holder gets **complete read access to
that environment's flag evaluation data** (`stream.launchdarkly.com/flags` with
the SDK key returns the full evaluated flag payload — verified R9 phase C as
by-design for SDK keys). A token intended to have ZERO permissions can now:

1. read every member's e-mail + full audit history (R5 evidence)
2. read the webhook HMAC signing secret and forge signed events (R6 evidence)
3. **read every SDK key and mobile key in every environment (R10 evidence)**
   → exfiltrate all flag targeting/evaluation data for production environments
4. read the full API token inventory incl. per-token metadata and 4-char
   previews (R10: `GET /api/v2/tokens/{id}` returns `"token":"3488"` preview)
5. read relay-auto-config policy documents (R5), integration configs with
   masked keys (R9), ip-allowlist, AI token-usage counters (R10)

Write side remains correctly enforced: `POST /api/v2/flags/default` with the
same token → `403 {"effect":"deny","action":"createFlag"}` (policy engine
denial, not a validation error), while the same payload under the owner token
returns 201. **The bypass is strictly read-only.**

Severity framing: intra-account vertical privilege escalation (zero-privilege
credential → full secret disclosure incl. SDK/mobile keys + webhook signing
secret + member PII). Cross-org isolation remains intact (account-scoped only).
Proposed severity: **P2 minimum; argue P1 on the SDK-key impact** (full
production flag-data exposure + forgeable webhook signatures from a token whose
effective permissions are nothing).

Additional R10 no_access-readable families (GET 200, lower impact):
`/api/v2/account/ip-allowlist`, `/internal/ai/evaluator/token-usage/daily`,
`/api/v2/integration-capabilities/{big-segment-store,featureStore,flag-import}`,
`/api/v2/templates`, `/internal/config/anonymous`.

New negative controls (R10, still fenced): warehouse destination keypair
`POST /api/v2/destinations/generate-warehouse-destination-key-pair` is a
stateless key factory (bogus `projectKey` also → 201; no cross-tenant write,
no existence oracle); `access-summary/preview` uniformly plan-gated 403;
`engineering-insights/flag-events` uniform 403; main-app query-param grammar
(filter `field:value` parser, sort allowlist, strict int limit/offset) rejected
every injection shape (14 payloads × filter/sort/limit/spec).

---

## R11 escalation — classic webhooks family: signing secret fully disclosed (2026-10-24)

Live-browser recon of the entire `/settings` tree (24 pages, XHR capture) surfaced the
classic webhooks family as an additional no_access-readable surface, escalated with a
signing-secret test:

1. `GET /api/v2/webhooks` under the no_access token → **200** with the full webhook
   inventory (names, URLs, tags, enabled state) — same-org; cross-org (TST session)
   correctly 404.
2. **Decisive test**: created a webhook with `sign: true` in the ORG account via the
   owner session (LD generated signing secret `0442950278484bb1ab510eba4b7f1344`).
   `GET /api/v2/webhooks/{id}` under the **no_access** token → **200 with the full
   32-hex HMAC signing `secret` field byte-identical to the owner response.** This is a
   second, independent signing-secret leak vector alongside the integration-destination
   secret (above) — the classic webhooks family is used by most native integrations
   (Slack, PagerDuty, custom consumers verify `X-LD-Signature`).
3. Write remains denied: `PATCH /api/v2/webhooks/{id}` (no_access) → `403
   {"action":"updateOn","resource":"webhook/{id}"}`. Strictly read-only.
4. Artifact hygiene: the sign-enabled test webhook was deleted immediately after the
   test (204, verified 404).

Additional R11 no_access-readable families (GET 200, breadth):
`/api/v2/announcements` + `/internal/announcements`,
`/api/v2/projects/default/{lifecycle-settings,automated-cleanup-settings(+`/upcoming`),
experimentation-settings}`, `/api/v2/projects/{p}/environments/{e}/adaptive-triggers`
(correct grammar: `resourceKind=flag&resourceKey=...`),
`/api/v2/usage/{clientside-contexts,serverside-contexts,streams/client,streams/server,
total-contexts,vega-ai,warehouse-export,data-export-source-capabilities}` (the last
also reflects the numeric `accountId`).

R11 negative controls (all defended):
- `PUT /internal/accounts/{id}/agent-control/settings`: route resolves the account from
  the session/token identity — the path id is **ignored** (TST session on ORG path
  returned TST's own data; NA token on TST path returned ORG's own data). No cross-org.
- `POST /api/v2/account/relay-auto-configs/{id}/reset`: no_access → 403 policy
  (`resetRelayAutoConfiguration`); cross-org session → 404. Owner-only.
- `POST /internal/authorization/access-check/gonfalon/bulk` (needs `Authorization`
  header; body = JSON array of `{action, resource}`): supported resource types
  `proj/`, `member/`, `webhook/`, `relay-proxy-config/`. With `action:"*"` the
  resolver returns `allowed=true` for own, foreign, **and random/deleted** ids
  (member/webhook/relay) — no existence resolution, no cross-org oracle. The only
  signal is `proj/{key}`: existing key → 200 `Access denied` (no_access) vs
  nonexistent → 400 `Invalid resource` — a narrow in-org project-key existence
  signal, negligible because the token already reads the project list.
- Invoice detail + PDF route (`/internal/account/invoices/{id}[/
  LaunchDarkly_Invoice_{id}.pdf]`) → 404 even for the owner.
- `/api/v2/announcements/{id}` detail → 405 (list-only route).
- SAML (`/internal/account/saml`) → legacy "Invalid account ID header" fence for
  tokens; SCIM → 404 "scim client not found" (no client) — no config disclosure.

## R13 — Chain demonstrated: disclosed SDK key → full live flag readout (P1 evidence)

The strongest triage question for this finding is "so what — what does a leaked
SDK key actually yield?" R13 closes that gap end-to-end:

1. `GET /api/v2/projects/default/environments/test` with the zero-privilege
   `no_access` token → 200, full `apiKey` (`sdk-...`) + `mobileKey` values.
2. `GET stream.launchdarkly.com/flags` with that disclosed key → **HTTP 200**,
   initial SSE `put` payload containing the environment's complete flag state
   (~19 flags in our test env: keys, on/off, rules, targets, variations,
   fallthrough, clientSideAvailability — full targeting dump).

Evidence: `recon/r13_hunt5b.txt` + raw stream payload
`recon/r13_chain_demo.txt` (captured 2026-10-24).

=> The bypass is not "metadata exposure": a no-policies token yields working
production-environment credentials that immediately exfiltrate live flag
values and targeting state. This is the concrete P1 impact argument.

Additional R13 note: the same defect class exists in **zero-auth form** on
`demo.app.launchdarkly.com` (see FINDING_004) — an entire tenant API readable
with no credential at all, confirming these key values are treated as
web-deliverable data across hosts.

## R15 update (2026-10-24) — read-only claim re-verified with sharp negatives

Probed whether the zero-policies token can reach ANY state-changing handler
(all on our own tenant, all revertible):

| probe | result |
|---|---|
| `PATCH /api/v2/flags/default/{flag}` real change (desc -> marker) | **403** policy deny (`updateDescription`, effect: deny) |
| `PATCH /api/v2/flags/default/{flag}` same-value (vacuous) | **200** but cosmetic — `_version` unchanged (6), no persistence, no audit entry (mirrors demo-host R14 quirk) |
| `PATCH /api/v2/members/{own-id}` any body incl. role | **409** `"You cannot modify your own role"` — business-rule rejection, i.e. the request REACHES the member-update handler for self |
| `PATCH /api/v2/members/{foreign-tenant-id}` | **404** `Invalid resource identifier` — account-scoped resolution enforced |

Interpretation: the policy engine denies real flag mutations; member-update
scoping blocks foreign members at resource resolution and self-role changes at
business rules. The no_access token remains **effectively read-only on the
write plane** — the F2 impact case therefore still rests on the R13 read chain
(no_access -> sdk key -> full live flag readout), which is where the P1
argument lives.

Evidence: `recon/r15_hunt3.txt`, `recon/r15_hunt3b.txt` (captured 2026-10-24).
