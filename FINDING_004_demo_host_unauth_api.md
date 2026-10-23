# FINDING_004 — Fully unauthenticated read access to the LaunchDarkly demo product instance API (`demo.app.launchdarkly.com`), including staff PII, token inventory, full audit log, and production SDK/mobile key values

- **Asset:** `demo.app.launchdarkly.com` (product subdomain of in-scope `app.launchdarkly.com`) — `/api/v2/*`, `/internal/*`
- **Auth required:** NONE (fully unauthenticated read of the entire customer-facing API surface)
- **Severity (our assessment):** P2 candidate (VRT: Broken Access Control / Sensitive Data Exposure); honest counter-argument: the tenant is LaunchDarkly's own public demo account, and demo-mode browsing may be intentional — but the exposed surface and data classes exceed any plausible demo-mode scope
- **Status:** repro-verified 2026-10-24 (R13); evidence archived at `recon/r13_demo_*.json`

## Summary

The host `demo.app.launchdarkly.com` serves the LaunchDarkly product SPA and the
full `/api/v2/` + `/internal/` API against a dedicated "demo" tenant
(account `_id 675b806fed1489094561e466`, organization "LaunchDarkly", project
`default` "LaunchDarkly"). Unlike `app.launchdarkly.com`, the demo host does
not enforce authentication on API routes: every read endpoint tested returns
`200` to a completely unauthenticated caller with the identical payload an
authenticated owner session receives (verified by replaying the same requests
with the ORG session cookie — byte-identical results). The API does resolve a
synthetic "demo user" identity (`/api/v2/members/me` → reader-role member
`675c915ebdf9a10981341653`), and the policy engine correctly denies writes
(`POST /api/v2/flags/default` → 403 `createFlag` deny) — but **all reads are
open to the internet**.

## Evidence (all captured with zero credentials, single GET each)

### 1. Full SDK + mobile key values (production environment)
- `GET /internal/list/environments` →
  `{"apiKey":"sdk-c94af27e-6271-4cdc-add9-a5710b51dcab","mobileKey":"mob-08fc98c1-db34-4f9a-914b-71279975f8c8",...}`
- `GET /api/v2/projects/default/environments/production` → 200 with full
  `apiKey`/`mobileKey` **values** (not masked, not previews)
- Impact: anyone can read the demo tenant's complete live flag state via
  `stream.launchdarkly.com/flags` with the disclosed SDK key, and inject
  analytics events via `events.launchdarkly.com` — the same chain
  demonstrated for FINDING_002 (`recon/r13_chain_demo.txt`).

### 2. Staff PII
- `GET /api/v2/members` → 2 members with real LaunchDarkly staff emails:
  `team-growth@launchdarkly.com` (owner, firstName "Sam" lastName "Demo") and
  `team-growth+demo1@launchdarkly.com` (reader "Demo User").
- `GET /api/v2/members/me` → 200 unauthenticated (synthetic demo identity,
  incl. MFA-send settings shape `sendMfaEnabled...`).

### 3. API access token inventory
- `GET /api/v2/tokens` → **24 access tokens** with `_id`, owner/member identity,
  4-char previews and — critically — token *names* that expose the account's
  security-relevant processing history, e.g.:
  - `LDCLI access token for i027probe/i027role/i027scope/i027mem` (issue-numbered probes)
  - `LDCLI access token for i109race`, `i109xss <img src=x onerror=alert(document.domain)>`
    (a stored-XSS payload embedded in a token name, reflected unauthenticated)
  - `LDCLI access token for cors2`, `xhost`, `otok`, `i068mint/svcA-D`
  - These are recognizably leftovers from other security researchers' testing.
- Negative control: no full token values are present (previews only), and a
  recursive scan of all demo captures found no JWTs, `api-` tokens, cloud
  keys, or private-key PEMs (`recon/r13_demo_tokens.json`).

### 4. Complete audit log
- `GET /api/v2/auditlog` (and `?q=` search) → full tenant history incl.
  repeated `"[Demo User](mailto:team-growth+demo1@launchdarkly.com) reset the
  access token..."` entries — i.e., credential-management events with member
  attribution, plus flag-change history and resource links.

### 5. Everything else a customer session can read
- `/api/v2/projects` + `/api/v2/projects/default` + environments list/detail
- `/api/v2/flags/default` (full flag list incl. targeting), `/api/v2/segments/default[/production]`
  ("Beta Users" segment with descriptions), `/api/v2/metrics/default`,
  `/api/v2/teams` (with per-team `_access` policy state), `/api/v2/webhooks`,
  `/api/v2/account` (billing links, config), `/internal/account`
- `/internal/config/authenticated` → **200 with a 300+ KB bootstrap payload**
  (on `app.launchdarkly.com` this exact route requires a session and returns 401;
  full capture `recon/r13_demo_config_authed.json`) — mirrors the
  FINDING_003 data classes (dogfood URIs, `observabilityProjectID`, telemetry
  keys, allClientSideFlags) for this tenant.
- `/internal/config/anonymous` → 200 (same FINDING_003-class payload on a
  second host — FINDING_003 breadth +1).

## Reproduction

```bash
curl -s https://demo.app.launchdarkly.com/api/v2/projects | head -c 400
curl -s https://demo.app.launchdarkly.com/internal/list/environments
curl -s https://demo.app.launchdarkly.com/api/v2/members
curl -s https://demo.app.launchdarkly.com/api/v2/auditlog?q=reset | head -c 400
```
No cookies, no Authorization header, no CSRF token. Contrast: the same
requests against `app.launchdarkly.com` return 401. Authenticated replay with
an owner session returns byte-identical payloads, proving the demo host simply
skips the authentication gate.

## Write-path negative control

`POST /api/v2/flags/default` (unauth, valid body) → `403 {"message":"Access to
the requested resource was denied","reason":{"effect":"deny"},"access":
{"action":"createFlag","resource":"proj/default:env/production:flag/..."},
"code":"forbidden"}` — the policy engine is intact; the defect is read-only.
No state was modified (no artifact created; the single 403 write attempt had
no side effects).

## Impact

An anonymous visitor obtains: production SDK + mobile key values for the demo
tenant (→ full live flag readout and event injection on the demo account),
real LaunchDarkly staff email addresses, the complete audit history including
access-token reset events, a 24-token API credential inventory (incl. stored
XSS payloads in token names and researcher probing history), all flags,
segments, metrics and team data, and a 300 KB authenticated-mode bootstrap
config. Even if demo browsing itself is a deliberate product decision, the
*authenticated-only* control plane (member list, token inventory, audit log,
key values, `/internal/config/authenticated`) was never intended to be
anonymous-readable — `app.launchdarkly.com` enforces 401s on every one of
these routes, and the demo host's policy engine denies anonymous *writes*,
which demonstrates the tenant is still treated as access-controlled.

## Remediation suggestions

1. Enforce the same 401 authentication gate as `app.launchdarkly.com` on
   `/api/v2/*` and `/internal/*` for the demo host, then serve demo-mode
   content via the explicit anonymous bootstrap only (`/internal/config/anonymous`).
2. Rotate/restrict the demo tenant's `sdk-`/`mob-` keys and treat them as
   public (they are currently extractable by anyone).
3. Scrub staff PII (`team-growth@`, `+demo1` aliases) and historical
   researcher token names from the demo tenant; recreate the tenant fresh.
4. Add the demo host to the security review boundary for "authenticated"
   endpoints (auditlog, tokens, members/me) — these must never be
   demo-servable.

## Severity argument

- **P2 argument:** unauthenticated access to an entire authenticated API
  surface (authentication bypass class), disclosing credential-class values
  (SDK/mobile keys), personnel PII, credential-management audit events, and
  an access-token inventory on a production product host under
  `app.launchdarkly.com`. Broken Access Control / Authentication → per VRT
  "P2 — Unauthenticated access to authenticated-only functionality" fits the
  read plane precisely.
- **P3 counter-argument (honest):** the tenant is LaunchDarkly's own staged
  demo account; exposed flags/segments are demo data; no full access-token
  values leak. The strongest single artifacts are the key values + staff PII
  + audit log. Demo-intent may be argued by triage, but the tokens/members/
  auditlog/config-authenticated classes are clearly outside any demo-mode
  intent (write path denies anonymous users — access control was expected).

## R14 — Breadth, fence differential, and write-path hardening (evidence update)

### Breadth +10 (all unauthenticated, demo tenant)
Detail routes also readable: `GET /api/v2/tokens/{id}`, `/api/v2/members/{id}`,
`/api/v2/auditlog/{id}`, `/api/v2/teams/{key}`, `/api/v2/flags/default/{flag}`
(full flag incl. environments), `/api/v2/metrics/default/{key}`,
`/api/v2/integrations` (config link map), `/internal/account/invoices`
(`items:[]`), teams detail with `_access` policy state.

### The `/internal/*` legacy token fence is not enforced on the demo host
On `app.launchdarkly.com`, token-authenticated calls to account-scoped
`/internal/*` routes are rejected with `401 "Invalid account ID header"`.
The same calls with the same tokens on the demo host return `200`:
`/internal/account/invoices`, `/internal/list/environments` (full key values),
`/internal/account`, `/internal/config/authenticated`. The data served is the
DEMO tenant's (no cross-tenant leak), but the differential proves the demo
deployment skips an authentication control the main app enforces.

### Invalid-token fallback
`Authorization: api-<40 random hex>` on the demo host → `200` (silent fallback
to the anonymous demo identity) instead of `401`; `Bearer garbage` → 401. On
the app host both → 401. Auth failures should not upgrade to a working identity.

### Account-selector abuse: fully tested, negative
10 candidate tenant-selector headers (`x-launchdarkly-account`, `LD-Account`,
`X-Account-Id`, …) x 2 real tenant IDs, 6 query-param variants, path-based
account routes, and ORG/TST session cookies: ALL ignored — the demo host pins
the demo tenant. Valid `api-` tokens resolve their real tenant with identical
privileges to the app host (verified: NA token → ORG project list). No
cross-tenant read vector exists on the demo host.

### Write path: fenced (read-only bypass confirmed)
- `POST /api/v2/tokens` (token minting) → 403 `Sandbox does not allow this operation`
- `POST /api/v2/members` (invite) → 403 `Sandbox does not allow this operation`
- `POST /api/v2/webhooks`, `POST segments` → 403 policy deny
- Real-change `PATCH /description` / `/tags` → 403 `updateDescription` deny
- Same-value no-op PATCH → vacuous 200 (no persistence, no audit entry)
- `DELETE` nonexistent flag → 404 (fence vs resolution inconclusive)
The sandbox guard + policy engine block mutation; the defect is the read plane.

### Environment census
Subdomain sweep (27 candidates) — only `demo`, `accelerate`,
`product-analytics-api`, `pub/otel.observability` resolve under
`*.app.launchdarkly.com`. EU instance (`app.eu.launchdarkly.com`) is a
separate identity realm (our tokens → 401 `Invalid key`).
