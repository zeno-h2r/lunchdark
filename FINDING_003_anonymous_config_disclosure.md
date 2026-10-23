# FINDING_003 — Unauthenticated disclosure of LaunchDarkly production internal flag state, employee roster, incident comms, and privileged-customer metadata via `/internal/config/anonymous`

- **Asset:** `app.launchdarkly.com` — `GET /internal/config/anonymous` (also `200` with trailing slash and `?device=mobile`)
- **Auth required:** NONE (fully unauthenticated)
- **Severity (our assessment):** P3-arguable / P4-likely per Bugcrowd VRT ("Sensitive Data Exposure") — submitted for triager judgment; core argument is the aggregate of internal-only data classes below
- **Status:** repro-verified 2026-10-24 (R12); full raw payload archived at `recon/r12_config_anonymous_full.json` (324,387 bytes)

## Summary

The SPA bootstrap endpoint `/internal/config/anonymous` returns the complete
client-side configuration of LaunchDarkly's own production app account to any
unauthenticated caller. The response is a 324 KB JSON document containing the
evaluation of **2,676 internal feature flags** (`allClientSideFlags`) plus
operational metadata. While individual client-side flags are by design
delivered to browsers, this endpoint hands the *entire* internal rollout
state — including engineering-hiring metadata, live incident
communications, production infrastructure tuning, a privileged customer
account ID, AI system prompts, and unreleased roadmap details — to any
anonymous party with zero interaction, on an `/internal/*` namespace that
implies non-public scope.

## Evidence (key disclosed data classes)

### 1. Employee onboarding roster (personnel data)
55 flag keys of the form `new-hires-add-<username>` (73 JML-shaped flags
total), each referencing a real LaunchDarkly employee username — e.g.
`new-hires-add-aacharya`, `new-hires-add-jmcelroy`, `new-hires-add-zverrilli`
(full list: `recon/r12_newhires_flags.txt`). This is LD's automated
joiner/mover/leaver pipeline leaking the company hiring pipeline and
staff usernames to the public internet.

### 2. Live incident communications
`app-restart-banner-data`:
```json
{"enabled": true, "text": "Related to this incident: To ensure flag updates
reach all applications, restart any LaunchDarkly SDKs or Relay Proxy
instances that were running from 9 - 11 am PT on July 10th."}
```
Operational incident details (time window + affected components) served to
anonymous callers.

### 3. Internal security posture
- `enable-audit-log-secret-redaction = false` — LD's own audit-log secret
  redaction is OFF in their production account
- `enable-internal-authorization-endpoint = true` — confirms the internal
  bulk authz endpoint (see FINDING_002 R11 notes) is enabled in production
- `allow-legacy-continuation-tokens = true`, `cap-service-token-by-personal-token-role = true`
- `accepted-redirect-hosts = ["accelerate.app.launchdarkly.com"]` — the app's
  redirect-host allowlist

### 4. Privileged customer metadata
`accounts-excluded-from-overage-emails = {"accounts": ["5bfdc6a223d2f65d48b8fd10"]}`
— a specific customer account ID exempted from overage billing emails. The ID
is a MongoDB ObjectId (creation timestamp decodable). Disclosure that a named
account receives special billing treatment.

### 5. Production infrastructure details
- `clickhouse-ingest-setting-overrides` — production ClickHouse cluster insert
  tuning (`min_insert_block_size_rows=12582540`, filesystem cache settings…)
- Internal hostnames: `app.ld.catamorphic.com`, `stream/events.ld.catamorphic.com`
  (dogfood), `otel.observability.app.ld.catamorphic.com`,
  `pub.observability.app.ld.catamorphic.com`,
  `product-analytics-api.app.launchdarkly.com/{block,data}-service`,
  `demo.app.launchdarkly.com`, `accelerate.app.launchdarkly.com`
- `common-varnish-purge-targets`, `beast-mode` routing config
  (`{"all": true, "routes": []}`)

### 6. AI/ML internals
`agent-control-starter-chatbot-config` — full AI Config payloads: system
instructions ("You are a friendly, concise customer support agent…"),
model identifiers (`Anthropic.claude-haiku-4-5-20251001`), generation
parameters (`temperature 0.7`, `max_tokens`), and sample responses.

### 7. Unreleased roadmap
`experiment-metric-compatibility-rules` references internal ticket IDs and
timelines — `docNote: "LAUNC-2510"`, `"Q3 2026 target, not yet built"`,
`"Legacy quantile implementation broken for Bayesian; same Airflow pipeline
as Hosted"` — plus the full experiment tracking registry
(`exp_2026_*` → flag mappings).

### 8. Corroborating metadata for FINDING_001
`observabilityProjectID = 1jdkoe52` (the shared observability workspace ID
identical across customer orgs — see FINDING_001), `clientSideId
5866f3891cd8810a42ce5281`, `secureModeContextHash`, anonymous
`dogfoodContext` with per-request session UUID, and third-party telemetry
keys (Segment write key, Datadog RUM client token, New Relic license key,
Algolia search keys, Stripe publishable key — public-by-design individually,
but presented here as the full telemetry/surveillance stack map).

## Reproduction

```bash
curl -s https://app.launchdarkly.com/internal/config/anonymous | head -c 500
```
No cookies, no Authorization header, no CSRF — direct unauthenticated GET.
`/internal/config/anonymous/` (trailing slash) returns the identical payload.

## Negative controls (checked, documented)

- **No credential-class secrets present**: recursive scan found no JWTs,
  `sdk-`/`mob-`/`api-` keys, cloud provider keys (AKIA/AIza), GitHub/Slack
  tokens, or private-key PEMs. The two 40+-char strings are the
  `secureModeContextHash` and the Algolia search-only key.
- `GET /internal/config/authenticated` → 401 (legacy account-ID fence holds)
- Sibling paths `/internal/config`, `/internal/config/bootstrap`,
  `/internal/config/flags`, `/internal/config/anonymous/v2` → 404;
  `/internal/config/features` → SPA HTML fallback
- Flag *values* are the anonymous-context evaluation — no user-specific
  targeting data is exposed (per-request anonymous session UUID in
  `dogfoodContext`)

## Impact

An anonymous attacker obtains a continuously-refreshing mirror of
LaunchDarkly's internal engineering state: who LD is hiring (usernames),
what LD is shipping and when (roadmap tickets), how LD's production data
infrastructure is tuned, which customer receives billing exemptions, what
LD's current security-posture toggles are, and the company's live incident
communications. This is reconnaissance-grade information for further
social engineering, bug hunting, and competitive intelligence, and includes
personnel data (employee usernames) that LD clearly did not intend to
publish. The `/internal/` namespace and the presence of employee-roster and
incident-banner data demonstrate the payload's intended audience is
internal — the anonymous delivery is the defect.

## Remediation suggestions

1. Serve only the minimal flag set genuinely needed by logged-out pages;
   gate the full `allClientSideFlags` payload behind authentication.
2. Move employee-named (JML) flags out of the client-side flag set — they
   should be server-side only.
3. Strip incident banner content, account IDs, infrastructure parameters,
   and AI prompt payloads from the anonymous bootstrap.
4. Rename/relocate the endpoint out of the `/internal/*` namespace to avoid
   misleading trust boundaries, and add rate limiting.

## Severity argument

- **P3 argument:** aggregate internal-state disclosure including personnel
  data (54+ employee usernames), live incident comms, a specific privileged
  customer account ID, and unreleased roadmap — all unauthenticated.
- **P4 counter-argument (honest):** individual client-side flags are
  browser-delivered by design; no credential-class secret is present. The
  finding's strength is the aggregate + the `/internal/*` namespace +
  personnel/incident/customer data that was never intended for public
  delivery.
