# SUBMISSION 3 — Unauthenticated `/internal/config/anonymous` exposes LaunchDarkly production internal flag state (2,676 flags), employee onboarding roster, live incident communications, privileged customer account ID, production infrastructure tuning and AI system prompts (324 KB)

- **Platform:** Bugcrowd — LaunchDarkly (`launchdarkly-mbb-og`)
- **Hunter:** zeno0
- **Target:** `app.launchdarkly.com` — `GET /internal/config/anonymous` (also 200 with trailing slash and `?device=mobile`; mirrored on `demo.app.launchdarkly.com`)
- **Suggested VRT:** Sensitive Data Exposure → P3
- **Tested:** 2026-10-24 (full capture archived; re-verified multiple times)

---

## Title

**Unauthenticated 324 KB disclosure of LaunchDarkly's own production internal configuration: employee hiring roster, live incident banner, security-posture toggles, a privileged customer's account ID, ClickHouse production tuning, AI agent system prompts and unreleased roadmap — via `/internal/config/anonymous`.**

---

## Summary

The SPA bootstrap endpoint `GET /internal/config/anonymous` returns the complete client-side configuration of LaunchDarkly's **own production app account** to any unauthenticated caller — a 324,387-byte JSON document containing the evaluation of **2,676 internal feature flags** (`allClientSideFlags`) plus operational metadata. Individual client-side flag evaluations are by design delivered to browsers; the defect here is the *aggregate*: the endpoint hands the entire internal rollout state — including personnel data, live incident communications, security-posture toggles, a privileged customer identifier, production data-infrastructure parameters, AI prompts, and unreleased roadmap tickets — to anyone with zero interaction, under an `/internal/*` namespace that implies non-public scope.

## Reproduction (copy-paste)

```bash
curl -s "https://app.launchdarkly.com/internal/config/anonymous" -o cfg.json -w "%{http_code} %{size_download}\n"
# -> 200 324387   (no cookies, no Authorization header, no CSRF)
curl -s "https://demo.app.launchdarkly.com/internal/config/anonymous" -o cfg2.json -w "%{http_code} %{size_download}\n"
# -> 200 (same payload class on the demo host)
```

## Evidence — disclosed data classes

### 1. Employee onboarding roster (personnel data)
55 flag keys of the form `new-hires-add-<username>` (73 JML-shaped flags total), each referencing a real LaunchDarkly employee username — e.g. `new-hires-add-aacharya`, `new-hires-add-jmcelroy`, `new-hires-add-zverrilli`. This is LD's automated joiner/mover/leaver pipeline leaking the company hiring pipeline and staff usernames to the public internet.

### 2. Live incident communications
```json
{"enabled": true, "text": "Related to this incident: To ensure flag updates reach all applications, restart any LaunchDarkly SDKs or Relay Proxy instances that were running from 9 - 11 am PT on July 10th."}
```
Operational incident details (time window + affected components) served to anonymous callers.

### 3. Internal security posture
- `enable-audit-log-secret-redaction = false` — LD's own audit-log secret redaction is OFF in their production account
- `enable-internal-authorization-endpoint = true` — the internal bulk authorization endpoint is enabled in production
- `accepted-redirect-hosts = ["accelerate.app.launchdarkly.com"]` — the app's redirect-host allowlist

### 4. Privileged customer metadata
`accounts-excluded-from-overage-emails = {"accounts": ["5bfdc6a223d2f65d48b8fd10"]}` — a specific customer account ID exempted from overage billing emails (MongoDB ObjectId; creation timestamp decodable). Disclosure that a named account receives special billing treatment.

### 5. Production infrastructure details
- `clickhouse-ingest-setting-overrides` — production ClickHouse cluster insert tuning (`min_insert_block_size_rows=12582540`, filesystem cache settings…)
- Internal hostnames: `app.ld.catamorphic.com`, `stream/events.ld.catamorphic.com`, `otel.observability.app.ld.catamorphic.com`, `pub.observability.app.ld.catamorphic.com`, `product-analytics-api.app.launchdarkly.com/{block,data}-service`, `demo.app.launchdarkly.com`, `accelerate.app.launchdarkly.com`
- `common-varnish-purge-targets`, `beast-mode` routing config

### 6. AI/ML internals
`agent-control-starter-chatbot-config` — full AI Config payloads: system instructions ("You are a friendly, concise customer support agent…"), model identifiers (`Anthropic.claude-haiku-4-5-20251001`), generation parameters (temperature 0.7, max_tokens), and sample responses.

### 7. Unreleased roadmap
`experiment-metric-compatibility-rules` referencing internal ticket IDs and timelines — `LAUNC-2510`, "Q3 2026 target, not yet built", "Legacy quantile implementation broken for Bayesian; same Airflow pipeline as Hosted" — plus the full experiment tracking registry (`exp_2026_*` → flag mappings).

### 8. Corroborating metadata
`observabilityProjectID = 1jdkoe52` (the shared Observability workspace ID used by every customer org — relevant to a separate cross-tenant injection submission), `clientSideId`, `secureModeContextHash`, per-request anonymous `dogfoodContext`, and the full telemetry stack map (Segment write key, Datadog RUM client token, New Relic license key, Algolia keys, Stripe publishable key — individually public-by-design).

## Negative controls (checked and documented)

- **No credential-class secrets present**: recursive scan of the full capture found no JWTs, no `sdk-`/`mob-`/`api-` keys, no cloud keys (AKIA/AIza), no GitHub/Slack tokens, no private-key PEMs. The two 40+-char strings are the `secureModeContextHash` and the Algolia search-only key. We do not claim secret leakage — the finding is the aggregate internal-state disclosure.
- `GET /internal/config/authenticated` → 401 (the authenticated variant is correctly gated on the main app).
- Sibling paths `/internal/config`, `/internal/config/bootstrap`, `/internal/config/flags`, `/internal/config/anonymous/v2` → 404; `/internal/config/features` → SPA HTML fallback.
- Flag *values* are the anonymous-context evaluation — no user-specific targeting data is exposed.

## Impact

An anonymous attacker obtains a continuously-refreshing mirror of LaunchDarkly's internal engineering state: who LD is hiring (usernames), what LD is shipping and when (roadmap tickets), how LD's production data infrastructure is tuned, which customer receives billing exemptions, what LD's current security-posture toggles are, and the company's live incident communications. This is reconnaissance-grade information for social engineering and further technical attacks, and includes personnel data that LD clearly did not intend to publish. The `/internal/` namespace, the employee-roster flags and the incident-banner content demonstrate the payload's intended audience is internal — the anonymous delivery is the defect.

## Suggested remediation

1. Serve only the minimal flag set genuinely needed by logged-out pages; gate the full `allClientSideFlags` payload behind authentication.
2. Move employee-named (JML) flags out of the client-side flag set — server-side only.
3. Strip incident banner content, customer account IDs, infrastructure parameters, and AI prompt payloads from the anonymous bootstrap.
4. Relocate the endpoint out of the `/internal/*` namespace and add rate limiting.

## Notes for triage

- Honest counter-argument: client-side flag delivery to browsers is by design, and no credential-class secret is present — we accept this may land P4. Our P3 argument is the aggregate of never-meant-to-be-public classes (personnel roster, incident comms, privileged customer ID, infra tuning, roadmap) delivered to anonymous callers under an internal namespace.
- GET-only testing; no state was modified anywhere on the target.
