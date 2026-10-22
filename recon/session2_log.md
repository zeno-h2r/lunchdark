# Session 2 progress — 2026-10-22 (SDK setup + telemetry deep-dive)

## SDK setup for gen_ai traces (user request)
- npm: @launchdarkly/node-server-sdk 9.15.0, server-sdk-ai 2.0.15, ai-node/ai-server, ai-otel, o11y 1.2.2 installed
- SDK key (org A test env): sdk-c6ce7a15-4f85-4db1-a938-4c7378ddd667
- **AI Config fixture created (org A)**: zeno-ai-test v3, variations v1/v2 (model openai.gpt-5.4), state published
  - API quirk: PATCH wrapper is {"patch":[...]} with Content-Type: application/json (json-patch+json REJECTED); modelName only settable via POST variations (PATCH ops on /variations/i/model and /defaultVariants silently ignored)
  - /internal/ai-configs/{configKey}/completion requires LD-API-Version header + input:{messages:[...]}
- **AI SDK source (ai-server/dist/index.js) — ingestion auth model**:
  - OTLPTraceExporter(url=otel.observability.app.launchdarkly.com/v1/traces, GZIP) — NO Authorization header
  - routing key = resource attribute `highlight.project_id` = **raw SDK key** (sent unauthenticated in body)
- Injected span (launchdarkly.operation.type=gen_ai) with org A SDK key → **LANDED, verified via pri graph GetMetrics metric_value=1**

## pri.observability.app.launchdarkly.com — auth model cracked
- Frontend calls it directly with: Cookie ldso + **ob_ldso** (issued server-side on obs page visit) + header **x-ld-project-id** (project ObjectID)
- project_id variable in GraphQL = project ObjectID (NOT "1jdkoe52" — that was placeholder)
- ob_ldso ALONE is sufficient (no ldso needed) — separate session realm

## Cross-tenant results (all SCOPED — documented dead ends)
- GetMetrics with A-session + B-project (hdr+var) → authz error "authorization request failed... Invalid resource"
- header/var mismatch: project_id VARIABLE drives authz; header ignored
- unknown/invalid project_id → fail-open returns SESSION project data (not cross-tenant; own data only)
- ld_environments(project_key:"zenovictimproj") as org A → 404 Unknown project key (session-scoped key resolution)
- ld_flag same → "project not accessible in this account" — good hygiene
- pri graph read side: SCOPED. Write side requires secret SDK key = the credential itself (Highlight.io design)

## Observability fixtures
- org B: project zenovictimproj (6ada0cce6f9f4507ca1c771e) env vtest; flag victimflag (TOP-SECRET-VICTIM zeno-victim-7741)
- org B spans injected: 3 (org B sdk key sdk-96141640-...)
- org A spans injected: 1
- Modern flag create route: POST /api/v2/flags/{projectKey} (NOT /api/v2/projects/{p}/flags — that 404s)

## OTLP injection findings recap
- /v1/traces accepts arbitrary highlight.project_id at HTTP level (partialSuccess empty), landing verified ONLY for valid SDK keys
- traceId/spanId must be hex (server: ID.UnmarshalJSONIter)
