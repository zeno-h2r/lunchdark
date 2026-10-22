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

## TECH: authz oracle + tokens — FINDING 002 (P2)
- access-check oracle: POST /internal/authorization/access-check/gonfalon/bulk, Authorization: <document.cookie>; cross-org resources → "Invalid resource" (scoped)
- teams addMembers: cross-org member ID → "does not exist" (scoped); member-existence oracle within own account
- **FINDING 002 (P2): API token with basePermissions=no_access reads account-level endpoints**:
  - 200: /api/v2/members(+{id}), /api/v2/auditlog(+{id}), /api/v2/tokens (inventory w/ lastUsed), /api/v2/webhooks(+{id}), /api/v2/roles(+{key}), /api/v2/projects (list)
  - 403 (correct): flags, project detail, environments (SDK keys safe), segments, metrics, teams; ALL writes 403
  - Report: FINDING_002_noaccess_token_bypass.md
- Anomaly: reader-base custom-role token — mixed-type-variation flags (string+bool) 404/disappear from list+item reads; boolean-variation flags all readable (policy filter bug, not root-caused)
- Flag create route: POST /api/v2/flags/{projectKey}; members invite: POST /api/v2/members with ARRAY body [{"email","role"}]
- 2nd member fixture in org A: 6ada14122e3d84072f7dcf53 (zeno0+second@…, reader, pending invite)
- Webhook SSRF: works by design (outbound to arbitrary https), delivery confirmed via webhook.site (LD-Integrations/1.0, AWS IPs)

## Session 2 (cont.) — systematic technique sweep results (all SCOPED unless noted)

| Technique | Result |
|---|---|
| Layers cross-org (same 'default' key) | org B list empty; scoped |
| Experiments cross-org | 404 "experiment not found"; scoped |
| Metrics cross-org | 404 "metric resource key not found"; scoped |
| internal/.../experiments/{k}/files/{fileId} | 500 on own (route broken w/o files), 404 cross-org; needs LD-API-Version |
| Agent Control settings /internal/accounts/{id}/agent-control/settings | path accountId IGNORED — session-rewritten read AND write (fail-closed) |
| Relay auto-configs IDOR by _id | 404 cross-org; displayKey truncated even for owner |
| Billing /internal/billingv2/* | query params ignored; session-scoped |
| SSO domain verification | DNS TXT-based; claiming any domain allowed but verification needs TXT control (proper design) |
| Context-instances search | strict FQL parser, no injection |
| assignment/metric data sources | session-scoped |
| flag-cleanup insights | param appears ignored; no discriminator proven |
| Shortcuts (LD-API-Version: beta required) | scoped per project |
| Audit log cross-org | org B sees only own entries; scoped |
| Variation-type anomaly | reader-base token: mixed-type-variation flags (string+bool) → 404; bool/bool, str/str, num/num → 200 (pattern confirmed) |

Fixtures created org A: metrics zeno-victim-metric, layers zeno-victim-layer, experiment zeno-victim-experiment (c54c3c9c-31ec-41d1-946e-0f074a2c35e3), flags zeno-secret-fixture/-2/-3, zeno-pre-t4, zeno-numflag, zeno-strflag, roles zeno-flag-viewer(+noaccess), tokens zeno-scoped-ui/-2/-3, zeno-noaccess-tok
Fixtures org B: project zenovictimproj (6ada0cce6f9f4507ca1c771e), env vtest, flag victimflag
2nd member org A: 6ada14122e3d84072f7dcf53 (reader, invited)

## Session 2 (final) — remaining surfaces
- Views cross-org: 404 "View not found" — scoped
- flag-links cross-org (beta header): 200 with empty items (does not 404 on foreign flag — non-distinguishing, negligible); link fixture zeno-link/_deepLink TOP-SECRET-LINK-7741 NOT leaked to org B
- release-policies route not present in this app version (404)
- Destinations (warehouse) setup: 405 on GET; setup flow requires integration entitlements (plan-gated)
- integration-configurations: list route 404; per-key setup 405 (entitlement-gated)

## SESSION 2 BOTTOM LINE
- 1 new P2-class finding: FINDING_002_noaccess_token_bypass.md (no_access tokens read members/auditlog/tokens/webhooks/roles)
- 1 anomaly documented (mixed-variation flags vanish for custom-role tokens)
- All cross-org surfaces (layers/experiments/metrics/views/flag-links/relay/agent-control/billing/shortcuts/auditlog) properly session-scoped
- Observability OTLP ingestion: routing key = SDK key in body (secret); gen_ai span landed + verified on traces page
