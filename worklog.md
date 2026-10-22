# LaunchDarkly Bug Bounty — Work Log
Repo: zeno-h2r/lunchdark | Target: app.launchdarkly.com | Platform: Bugcrowd | Operator: zeno0

---

## 2026-10-22 — Session 1: Application Learning / JS Recon

### Task 1: Engagement setup
- Verified GitHub token → repo zeno-h2r/lunchdark OK (public, 200)
- Created RULES.md, PROGRAM.md, worklog.md

### Task 2: Unauthenticated recon app.launchdarkly.com
- Server: Fastly (varnish). HTTP/2. HEAD / → 405, GET / → 200
- App codename: **gonfalon** (CSP report-uri ddtags service:gonfalon)
- Static assets: static.launchdarkly.com/app/s/ld/
- Manifest: manifest.896789324.json
- CSP highlights (connect-src):
  - *.ld.catamorphic.com (legacy realtime backend)
  - *.app.launchdarkly.com (wildcard subdomains incl. pub/pri.observability.app.launchdarkly.com)
  - wss://pri.observability.app.launchdarkly.com (Observability websockets)
  - *.launchdarklysessions.com (Session Replay, frame-src)
  - whatsnew.launchdarkly.com (frame-src)
  - launchdarkly.com/docs/api/fern-docs/search/v2/key (docs search key endpoint)
- frame-ancestors: app.coast.io, launchdarkly.coastdemo.com, play.instruqt.com/launchdarkly
- Unauth bundle: runtime, initial.vendor, bootstrap, launchpad, common, loadUnauthenticated
- Internal config endpoint: /internal/config/anonymous (preload in unauth HTML)

### Task 3: Authenticated shell (cookie zeno0+org)
- Session ALIVE. GET / → 303 → /projects/default/flags?env=test&selected-env=test
- Leaked defaults: project key "default", env key "test"
- Auth bundle adds: loadApp.9ec5539a032cf1eb.js, common.3cdb8d3b7e33d74b.js
- ld-api-version: 20240415 header on responses

### Task 4: Manifest analysis
- manifest.896789324.json: 1624 entries, **554 unique JS chunks**
- Feature map extracted (chunk_list.txt). High-value/newest features:
  - Agent Control: AgentControlOptIn, AgentcontrolWelcome*, AIAgentGraphs, AICodingAgents, AIOptimizeAgent, SignUpAgentControlRouteEntry
  - AI Configs: AiConfigs*, AiConfigPlayground, AiLibrary* (Datasets/Models/Skills/Tools), AiEvaluation*, AiJudgeTemplate*
  - Observability: Observability* (Logs/Traces/Errors/Sessions/Dashboards/Alerts/Database), ld-observability, framework.observability
  - Vega AI assistant: Vega*, FlagVegaConversations, VegaWorkflowEditor
  - Product Analytics: product-analytics-* (cohorts, dashboards, events, user-activity)
  - Release: OrganizationReleaseAutopilot, ReleaseCoordinatorDashboard, ReleasePipelineEditViewV2, OrganizationReleasePolicies
  - Experiments: Holdout*, MultiArmedBandit*, ExperimentPendingChanges
  - Auth/Security surfaces: AccountImpersonationContainer, EscalatePrivileges, OrganizationAuthorizationTokens* (clone/edit/reset), IPAllowlistSection, SSODomainVerification, EnrollMFAContainer, TrustThisDeviceContainer, ConfirmAuth
  - Org mgmt: OrganizationMembers, OrganizationTeams, OrganizationRoles (RoleBuilder), ChooseOrganizationContainer, JoinOrg, CreateOrJoinContainer
  - Integrations: IntegrationsWebhook*, IntegrationsSlack*, IntegrationsSentry, GithubConnect, IntegrationsGithubApp
  - Data: DataSources*, Contexts*, SegmentTargetingV2, LiveEvents, SdkEventsQueryDashboard
  - Misc: UploadImageContainer, PayloadFilters*, Views*, FeaturePreviews, OnboardingHome

### Next
- Extract API endpoints from common.js (7.8MB) + loadApp.js (3.5MB)
- Enumerate /internal/* endpoints
- Map org IDs: org A (zeno0+org): ajs_group_id=6a0ccb4bd46a010aac3a7b3f, user 6a0ccb4bd46a010aac3a7b41
- org B (zeno0+tester): ajs_group_id=6a0ccca921be370a8e15825e, user 6a0ccca921be370a8e158260

---

## Session 1 (cont.) — API Surface Extraction + Observability Deep-Dive

### Task 5: Endpoint extraction from bundles
- 405 unique endpoints extracted (recon/endpoints.txt on GitHub)
- Key internal: /internal/account/session/escalate, /internal/authorization/access-check/{service}/bulk,
  /internal/members/{id}/access-summary, /internal/contact-us/forms/{formId}/public-submit,
  /internal/ai-configs/{configKey}/completion
- Full /api/v2 surface incl. undocumented: release-policies, views, layers, holdouts, flag-links,
  approval-requests/{id}/apply|reviews, destinations, segment exports/imports

### Task 6: Session verification (both accounts)
- ORG A (zeno0+org, "zeno test"): member 6ac28fd11c28fb07516cf363, role=owner, account 6ac28fd11c28fb07516cf361
  - envs: test=6ac28fd11c28fb07516cf364, production=6ac28fd11c28fb07516cf365
- ORG B (zeno0+tester, "zeno victim"): member 6ac29057ccacd606b1576cb9, role=owner, account 6ac29057ccacd606b1576cb7
- Both: Developer2025 plan, MFA disabled, backend dd7f96edb, frontend 896789324
- 2652 client-side flags each; notable: enable-canary-token, factory-user-token-oauth-enabled,
  enable-modernized-tokens-endpoint, tui-agentcontrol-targeting
- Observability config: observabilityProjectID="1jdkoe52" (BOTH orgs same value!), 
  pub graph: pub.observability.app.ld.catamorphic.com, otel: otel.observability.app.ld.catamorphic.com

### Task 7: TECHNIQUE #1 — Cross-Org IDOR baseline (results: properly scoped)
| Endpoint | B->A result | Verdict |
|---|---|---|
| GET /api/v2/members/{A_member} | 404 not_found | scoped |
| GET /api/v2/auditlog/{A_entry} | 404 | scoped |
| GET /internal/members/{A_member}/access-summary | 403 "Plan does not allow this operation" | plan-check fires BEFORE org check (noted) |
| GET /api/v2/tokens/{A_token} | 404 Token not found | scoped |
| PATCH /api/v2/tokens/{A_token} | 404 | scoped |
- Org A fixture created: access token _id=6ad9fbdd910326079dc637cf (reader, value known)
- Destination webhook creation: 403 "Destination kind webhook is unavailable" (plan-gated)

### Task 8: Observability service (pri.observability.app.launchdarkly.com) analysis
- Highlight.io-derived backend. GraphQL at "/", Go router ("page not found" on /graphql)
- **Introspection ENABLED**: 190 queries, 70 mutations, 1 subscription (recon/obs_graphql_schema.txt on GitHub)
- High-value queries: session(secure_id), sessions(project_id,...), ld_flag(project_key,flag_key,env_key),
  ld_flag_evaluations(...), ld_environments(project_key), conversation_history(conversation_id), alert(id),
  graph(id), visualization(id), billingDetails(workspace_id), workspace_admins(workspace_id),
  aiConversationHistory(project_id,...,user_email), topUsers(project_id), session_summary, trace(project_id,trace_id)
- Auth model: LDProjectAuth middleware. Enumerating projects/workspaces blocked: "LDProjectAuth does not support GetProjects"
- Unauth requests: "LDProjectAuth requires LDAccountID in context"
- LDAccountID NOT client-header controllable (tested x-ld-account-id, ld-account-id, LDAccountID, etc. unauth — all rejected)
- ld_flag/ld_environments proxy to Gonfalon: fail with "Invalid account ID header" using our cookies
  (account resolution for gonfalon callback fails — likely needs full Observability enablement)
- project(id:"1jdkoe52") returns null for BOTH orgs; workspace_for_project expects numeric ID
- ob_ldso cookie = signed token, cannot be forged without server key
- Public graph (pub...catamorphic.com): only {ignore, sampling} queries — locked down
- VERDICT so far: no cross-org leak demonstrated on observability private graph. Session binding is server-side. Honest: no finding here yet.
- Suspicious: otel.observability.app.ld.catamorphic.com/v1/traces returned HTTP 200 to unauth empty POST — IN PROGRESS

### Next
- Verify OTel ingestion auth (trace/log injection cross-tenant?)
- Technique #2 candidates: OTel ingestion auth, approval-requests IDOR (needs fixture), AI configs, Vega
