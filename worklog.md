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
