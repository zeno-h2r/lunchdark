# LaunchDarkly SPA — Application Map (R0+R1 Recon)

**Target:** `https://app.launchdarkly.com` (SPA codename: **gonfalon**)
**Frontend:** `e3ebfdb78` / **Backend:** `8f53c9cd2` (as of 2026-10-22)
**Accounts:** `[ORG]` zeno0+org (owner, project `default`/zenocrowd) · `[TST]` zeno0+tester (owner, project zenohacker)
**Method:** authenticated browser walk (R0) + full JS corpus extraction (R1: 549 chunks + 5 main bundles, ~107MB)

---

## 1. Verified route map (R0 browser walk)

### 1.1 Account-level (`/settings/*`) — all verified 200
| Route | Title | Notes / API backing |
|---|---|---|
| `/settings/general` | General settings | Sections: Plans & usage, Access, Connections, Configuration, Security, Your organization → `GET /internal/config/authenticated`, billingv2 |
| `/settings/projects` | Projects | `GET /api/v2/projects` |
| `/settings/members` | Members | `GET /api/v2/members`, invite flows |
| `/settings/teams` | Teams | `GET /api/v2/teams`, maintainers, access summaries |
| `/settings/roles` | Roles | Custom roles: `GET /api/v2/custom-roles`, RoleBuilder |
| `/settings/authorization` → `/t/tokens` | Authorization (redirect) | **API access tokens + OAuth2 clients**: `/api/v2/tokens`, `/api/v2/tokens/{id}/reset`, `/internal/account/oauth2/applications` |
| `/settings/billing` | Billing | `/internal/billingv2/account/subscription`, invoices, Stripe card setup intent |
| `/settings/integrations` | Integrations | Marketplace + destinations + webhooks + incoming-webhook subscriptions |
| `/settings/relay` | Relay Proxy | `/api/v2/account/relay-auto-configs` |
| `/settings/sdks` | SDKs | **Org-wide SDK keys surface** (new): `/api/v2/account/sdk-keys`? + `OrganizationSDKs` chunk |
| `/insights` | Launch Insights | Org analytics: `/internal/insights/*` (flag-cleanup, flag-usage, member-metrics, rollout-metrics, scores) |

### 1.2 Project-level (`/projects/:projectKey/*`)
| Route | Title | Feature |
|---|---|---|
| `/flags` | Flags | Flag list, views switcher, `FlagsConnect`, bulk ops |
| `/flags/:flagKey/targeting` | Flag targeting | Rules, expiring targets, pending changes, test-run (`FlagTargetingTestRun`), conflicts, audience |
| `/flags/:flagKey/{evaluations,insights,monitoring,code,history,settings}` | Flag tabs | `/internal/projects/{p}/flags/{f}/monitor/*`, followers, subscriptions |
| `/segments` (+`/new`, `/{key}/{targeting,flags,history,settings}`) | Segments | Big segments, `SegmentTargetingV2` |
| `/contexts` | Contexts | `ContextsKindManagement`, instance details, kind settings |
| `/live` | Live events | SSE stream of evaluations |
| `/experiments` | Experiments | iterations, exposures, stratified-sampling, MAB analyses |
| `/multi-armed-bandits` | Multi-armed Bandits | standalone bandit dashboard (new) |
| `/holdouts` | Experiments (holdouts) | holdout design/details |
| `/sessions`, `/errors`, `/logs`, `/traces` | Observability | LD Observability (DSP): `ld-observability` chunk, session-manager, recorder |
| `/observability-metrics`, `/alerts`, `/dashboards` | Observability cont. | alert rules, custom dashboards, `/api/v2/chart/data/analysis` |
| `/metrics` | Metrics | custom metrics + metric groups + data sources |
| `/observe` | Event explorer | event queries |
| `/data-sources/{metrics,assignments,attributes}` | Data sources | warehouse-native: assignment/metric data sources, **`/probe` endpoint** |
| `/approvals` | Approvals | approval requests dashboard |
| `/guarded-rollouts` | Guarded rollouts | automated releases, `/automated-releases/*`, metric-states, exemplar-errors |
| `/ai-configs` | AI Configs | configs, model-configs, prompt-snippets, skills, tools, monitoring, playgrounds, evaluations, judge-templates, agent-graphs/optimizations |
| `/settings` (project) | General | environments, API keys per env, approval settings, observability settings, **audit log lives at `/projects/{k}/audit` → redirects `/settings?activity=true`** |

### 1.3 Other surfaces
- `/settings/escalate` — **session privilege escalation (support/admin impersonation gateway)**, chunk `EscalatePrivileges`
- `confirm-auth/:deviceCode` — device-code auth confirmation (chunk 32936)
- `/choose-organization`, `/join-your-organization/:token`, `/pending-invite/:token`, `/invite/:invitationToken`, `/signup/:token`
- `launchlitely/:projectKey` — AI assistant surface (crashes unauth page render in walk)
- `/foundation-cost-calculator` — beta tool (page render crash observed)
- `/internal/new-hires` — LD-internal tool surface
- `/factory/releases` — internal "factory" dogfooding surface (`/api/v2/account/factory-settings`)
- Views: nested under flags UI (view switcher); standalone `/views` 404s without view context
- Archived flags: `/projects/{k}/flags/archived` (nested `active`/`archived` index routes confirmed in router)

## 2. API endpoint inventory (R1)

**Totals:** 543 unique endpoint patterns (vs. 337 in pre-R1 pass) — `analysis/endpoints_full.txt`
- `/api/v2/*` public API: ~180 patterns
- `/internal/*` app-only: ~330 patterns (250 newly surfaced by chunk pass)
- GraphQL: `POST /graphql` (referenced in product-analytics surface)
- WebSocket: `wss://realtime.courier.com` (notification inbox)
- 45 chunk files send `LD-API-Version: beta` headers (new-version API surface)

### 2.1 Highest-value NEW endpoints (not in any public API docs)
| Endpoint | Why it matters |
|---|---|
| `POST /internal/projects/{p}/assignment-data-sources/{dsKey}/probe` | server-side data-source probe → SSRF candidate (plan-gated) |
| `POST /api/v2/destinations/projects/{p}/environments/{e}/kinds/{kind}/setup` + `/complete-setup` | **new warehouse destination kinds incl. `clickhouse`**; two-phase setup → credential/SSRF surface |
| `POST /api/v2/destinations/projects/{p}/environments/{e}/test-warehouse-destination-connection` | explicit connection tester → SSRF probe |
| `POST /api/v2/destinations/generate-warehouse-destination-key-pair` | key generation for warehouse pairs |
| `GET /internal/projects/{p}/warehouse-native-integrations/{id}/health`, `/metric-data-source-preview` | server-side warehouse connectivity checks |
| `GET /internal/warehouse-integrations-health` | org-wide integration health |
| `POST /internal/device/{deviceCode}` | device-code grant confirmation |
| `GET /internal/accounts/{email}` | **account lookup by email** — enumeration oracle candidate |
| `GET /internal/unauthenticated-members/organization-verifications` (+`/{id}`) | unauthenticated member/org verification surface |
| `POST /internal/account/join`, `/internal/invite/{p}`, `/internal/invite/{p}/mfa` | org-join flows — invite-token entropy/IDOR targets |
| `POST /internal/billingv2/account/subscription/{cooloff-retrial,cooloff-retrial-extension,trial-extension,trial-extension/eligibility,campaigns}` | **billing state machine** — plan/entitlement manipulation candidates |
| `POST /internal/ai-configs/{configKey}/completion` | server-side LLM proxy (beta header) |
| `GET /internal/ai/evaluations/providers`, `/internal/ai/evaluator/token-usage/daily` | AI provider inventory |
| `POST /internal/launchlitely/calculate` | AI assistant action endpoint |
| `/internal/projects/{p}/flag-cleanup/{eligibility,retrieve}`, `/internal/flag-cleanup` | flag cleanup engine |
| `/internal/projects/{p}/flag-templates`, `/internal/projects/{projectKey}/flag-templates/{templateKey}` | flag templates |
| `/internal/projects/{projectKey}/adaptive-triggers` (+`/counts`) | adaptive triggers (new) |
| `/internal/projects/{p}/automated-rollout-configs` (+`/{id}/control`, `/start`) | automated rollout control plane |
| `/internal/projects/{p}/ux-insights/{reports,runs}` | UX insights engine |
| `/internal/projects/{p}/datasets/{id}/{upload-url,download,preview,rows,errors,versions}` | **dataset upload pipeline** → SSRF/path-traversal/IDOR candidates |
| `/internal/resources/project/{p}/environment/{e}/{kind}/{key}/followers[/{memberId}]` | generic resource followers (IDOR surface) |
| `/internal/monitor/events/{eventKey}/metadata`, `POST /internal/projects/{projectKey}/monitor/events/{eventKey}` | monitor event ingestion |
| `/internal/entitlements/{ai-configs,release-guardian}` | plan entitlement checks |
| `/internal/incoming-webhook-subscriptions/providers/{p}[/projects]` | incoming webhooks (GitHub/other → LD) — **spoofing/replay surface** |
| `/internal/integrations/{p}/capabilities/approval/map-members` | integration identity mapping |
| `/api/v2/account/factory-settings[/repos/{p}]` | internal factory repos config |
| `/api/v2/account/ip-allowlist[/{id}]` | org IP allowlist CRUD |
| `/api/v2/account/pending-requests/{kind}` | org join-request handling |
| `/api/v2/approval-requests/{id}/apply`, `/reviews` | approval workflow engine (cross-project apply?) |
| `/api/v2/code-refs/extinctions`, `/statistics/{projectKey}` | code refs |
| `/api/v2/chart/data/analysis/{analysisId}` | product analytics chart data (GraphQL-adjacent) |

### 2.2 Cross-org IDOR candidate list (resource-ID-in-path, org implicit)
From `endpoints_full.txt` — candidates where `{id}` is globally-unique Mongo ObjectId and org scoping is the only barrier:
`/api/v2/members/{id}`, `/internal/members/{id}/access-summary`, `/api/v2/tokens/{id}`(+`/reset`,`/clone`,`/edit`), `/api/v2/teams/{key}`, `/internal/teams/{key}/access-summary`, `/api/v2/auditlog/{id}`, `/api/v2/approval-requests/{id}`, `/internal/comments/{id}`, `/internal/profile/following`, `/internal/resources/.../followers/{memberId}`, `/internal/projects/{p}/datasets/{datasetId}/*`, `/api/v2/destinations/{p}/{e}/{id}`, `/internal/account/domain-verifications/{id}`, `/internal/account/invoices/{id}`, `/api/v2/announcements/{announcementId}`.

## 3. JS corpus (saved to GitHub `js/`)

| Path | Size | Contents |
|---|---|---|
| `js/main/common.js` | 7.9MB | shared vendor+app code |
| `js/main/loadApp.js` | 3.5MB | **full route table** (`spa_routes.json`) |
| `js/main/bootstrap.js` | 77KB | shell bootstrap, session/config wiring |
| `js/main/runtime.js` | 66KB | webpack/rspack chunk map |
| `js/chunks/*.js` | 96MB | **548 lazy-loaded feature chunks** (all 549 module names, incl. AI, observability, product-analytics, billing, authorization) |
| `js/ai/*.js` | 8.8MB | AI Configs deep chunks |
| `analysis/chunk_urls.json` | — | exact source URLs for every chunk |
| `analysis/endpoints_full.txt` | — | 543 endpoint patterns + source chunk provenance |
| `analysis/spa_routes.json` | — | 255 extracted router paths |

## 4. Notable module names (feature modules worth reading)
`AccountImpersonationContainer` · `EscalatePrivileges` · `OrganizationAuthorizationOAuth*` · `OrganizationTokenLimits` · `ObservabilityDatabaseQuery` (SQL-ish query UI) · `product-analytics-*` (cohorts/dashboards/user-attributes) · `Vega{Workflows,Conversation,History,Settings}` (AI workflow engine) · `AgentControlOptIn` · `AgentcontrolWelcome*` · `AIAgentGraphs` · `AIOptimizeAgent` · `FlagsConnect`/`GithubConnect` · `AwsMarketplaceSetup` · `ManageAccountProvisioning` (SCIM) · `SSODomainVerification` · `IPAllowlistSection` · `PromoCodeContainer` · `FacilitatedTrialSignupContainer` · `SpringSignupPage` · `FeaturePreviews` · `SdkEventsQueryDashboard` · `UnauthenticatedTargeting`
