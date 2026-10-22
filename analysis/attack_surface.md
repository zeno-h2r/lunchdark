# LaunchDarkly — Attack Surface Analysis (post R0+R1)

Scope: P1/P2/P3 targets only. Program priorities: cross-org isolation, IDOR, SQLi, RCE, stored/reflected XSS, auth bypass, SSRF, cross-org data leak. Excluded: CSRF (non-sensitive), open redirects, CSP absence, client SDK keys, DoS.

## A. SSRF candidates (server-side fetch with user-controlled target)
| # | Surface | Vector | Pre-test status |
|---|---|---|---|
| A1 | Warehouse destination setup: `POST /api/v2/destinations/projects/{p}/environments/{e}/kinds/{kind}/setup` (kind now includes **clickhouse**; plus redshift/s3/bigquery/databricks/snowflake-v2 complete-setup) | host/endpoint fields in setup payload; `/test-warehouse-destination-connection` is an explicit connect-back | T3 showed 403 plan-gate for destination kinds — **retry clickhouse + check per-kind gating**; `complete-setup` may run after trial upgrade path or via `trial-extension` billing endpoint |
| A2 | `/internal/projects/{p}/assignment-data-sources/{dsKey}/probe` | probe URL | plan/entitlement gated (T3) |
| A3 | `/internal/projects/{p}/warehouse-native-integrations/{cfgId}/{health,metric-data-source-preview}` | warehouse config | needs warehouse integration — check if creation is gated same as destinations |
| A4 | `/internal/projects/{p}/datasets/{id}/upload-url` | upload pipeline (SEC-8991 adjacency) | entitlement unknown — probe |
| A5 | Webhook destinations (already created 2 in [ORG]) | delivery to OAST | **PENDING Burp OAST check** (from T3) |
| A6 | `SdkEventsQueryDashboard` / observability `ObservabilityDatabaseQuery` | query engine target | read chunks first; likely internal-only backend |

## B. Cross-org IDOR / isolation
B1. ObjectId-space resources with org-scoped resolver (T1 tested members/tokens/teams/auditlog/projects — all 404, **no oracle**). Remaining untested IDs:
  - `/api/v2/approval-requests/{id}` (+`/apply`, `/reviews`) — apply action may cross project/org boundary via projectKey injection in body
  - `/internal/comments/{id}` — comments are attached to approval requests/flags; check fetch-by-id
  - `/internal/projects/{p}/datasets/{datasetId}/*` (rows/preview/download) — dataset IDs may not be org-scoped (uploaded via pipeline)
  - `/internal/resources/project/{p}/environment/{e}/{kind}/{key}/followers/{memberId}` — follower add/remove with arbitrary memberId
  - `/api/v2/destinations/{p}/{e}/{id}` — destination ID vs. path project mismatch (put [ORG] destination ID into [TST] path p/e)
  - `/internal/account/domain-verifications/{id}` — domain verification records (global ID?)
  - `/internal/invite/{p}` with [TST] token against [ORG] org id
B2. Key-space confusion: project/env/segment/flag keys are org-unique (T1 confirmed). AI config keys also org-scoped (T2 confirmed). **Un-tested distinguisher: `/internal/projects/{p}/flag-templates/{templateKey}` and `/api/v2/code-refs/repositories/{repo}`** (repo keys may be global per org).

## C. Auth / session / signup surface (newly mapped)
| # | Surface | Test |
|---|---|---|
| C1 | `GET /internal/accounts/{email}` | call as [TST] with [ORG] email → account info leak / enumeration |
| C2 | `/internal/unauthenticated-members/organization-verifications[/{id}]` | hit UNAUTHENTICATED; probe ID for other orgs' verification records |
| C3 | `/internal/device/{deviceCode}` | POST with guessed/leaked deviceCode; check code entropy + rate-limit-exclusion |
| C4 | `/settings/escalate` + `/internal/account/session/escalate` | escalate with non-staff session; check error/entropy; staff-only enforcement |
| C5 | `/internal/invite/{p}`, `/internal/account/signup/{token}/pending-invites`, `/internal/account/suggest-invites` | invite-token entropy (long tokens?), cross-org invite probing, `pending-invites` with guessed tokens |
| C6 | `/internal/account/join` + `/api/v2/account/pending-requests/{kind}` | join-request flow: request → approve self? pending-request ID enumeration |
| C7 | `/choose-organization` flows (`ChooseOrganizationPasswordFormContainer`) | password verification oracle between orgs sharing email |
| C8 | OAuth2 apps (`/internal/account/oauth2/applications`) | create app → authorization-code flow against other org? redirect_uri validation |

## D. Billing / entitlement manipulation (plan-gates are the main blocker for A1-A4)
| # | Surface | Test |
|---|---|---|
| D1 | `POST /internal/billingv2/account/subscription/cooloff-retrial` + `-extension` | retrial state machine abuse as non-owner (role check) |
| D2 | `POST /internal/billingv2/account/subscription/trial-extension/eligibility` | check response body for plan internals; replay/extend logic |
| D3 | `POST /internal/billingv2/account/subscription/campaigns` | campaign code application (PromoCodeContainer) — apply internal campaigns |
| D4 | `/internal/entitlements/{ai-configs,release-guardian}` | probe response shape; try flipping entitlement client-side is useless, but check server trusts request params |
| D5 | `/internal/billingv2/plans/{planType}/limits` | limits reveal + cross-plan limit bypass via API |

## E. Injection / XSS (post-T4 landscape)
E1. Markdown sanitizer blocks javascript:/data:/vbscript; audit titles escaped. Remaining: 
  - AI Config surfaces render LLM output (generationOutput) — stored XSS via AI variation content (test markdown/image rendering in playground results)
  - `/internal/comments` — comment rendering engine (markdown?) on approval requests
  - flag `FlagVegaConversations` — conversation UI renders AI + user content
  - Segment/flag names in email templates (excluded: email HTML injection not reportable)
E2. SQLi: `ObservabilityDatabaseQuery` chunk suggests a query builder — check `/internal/projects/{p}/observability/*` for query endpoints accepting raw SQL/filter DSL (LD Observability has its own storage; filter injection possible)
E3. Template injection: `CodeEditorHandlebarsHighlightPlugin` (client-side only), but flag-templates + `/internal/projects/{p}/flag-templates` may do server-side rendering of templates — probe `{{7*7}}`

## F. New-feature batch (recent 30-90 days, per program "what's new" bias)
- Guarded rollouts / automated releases: `/flags/{f}/environments/{e}/automated-releases/{id}/metric-results/{m}/timeseries`, `automated-rollout-configs/{id}/control` — control-plane actions with weak authz?
- Adaptive triggers `/adaptive-triggers` — trigger firing + rollback actions
- Multi-armed bandits standalone dashboard
- AI agent-graphs/optimizations (already partially tested T2-adjacent)
- Product analytics cohorts: user-attributes ingestion → PII handling cross-org?
- `/internal/insights/scores` + member-metrics — cross-member data exposure?
- LD Connect (`FlagsConnect`, `/api/v2/connect*`?) — org-to-org connection feature = inherently cross-org, verify tenant fencing

## G. Known tripwires (DO NOT TOUCH)
Canary destination UUIDs: `61f60f4a-67c1-42e6-be22-c90979c3f6f0`, `f35b06d5-dc7a-46aa-9de2-0a4fa7d8864f`, `e2925b9c-bcb4-418c-b4c9-a44bee75d7dc`, `7f4f4a74-dea6-42f6-a81a-5ab34ef800aa`, `9fb47fd6-5d44-4c75-9b26-b84d5819f48e`. Any cross-org probe must avoid destination IDs above.

## H. Priority-ordered test queue (next actions)
1. **C1** `GET /internal/accounts/{email}` — 2-min test, potential account disclosure (P2/P3)
2. **C2** unauthenticated organization-verifications — unauthenticated surface (P2/P3)
3. **D3/D1** billing campaigns + cooloff-retrial as [TST] owner (self-org first for validation, then role matrix)
4. **A1** clickhouse destination setup gating (bypass check after D-line entitlement changes)
5. **B1** remaining IDOR: comments, datasets, followers, approval-requests, destinations
6. **C4** escalate endpoint behavior matrix
7. **E1** AI-output stored XSS chain (requires AI Config + conversation UI)
8. **C3** device-code flow
9. **B2** code-refs repo key + flag-templates distinguisher tests
10. **E2** observability query DSL injection
