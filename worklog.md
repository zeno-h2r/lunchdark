# LaunchDarkly Bug Bounty Worklog

**Program:** LaunchDarkly (Bugcrowd, public, safe harbor) | **Hunter:** zeno0 | **Target:** https://app.launchdarkly.com
**Started:** 2026-10-23 | **Focus:** Cross-org isolation, IDOR, authz bypass, XSS, SSRF

---

## Milestone 1 — Session binding & attack surface map (2026-10-23)

### Test accounts (both self-registered via zeno0@bugcrowdninja.com)

| Session | Email | Member ID | Account (org) ID | Project | Project ID | Role |
|---|---|---|---|---|---|---|
| [ORG] | zeno0+org@bugcrowdninja.com | `6ac28fd11c28fb07516cf363` | `6ac28fd11c28fb07516cf361` | zenocrowd (key=default) | `6ac28fd11c28fb07516cf362` | owner |
| [TST] | zeno0+tester@bugcrowdninja.com | `6ac29057ccacd606b1576cb9` | `6ac29057ccacd606b1576cb7` | zenohacker (key=default) | `6ac29057ccacd606b1576cb8` | owner |

- Member creation timestamps ~2 min apart (Mongo ObjectId space overlaps — ID enumeration viable).
- Both sessions validated live via `GET /api/v2/members/me` (200 OK).
- SPA bootstrap: `GET /internal/config/authenticated?project=default&environment=test` (329KB state, includes `allClientSideFlags` with 2,659 LD internal flags — recon for enabled beta surfaces).
- backendVersion: `8f53c9cd2`, frontendVersion: `e3ebfdb78`.

### Endpoint map

Full SPA JS bundles pulled from static.launchdarkly.com (common.js 7.9MB, loadApp.js 3.5MB, bootstrap.js 77KB). 337 unique endpoint paths extracted → `recon/endpoints_raw.txt`.

High-value surfaces:

**Newest features (priority):**
- `POST/GET /internal/ai-configs/{configKey}/completion` — AI completion proxy
- `/api/v2/projects/{p}/agent-graphs`, `/api/v2/projects/{p}/agent-optimizations` (new AI agent surface)
- `/api/v2/projects/{p}/ai-tools`, `/api/v2/projects/{p}/ai-configs/{configKey}` family
- `/internal/projects/{p}/assignment-data-sources/{dsKey}/probe` — server-side probe (SSRF candidate)
- `/api/v2/destinations/{p}/{e}/{id}/test-event` — webhook test dispatcher (SSRF candidate)
- `/internal/projects/{p}/datasets/{id}/upload-url` — upload pipeline (SSRF/path traversal candidate)
- `/internal/projects/{p}/playgrounds`, `/internal/projects/{p}/evaluations`

**Cross-org IDOR candidates (resource ID in path, org implicit from session):**
- `/api/v2/members/{id}` | `/internal/members/{id}/access-summary`
- `/api/v2/tokens/{id}` | `/api/v2/tokens/{id}/reset`
- `/api/v2/teams/{teamKey}` | `/internal/teams/{key}/access-summary`
- `/api/v2/auditlog/{id}` | `/internal/accesses`
- `/api/v2/projects/{projectKey}` (project key must be made unique per org to distinguish)

---

## Technique 1 — Cross-org IDOR (IN PROGRESS)

Plan: as [TST], access [ORG]'s resources by ID/key. Baseline isolation check on `/api/v2/projects` (list), then ID-based probes on members/tokens/teams. If clean, create uniquely-keyed project `zxorg-proj-7f3a` in [ORG] and probe from [TST].

Probes:
1. `[TST] GET /api/v2/members` (list — should only return TST's own org members)
2. `[TST] GET /api/v2/members/6ac28fd11c28fb07516cf363` (ORG member by ID)
3. `[TST] GET /internal/members/6ac28fd11c28fb07516cf363/access-summary`
4. `[TST] GET /api/v2/projects` (list — should only show zenohacker)
5. `[TST] GET /api/v2/auditlog?limit=5` (should only show TST org events)

Results: **ISOLATED — no cross-org access found.**

| Probe ([TST] → [ORG] resource) | Result |
|---|---|
| `GET /api/v2/members` (list) | 200 — only own org members |
| `GET /api/v2/members/6ac28fd11c28fb07516cf363` | 404 `not_found` |
| `GET /internal/members/{id}/access-summary` | 403 `Plan does not allow this operation` (plan-gate, not authz) |
| `GET /api/v2/tokens/6ad9fbdd910326079dc637cf` | 404 `Token not found` |
| `GET /api/v2/auditlog/6ada17625e45b8076673741c` | 404 |
| `GET /api/v2/teams/zeno-team-a` + `/roles` | 404 `team not found` |
| `GET /api/v2/projects/zxorg-proj-7f3a` (distinguisher) | 404 `Unknown project key` |
| `POST /api/v2/flags/zxorg-proj-7f3a` (write probe) | 404 — owner-side confirmed flag absent |
| `POST /internal/projects/zxorg-proj-7f3a/flags/search` | 404 |

Analysis: every resource lookup resolves against the session-bound account ID server-side. `not_found` (not `forbidden`) responses mean org scoping happens at the query layer, not via post-fetch authorization — no oracle to distinguish existing vs non-existing resources cross-org. ID space (Mongo ObjectId) is enumerable but useless without a resolver flaw.

Artifacts left in [ORG]: project `zxorg-proj-7f3a`.

## Technique 2 — AI Configs surface (NEW FEATURE, high yield) (PENDING)

Targets:
- `/api/v2/projects/{p}/ai-configs/{configKey}` family (model-configs, prompt-snippets, skills, ai-tools)
- `POST /internal/ai-configs/{configKey}/completion` — server-side LLM completion proxy (potential SSRF via custom model provider config; prompt-injection; stored XSS via rendered AI output)
- Cross-org access on AI config keys (user-chosen keys → distinguishing-key test)
- `/internal/entitlements/ai-configs` — check plan gating first

### Results

**Completion endpoint mapped:** `POST /internal/ai-configs/{configKey}/completion` requires `LD-API-Version: beta` + body `{"input":{...}}`. Used ONLY by LD-internal automation (judge/autoname configs like `ai-config-autoname-runs`). User-facing test runs go through the **evaluations pipeline** instead:
`POST /internal/projects/{p}/evaluations/{evalId}/runs` → rows contain `generationOutput`, tokens, latency. Playground = evaluations wrapper (`/internal/projects/{p}/playgrounds`, `/evaluations/{id}`).

**Functional validation:** playground run completed end-to-end (Anthropic claude-haiku-4-5-20251001, output "PONG", 46/10k daily tokens).

**Cross-org probes ([TST] → [ORG]):**
| Probe | Result |
|---|---|
| `GET /internal/projects/default/evaluations/{org-guid}` | 404 Evaluation not found |
| `GET .../runs/{run-guid}/rows` | 404 |
| `GET /api/v2/projects/default/ai-configs/zeno-ai-func-1` | 404 AI config not found |
| `POST /internal/ai-configs/zeno-ai-func-1/completion` | 400 `not configured` — SAME error as non-existent key → no existence oracle |

**Verdict: ISOLATED.** No findings.

### Side finding (P5 recon, not reportable standalone)

`allClientSideFlags` → `warehouse-data-export-skip-list-config` (client-side delivered to every authenticated session) leaks LD-internal security instrumentation: ticket refs `SEC-8991 "SSRF probe"`, customer identifiers (Entain/mindbody/ramp/internal accounts), internal probe hosts (`62.169.16.105.nip.io`, `*.sslip.io`, `workers.dev`). Pure metadata exposure — honest severity P5. Recon value: data-export pipeline is SSRF-sensitive per LD's own tickets.

**⚠️ TRIPWIRES — DO NOT TOUCH these destination UUIDs (LD security canaries):**
`61f60f4a-67c1-42e6-be22-c90979c3f6f0`, `f35b06d5-dc7a-46aa-9de2-0a4fa7d8864f`, `e2925b9c-bcb4-418c-b4c9-a44bee75d7dc`, `7f4f4a74-dea6-42f6-a81a-5ab34ef800aa`, `9fb47fd6-5d44-4c75-9b26-b84d5819f48e`

---

## Technique 3 — Data-export SSRF / warehouse probe (BLOCKED)

- ALL data-export destination kinds plan-gated: `403 Destination kind {kind} is unavailable` (snowflake, snowflake-v2, s3, bigquery, databricks, redshift, etc.). SEC-8991 surface unreachable from these accounts.
- `assignment-data-sources` / `metric-data-sources`: empty, feature needs warehouse entitlement.
- Webhooks integration: created 2 hooks in [ORG] (intended functionality, not a finding):
  - `6ada601db9a33f075201c887` → `https://d9c558sobm9hlgrrkssg17bwia6p4dicf.oast.site/ld-webhook-probe`
  - `6ada6031de91770792196bf0` → `https://internal-probe-xyz.invalid-host-d9c558sobm9hlgrrkssg17bwia6p4dicf.oast.site/hook` (non-resolving — error-oracle test)
  - Flag changes fired (`ld-example-ops-maintenance-banner` tag/description patches). **PENDING: check OAST hits in Burp.** No delivery-status/error-echo API exists → no error oracle from webhooks.

**Verdict: BLOCKED by plan gating. No findings.**

Artifacts left in [ORG]: AI configs (`zeno-ai-test`, `zeno-ai-func-1`), model config (`zeno-custom-model`), playground, webhooks above, tag `oast-trigger-1`.

---

## Technique 4 — Audit log markdown/HTML injection via resource names (IN PROGRESS)

Observation: audit log `title` fields render markdown: `[zeno test](mailto:...) created a link to [zeno-webhook-fixture](https://...)`. Customer-controlled resource names (flag names, view names, tags) appear in titles. If the UI renders that markdown raw → stored XSS on any member viewing audit log.

Plan:
1. Create resource with markdown/HTML payload in name in [ORG] low-priv session context
2. Inspect rendered audit log in browser (DOM) for unescaped output
3. Escalate to javascript:/event-handler payloads if HTML survives

Results: **SANITIZED — no finding.**

1. Audit log list view does NOT render raw title markdown. Parser converts `[text](internal-href)` to sanitized React Router links (`/settings/members/{id}`, `/projects/default/flags/{key}`). No external/javascript hrefs observed.
2. Server-side resource-name sanitizer mutates markdown-ish names: `zeno [mdlink](https://example.com/zxprobe) probe` stored as `zeno dlink](https://example.com/zxprobe) probe`; audit titles escape name markdown (`\]\(`, `\-`).
3. Flag descriptions render markdown with live external links (confirmed), BUT sanitizer blocks: `javascript:` (all cases), tab-entity, `data:` URIs, `vbscript:`, raw HTML, reference-style links, `javascript&colon;`. All render as href="" anchors or plain text.

Program explicitly excludes "HTML injection on text fields within the app or emails". No P1-P3 finding.

Artifacts left in [ORG]: metric `zeno-md-probe-1`, flag `zeno-numflag` test payloads.

---

## Technique 5 — Policy engine edge cases via scoped API tokens (IN PROGRESS)

Focus areas: "Privilege escalation that bypasses org isolation controls", "Authorization Issues".

LD policy resources: `proj/{key}:env/{key}:flag/{key}` matched against statements. Edge cases:
1. Case sensitivity (`flag/KEY` vs `flag/key`)
2. URL-encoding normalization (`%2D`, `%2F` splits)
3. Trailing whitespace / unicode lookalikes
4. Wildcard segment matching
5. Cross-project same-key env scoping
6. `/internal/authorization/access-check/{service}/bulk` oracle

Setup: fresh scoped token in [ORG] allowing only `flag/zeno-allowed-*` in `proj/default:env/test`.

Results: **POLICY ENGINE SOLID — no finding.**

Setup learnings:
- Token API requires built-in role OR `customRoleIds` (IDs not keys). `customRoleKeys` silently dropped. `role:null + customRoleIds` = clean scoped token (`zeno-policy-final`, id 6ada62aa7d401b07a495ab9b, bound to role `zeno-restricted-8f3a` id 6ada620f2f4da00753fc44e7).
- Flag-level resources REQUIRE env segment (`proj/x:flag/y` is rejected by parser). Flag-description updates evaluate against EVERY env (deny if any env lacks grant) — hence policy needs `proj/x:env/*:flag/k*`.
- `proj/*` wildcard in first segment rejected by parser.

Baselines (PATCH as scoped token): allowed flag 200, denied flag 403, production env 404 (deny→404 masking).

Edge matrix (all safe): uppercase 404/invalid; %2D not decoded pre-match; dot-dot normalized; extra segments invalid; cross-account resource grammar rejected (`account/{other-org}:proj/x` invalid).

Access-check oracle: `POST /internal/authorization/access-check/gonfalon/bulk` (service enum = `gonfalon`), requires explicit Authorization header; SPA sends `Authorization: document.cookie` (same-origin, no leak — single usage). Oracle reflects policy decisions only; no cross-org expressibility in resource grammar.

Artifacts left in [ORG]: role `zeno-restricted-8f3a`, tokens `zeno-policy-probe` (6ada61dd...), `zeno-policy-final` (6ada62aa...), flags `zeno-allowed-1`/`zeno-denied-1`.

---

## Session status (2026-10-23)

Completed techniques: T1 cross-org IDOR (isolated), T2 AI Configs (isolated), T3 data-export SSRF (plan-gated), T4 audit/markdown XSS (sanitized), T5 policy engine (solid).

Pending user action: check Burp OAST for hits from webhook probes (`/ld-webhook-probe` should HIT from flag-change events; `invalid-host-...` should NOT resolve).

Candidate next techniques:
- T6: Auth/session surface — `/internal/account/session/escalate`, `revoke-sessions`, MFA enable/disable flows, invite-token entropy (`/internal/account/join`, `signup/{token}/pending-invites`, `suggest-invites`)
- T7: SSO/OAuth flows (github/google client IDs in bootstrap), SAML config
- T8: Contexts/segments — big segment rules, context instance access
- T9: Deep dive /internal/ usage endpoints + auditlog search filters (injection in search params)

---

## R0 — Full application exploration (browser walk) — COMPLETE (2026-10-23)

Method: authenticated agent-browser sessions (org account), 60+ routes walked, redirects + titles + headings captured (`recon/r0_walk.txt`).

**Live surfaces confirmed:**
- Account settings: `/settings/{general,projects,members,teams,roles,billing,integrations,relay,sdks}` + **`/settings/authorization` → redirects `/settings/authorization/tokens`** (API tokens + OAuth2 apps UI)
- Project: `/projects/default/{flags,segments,contexts,live,experiments,multi-armed-bandits,holdouts,sessions,errors,logs,traces,observability-metrics,alerts,dashboards,metrics,observe,data-sources/{metrics,assignments,attributes},approvals,guarded-rollouts,ai-configs,settings}`
- Audit log lives at `/projects/{k}/audit` → redirects `/projects/{k}/settings?activity=true`
- Org-level: **`/insights` (Launch Insights)** live
- Escalation UI: `/settings/escalate` (EscalatePrivileges chunk)
- 404-on-direct-GET: `/views`, `/applications`, `/workflows`, `/archived`, `/vega-conversations` (nested/contextual routes), `/foundation-cost-calculator`, `/launchlitely/{p}`, `/internal/new-hires` crash the page render (beta surfaces)

## R1 — JavaScript deep dive — COMPLETE (2026-10-23)

Corpus: runtime.js chunk map parsed (h.u function) → **548 chunk URLs reconstructed + downloaded (96MB)** + main bundles (11.3MB) + AI chunks (8.8MB). All saved to repo `js/`.

**Extraction results:**
- `analysis/endpoints_full.txt`: **543 unique endpoint patterns** (337 prior → +206 net new; 250 new /internal patterns)
- `analysis/spa_routes.json`: 255 router paths incl. `confirm-auth/:deviceCode`, `launchlitely/:projectKey`, `factory/releases`, `judge-templates/:templateKey`
- `LD-API-Version: beta` senders: 45 chunks. GraphQL: `POST /graphql` (product-analytics). WS: `wss://realtime.courier.com`.

**New high-value surfaces (full list in analysis/attack_surface.md):**
- Warehouse/SSRF: clickhouse destination setup (`/kinds/clickhouse/setup` + complete-setup), `test-warehouse-destination-connection`, `generate-warehouse-destination-key-pair`, warehouse-native `{health,metric-data-source-preview}`, datasets `{upload-url,download,preview}`
- Auth/signup: `GET /internal/accounts/{email}` (enumeration candidate), `/internal/unauthenticated-members/organization-verifications` (unauth), `/internal/device/{deviceCode}`, `/internal/invite/{p}`, `/internal/account/join`, `/settings/escalate`
- Billing: `billingv2/account/subscription/{cooloff-retrial,cooloff-retrial-extension,trial-extension,campaigns}` — potential plan-gate unlock path for SSRF surfaces
- IDOR remainder: approval-requests apply/reviews, comments/{id}, datasets/{id}/*, generic followers API, destinations path-mismatch tests
- Injection: observability query DSL, flag-templates server-side rendering, AI output rendering (comments + Vega conversations)

**Deliverables pushed to GitHub `zeno-h2r/lunchdark`:**
- `js/` — full SPA corpus (main/ + 548 chunks/ + ai/)
- `analysis/app_map.md` — complete application map (routes → features → APIs)
- `analysis/attack_surface.md` — prioritized attack surface + test queue (A-H sections)
- `analysis/{endpoints_full.txt,spa_routes.json,chunk_urls.json,r1_meta.json}`
- `worklog.md` — this update

---

## R3 — Hunting round 1 (P1/P2 focus) — 2026-10-23

All results: `recon/r3_*.txt`. Verdict per technique:

| # | Technique | Result |
|---|---|---|
| C1 | `GET /internal/accounts/{email}` (choose-org lookup) | **FENCED** — own-org email 200 (leaks org id/membersCount/signInType, owner-visible anyway), other-org + nonexistent = uniform 403 → no enumeration oracle. Pre-auth `PUT /internal/account/login2` returns `{}` 200 for ALL emails → no oracle. |
| C2 | `/internal/unauthenticated-members/organization-verifications/{id}` | **FENCED** — uniform `404 token not found` (auth + unauth, own id + other id). Token space unexplored (invite-linked). |
| C4 | `/internal/account/session/escalate` | **PASSWORD-GATED** — 401 `Invalid password` for both owner sessions. No bypass. |
| D3 | `PATCH /internal/billingv2/account/subscription/campaigns` | **VALIDATED** — every guessable plan-code (`FOUNDATION2023/2025`, `ENTERPRISE2023`, `PROFESSIONAL2021`, `STARTER2021`, `GUARDIAN2024`, trials) → 400 `campaignType not supported`; subscription state unchanged. User promo codes are Stripe-coupon backed (not guessable). No entitlement forgery. |
| A1 | Warehouse destination v2 endpoints | **PARTIALLY UNGATED, DEFENDED SSRF.** Setup endpoints now 201 for this plan: `kinds/{s3,clickhouse}/setup`, `generate-warehouse-destination-key-pair`. `test-warehouse-destination-connection` + destination CREATE remain kind-gated 403. **`kinds/clickhouse/complete-setup` performs REAL server-side connections** to user-supplied `host` (+port allowed): validation chain = strict host parse → DNS resolve (`Host does not resolve` oracle) → private/metadata IP block (`Host is not permitted`: 169.254.169.254, localhost) → SSRF-service blocklist (all Burp Collaborator TLDs oast.site/.pro/.live/.fun, subdomains, nip.io, trailing dot, uppercase) → TCP connect (s3.amazonaws.com:22/8123 → `ClickHouse connection test failed: An unknown error occurred.`; s3.amazonaws.com default → 504 gateway timeout). Connect errors are UNIFORM — no response oracle. `kinds/s3/complete-setup` does STS `AssumeRoleWithWebIdentity` w/ user ARN (error leaks trust-policy requirements). **Rebinding untestable: rbndr.us/whonow dead. PENDING: user-supplied non-blocklisted callback host for TOCTOU test.** |
| A4 | `/internal/projects/{p}/datasets/*` pipeline | **LIVE + ORG-SCOPED.** Create 201 (got `datasetId` UUID + presigned S3 uploadUrl `launchdarkly-production-us-east-1-user-upload-gfra/ai-evaluator/acc/{accId}/proj/{projId}/datasets/{id}/file.csv`, SigV2 + STS token). Cross-org [TST]→[ORG]: get/upload-url/rows/delete all `404 Dataset not found`; preview validates mode BEFORE authz (Pydantic `RowSelectionInput` verbose errors leak model fields — P5 info only, `mode=all` → 404). upload-url `filename` param NOT reflected in object key (fixed `file.csv`) → no S3 key traversal. |
| B1.3 | Generic followers API (`PUT /internal/resources/.../followers/{memberId}`) | **ORG-SCOPED** — cross-org memberId → 404 `Member not found` (member resolver org-scoped); self-org PUT 204. |
| B1.4 | Approval-requests list | List is org-scoped (both orgs see only own). Create-endpoint path not yet found (my guessed path 404) — TODO grammar from JS. |
| B2 | flag-templates / code-refs | Templates are LD global builtins (identical across orgs — not org data). code-refs repos empty both orgs. `automated-rollout-configs` plan-gated 403. `adaptive-triggers` needs sourceType param. |

**New recon intel:** LD data-export egress IP from clickhouse setup script: `35.192.85.117/32` (GCP us-central1). SEC-8991-style SSRF blocklist confirmed live at warehouse-complete-setup layer (covers oast.*, nip.io, sslip.io, workers.dev patterns).

**Net R3: 0 reportable P1/P2 yet — all surfaces either org-fenced, plan-gated, or parameter-validated.** Highest-potential pending item: warehouse complete-setup rebinding SSRF (needs external callback host), plus un-run: observability query DSL injection (E2), device-code flow (C3), product-analytics `/graphql` surface, approval-request create grammar.

Artifacts created in [ORG]: dataset `zeno-ds-probe` (e3ddcc72-d35e-43f5-8dcd-db74687f1b50); follower on flag `zeno-allowed-1` (ORG member). No canary destination UUIDs touched.

---
Task ID: R3-SSRF
Agent: Super Z (main)
Task: Deep SSRF + server-side fetch surface testing on app.launchdarkly.com using fresh OAST 0xfvy9xf0l070a369a4ln51he8uvdev0h.oast.me

Work Log:
- Matrix 1 (clickhouse dest complete-setup): .oast.me IS blocklisted (all 6 Collaborator TLDs covered); IDN dot tricks (U+3002/FF0E/FF61) rejected by host parser pre-IDNA; metadata.goog + metadata.google.internal blocked; [::ffff:169.254.169.254] blocked; example.com passes; NXDOMAIN oracle confirmed. Surface DEFENDED.
- Webhook layer: NO URL blocklist at creation — accepted http://169.254.169.254/, http://localhost/, http://metadata.goog/, http://metadata.google.internal/, http://[fd00:ec2::254]/ (12 webhooks created, tags zeno-ssrf); only port 80/443 enforced. Redirect following CONFIRMED (httpbin 302 -> webhook.site hit, UA LD-Integrations/1.0). Egress = AWS us-east-1 (54.144.218.89, 34.236.6.43, 54.221.221.197). Delivery status NOT exposed via API -> private-IP reachability unprovable via webhooks.
- Integration manifests: 19 URL/host-bearing integrations enumerated (recon/manifest_*.json). Almost all plan-gated 403 "does not allow integration configurations". custom-approvals NOT gated but create schema unresolved (tried name/config/on/apiKey/baseURL/values/variables/settings/fields/data/configuration/variables — all unknown-field errors; SPA sends {name,config,on} per JS bundle; manifest shows POST {{baseURL}}/api/approvals with Bearer apiKey + Handlebars body).
- Flag import (unleash) = UNGATED at API on Foundation plan. Full characterization: POST /api/v2/integration-capabilities/flag-import/{proj}/unleash {config:{sourceBaseUrl,sourceApiKey,ldApiKey,sourceProjectId,sourceEnvironmentId}} + /trigger.
  * Fetch path: GET {sourceBaseUrl}/api/client/features from AWS 52.21.152.96, arbitrary ports allowed, NO redirect following (302 treated as final response), dial-time Go Control func: "dial tcp HOST:PORT: X is not a public IP address" — catches loopback/link-local/metadata.goog/sslip/nip/IPv4-mapped-v6.
  * FULL ERROR REFLECTION via _status.errors[].message: dial errors, JSON parse first-char, AND full upstream response bodies for non-2xx ("error listing LD flags: {body} (401)"). Public-HTTP port-scan oracle possible.
  * *** POC COMPLETE (reflected SSRF + data injection): attacker JSON served at sourceBaseUrl -> LD parsed features[] -> createFlag executed -> REAL flag "zeno-imported-flag" created (desc/tags attacker-chosen, tag imported-from-unleash). Verified GET /api/v2/flags/default/zeno-imported-flag = 200. Chain blocked ONLY by ldApiKey privileges (writer token sufficed). ***
- Warehouse experimentation ADS (POST /internal/projects/{p}/assignment-data-sources): LIVE surface, integrationKey clickhouse-experimentation accepted; schema needs key+sqlQuery+columnMappings; blocked at "Unexpected JSON representation" (columnMappings shape) — time-boxed. Probe endpoint exists: /assignment-data-sources/{k}/probe.
- OAST usage: webhook W2 (oast.me/wh-direct), import FI3 (oast/unleash-api — LD fetched Collaborator HTML twice, parse error 'invalid character <' proves HTTP interaction), clickhouse V1/V9 blocked pre-DNS. USER: check Burp Collaborator for DNS+HTTP hits from 52.x/54.x AWS.

Stage Summary:
- Artifacts: recon/r3_ssrf_*.txt (phases 1-19), recon/manifest_*.json, scripts/ssrf_*.py (persisted harness).
- Verdict: clickhouse dest + import fetcher + ADS = defended (dial-time public-IP + blocklists + no-redirect). Webhook layer = weakest (no hostname checks at creation, accepts private/metadata URLs, follows redirects) but no status oracle -> impact unprovable blind. Flag-import = full reflection + attacker-JSON->createFlag PoC (by-design fetch, feature is admin-configured; reportable angle = response-driven object creation + body reflection, likely P4/P5 unless paired with plan-gate bypass claim — verify UI gating for Flag Import on Foundation plan first).
- Egress intel: webhooks/imports = AWS EC2 us-east-1; warehouse = GCP 35.192.85.117/32.
- Test assets in [ORG] to clean later: 12 webhooks (zeno-ssrf tag), 7 unleash imports (2 with IMDS URL), flags zeno-imported-flag(-2), tokens zeno-import-poc/zeno-import-writer, datasets/followers from earlier rounds. Canaries untouched.
- Next queue: CA create schema (via UI proxy capture), ADS columnMappings grammar, E2 observability injection, C3 device-code, /graphql surface.
