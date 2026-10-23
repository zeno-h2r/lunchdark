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

---
Task ID: R3-IDOR-LEAK
Agent: Super Z (main)
Task: IDOR + info-leak hunting (user directive: skip SSRF, keep hunting IDOR/info leak)

Work Log:
- scripts/idor2.py-idor4.py, leak5/6.py, role7-10.py persisted; outputs recon/r3_idor2/3/4.txt, r3_leak5/6.txt, r3_role7/8/9/10.txt
- Cross-org replay [TST]->[ORG] ids: members/{id}, members/{id}/teams, auditlog/{id}, webhooks/{id}, approval-requests/{id}(+/apply,/reviews), domain-verifications/{id} -> ALL 404/403 org-fenced, owner control 200 = clean oracle contrast
- Approval-request grammar solved: POST /api/v2/projects/{p}/flags/{f}/environments/{e}/approval-requests {description,instructions:[{kind:turnFlagOn}]} -> 201, AR id 6ada9379831a640734b4ffda; apply blocked by minNumApprovals (405 w/ message); cross-org apply/reviews 404
- comments: POST /internal/comments requires resourceId+mentionedUserIds+comment; resourceId URN formats from chunks: proj/{p}:env/{e}:flag/{f} and proj/{p}:env/{e}:experiment/{e} BOTH -> "Invalid resource ID format" (time-boxed out)
- domain-verifications: PATCH cross-org -> 404 fenced; own-org PATCH /isVerified triggers real TXT lookup ("failed to find matching TXT record")
- invite/{accId} POST = password step-up ("Invalid password") both orgs; suggest-invites 204 no content; device/{code} uniform 400 "bad device code" (no oracle)
- ROLE MATRIX (new axis): reader API token vs owner. Reads (members/auditlog/tokens/webhooks/teams/projects) 200 = by-design reader scope. Writes: token-create/member-invite/project-create/own-token-policy-patch -> 403 w/ policy action disclosure (action:createAccessToken etc = P5). /internal/* rejects API tokens entirely (401 Invalid account ID header) = session-only fence.
- FLAG-PATCH ANOMALY CLOSED: r8 reader PATCH flag name 200 -> isolated as NO-OP policy short-circuit: merge-patch with fields equal to current values returns 200 WITHOUT state change (version unchanged); real change -> 403 updateName. Not a write primitive (P5 curiosity, do not report as priv-esc).
- INFO LEAK sweep: 613 chunks secret-scanned (rg): 0 secrets/JWTs/internal hosts/staff emails; no stack traces anywhere; JSON-Schema validation messages leak property names/types (P5); billing 403 leaks internal policy action names (P5); auditlog attributes token actions to member email (token=None).
- Cleanup: 6 test tokens (zeno-reader-r7..r11, zeno-writer-r9) deleted. Created: AR 6ada9379..., flags zeno-esc-target/zeno-esc-proj-nope, webhook esc attempt (400, none created).

Stage Summary:
- IDOR verdict: cross-org object resolvers universally org-fenced; no IDOR found in members/auditlog/webhooks/approvals/domain-verifications/datasets/followers.
- Role authz verdict: policy engine correct on all real writes; only no-op-patch short-circuit (P5).
- Info-leak verdict: no secrets, no stack traces; only P5-grade schema/policy-action reflections.
- Net this round: 0 reportable P1/P2; P5 notes logged. Remaining untested: comments resourceId grammar (blocked), invite-token entropy (needs password step-up we don't have).

---
Task ID: R4-LEARN
Agent: Super Z (main)
Task: Keep learning the app — refresh JS corpus, map new surfaces, live characterization

Work Log:
- New runtime runtime.2ae60dfa8499d398.js parsed (name map inline in h.u): 547 chunks, 0 new names, 24 updated hashes (Application views, observability.shared, AiEvaluationRuns, AiLibraryDatasets, CreateOrJoinSwitcher, Profile...). Diff saved analysis/chunk_diff_new.txt.
- Downloaded common.js (7.7MB) + observability.shared.js (3.4MB); 21 others CDN-403. Extracted 379 endpoints -> analysis/endpoints_new.txt.
- Live GET sweep: Views/Layers/Holdouts/ReleasePolicies/Roles/ContextKinds/SDK-keys/AI-evals/Playgrounds all live on Foundation plan; release-plans 403 gated.
- MAPPED the new generic query engine (chart/data + list/data): full DSL via validation-oracle mining + SPA bundle extraction (scripts/learn1-7.py). Valid queries return 200 with real data (traces span zeno.genai.probe).
- E2 (query injection) tested to closure: enum + parameterization = defended; cross-org projectKey fenced; op/type enums leak in errors (P5).
- verify-code/forgot/contact-us: no enumeration oracles (uniform responses).
- access-check bulk: service=app-api valid, needs Authorization header param; validator inconsistency with/without header (P5, time-boxed).
- SDK-keys API returns full key values on GET (own-org by-design; reader-role visibility unverified).
- AI evals/playgrounds/layers/views cross-org: uniform 404 = org-fenced.
- attack_surface.md updated with §I (R4 results + next queue).

Stage Summary:
- Net: E2 closed as defended; query-API grammar fully documented; new feature surfaces (views/layers/evals) all org-fenced on first cross-org probe; no P1/P2 from learning round.
- Artifacts: recon/r4_learn1-7.txt, analysis/endpoints_new.txt, analysis/chunk_diff_new.txt, scripts/learn*.py.
- Next queue: segment exports IDOR (file download), layers experiments cross-org, evaluation runs write-verbs cross-org, AI completion grammar, access-check bulk full body.

---
Task ID: R5-HUNT
Agent: Super Z (main)
Task: "start hunting" — R5 round: segment exports IDOR, no_access escalation, /internal via API tokens, layers/experiments cross-org, relay configs, flag-import gating

Work Log:
- scripts/r5_hunt1-5.py persisted; outputs recon/r5_hunt1-5.txt
- SEGMENT EXPORTS (last live IDOR candidate): POST /api/v2/segments/{p}/{e}/{s}/exports -> 204 + Location header w/ UUID id (id only via Location header; regular segments 500, big/unbounded segments work). GET export: status in_progress->complete, then _links.file = PRESIGNED S3 URL (SigV4 + STS token, X-Amz-Expires=600). Cross-org [TST] GET -> 500 "Error looking up export" (uniform 500 for non-existent too -> NO existence oracle; 500-not-404 = sloppy error, P5). Unauth -> 401. S3 layer locked: unsigned GET 403, list-type=2 own-prefix 403, dir listing 403. VERDICT: DEFENDED. Bucket name/path structure disclosed: launchdarkly-bigsegment-files-production/acct-{accId}/env-{envId}/exports/{segKey}/{exportId}/{segKey}.csv.
- FINDING_002 STRENGTHENED (no_access bypass, read-only): newly confirmed 200s under no_access token: GET /api/v2/account (org name, requireMfa, sessionConfig), GET /api/v2/account/relay-auto-configs[/{id}] (INCL. FULL POLICY DOCUMENTS proj/*:env/*:* + creator identity/email), GET /api/v2/usage + usage/{streams,streams/server,data-export-events,warehouse-export}, GET /api/v2/code-refs/repositories, GET /internal/entitlements/release-guardian ({"state":"enabled",usageGatedTrials}). All WRITE verbs correctly 403 (createCodeRefsRepository, createAccessToken, createWebhook, updateAccessTokenName) -> bypass strictly READ-ONLY, no priv-esc.
- /internal/* + API tokens: newer internal endpoints use unified policy middleware (NOT the old account-header fence): project-scoped ones 403 viewProject (correct); /internal/entitlements/release-guardian 200 = fence miss (entitlement state only, P5); /internal/comments accepts API tokens (400 resourceId invalid, not 401) — but comments resourceId grammar STILL unsolved (URN formats proj/{p}:env/{e}:flag/{f} + 9 variants all "Invalid resource ID format"; GET query-param form probed too) — permanently time-boxed.
- Layers/experiments cross-org: layer-by-key GET=405 path quirk; experiments: [TST] GET/reload on ORG experiment key -> 404 uniform (fenced); PATCH needs {comment,instructions:[...]} semantic body (updateTags/updateMaintainerId kinds; updateTags value field name unresolved — time-boxed).
- Evaluation runs cross-org write: POST runs on ORG eval id as [TST] -> 404 fenced; DELETE -> 405 (no such route). Fenced.
- Destinations list endpoint times out server-side (>45s, 2 attempts) — skipped, canaries untouched.
- Flag-import gating CLOSED: allClientSideFlags enable-flag-import-integration=True on Foundation plan -> R3 flag-import SSRF reflection chain is a legitimately-enabled feature (no plan-gate-bypass angle; stands at P4/P5 as response-reflection finding, not recommended for submission).
- Cleanup: all r5 tokens/roles deleted (r5/r5b/r5c/r5d), segments zeno-bigseg-r5 + zeno-export-seg deleted. No canary UUIDs touched. Artifacts: exports can't be deleted via API (405) but bigseg deletion cascades.

Stage Summary:
- Net R5: segment-export IDOR = DEFENDED (presigned S3, no cross-org oracle); no_access bypass = READ-ONLY + endpoint list expanded (strengthens FINDING_002 to ~11 endpoint families incl. policy documents + relay configs); entitlements/release-guardian = first /internal bypass (P5 content); experiments/eval-runs cross-org fenced; flag-import plan-gate angle closed.
- Reportable inventory unchanged: FINDING_001 (P3 obs cross-tenant injection) + FINDING_002 (P2 no_access read bypass, now stronger). Nothing new reportable this round.
- Next queue: patch/verify FINDING_002 repro with expanded endpoint table and submit P2; optionally FINDING_001 as P3; new-round ideas: OAuth2 apps redirect_uri validation (C8), SSO/SAML flows (T7), contexts instance access (T8), auditlog search filter injection (T9).

---
Task ID: R6-IDOR-LEAK
Agent: Super Z (main)
Task: "keep hunt idor, info leak" — R6 round: webhook secret vs no_access, cross-org scoping of the bypass, scheduled-changes/contexts/OAuth2/insights/legacy IDOR remainder

Work Log:
- scripts/r6_hunt1-2.py persisted; outputs recon/r6_hunt1.txt, r6_hunt2.txt
- *** WEBHOOK SIGNING SECRET LEAK: GET /api/v2/webhooks/{id} under no_access token returns "secret" field (HMAC-SHA256 webhook signing key) + target URL. Verified twice with fresh tokens. List view omits it, detail GET leaks it. Reader role also sees secret (LD models reader=view-all) -> framing: zero-privilege token discloses signing secret -> forged X-LD-Signature events against customer endpoints (CI/CD hooks). Added to FINDING_002 as impact upgrade. ***
- CROSS-ORG SCOPING OF BYPASS RE-VERIFIED: ORG no_access token -> TST member/webhook ids 404; auditlog/tokens/roles/relay/account 200s contain ONLY own-org data (account resolved from token). Bypass strictly intra-account -> stays P2, not P1.
- scheduled-changes: create 201 (executionDate+instructions+comment), cross-org [TST] GET/DELETE -> 404 "flag not found" (fenced, clean 200/404 contrast)
- contexts/search: 0 items in test env (no instance data -> instance cross-org untestable, time-boxed)
- OAuth2 apps: GET list 200 (empty); POST create 405 (route shape unresolved, time-boxed)
- insights member-metrics: memberId param IGNORED (uniform aggregate response own-org; TST->ORG memberId same shape) -> no cross-member leak
- automated-releases list endpoint 404 (no data); legacy API shapes (/api/flags, /api/v1, /api/evaluate) all dead 404 HTML
- AR detail: no comments embedded; [TST] cross-org AR fetch 404 fenced
- Cleanup: r6 noaccess/reader/org-tok-for-id tokens + role + both test webhooks deleted. Canaries untouched.

Stage Summary:
- FINDING_002 impact upgraded: webhook signing-secret disclosure via zero-privilege token (forge signed LD events). Cross-org check confirms intra-account scope (P2 holds).
- IDOR remainder closed: scheduled-changes/contexts/AR/legacy/insights all fenced or empty.
- Reportable inventory: FINDING_001 (P3 obs injection), FINDING_002 (P2, now incl. secret disclosure). Ready to draft reports.
