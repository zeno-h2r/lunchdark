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
