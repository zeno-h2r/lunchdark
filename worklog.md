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

---
