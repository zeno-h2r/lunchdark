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

Results: (pending)

---
