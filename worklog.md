# Worklog — LaunchDarkly MBB (zeno0 × Super Z)

## 2026-10-22 · Task 0 — Kickoff & infrastructure
- Repo seeded: RULES.md, PROGRAM.md, worklog.md.
- Method locked: dual-account cross-tenant isolation testing (Autorize-driven), IDOR + info-leak hunting across queries and endpoints.
- Sweep order (learn-the-app pass): Agents/AgentControl → AI Configs → Experiments → Telemetry/GenAI traces → Contexts/Segments → Shortcuts → Features → all 15 settings pages.
- Priority intel from program brief: `/private/*` improper accessibility = P1 candidate class (separate auth mechanism, not meant for customer auth); `stream.launchdarkly.com` has 0 known issues (untouched surface); export the 28 known issues on app.launchdarkly.com before claiming anything (dup avoidance).
- Fresh-surface intel (Rule 25): AgentControl shipped 2026-10-09 (13 days old), AI SDK GA 2026-09-03, warehouse-backed experiments 2026-09-23. AgentControl + AI Config monitoring (traces/metrics tabs) = least-battle-tested surfaces in the app.
- Accounts: ORG / TESTER (labels only). Session liveness baseline NOT yet run.
- Findings: none yet.
- Next: (1) baseline scoping curls `/api/v2/members/me` + `/api/v2/projects/default` per session, verify `_id` divergence; (2) seed canary flags `zzx-canary-org` / `zzx-canary-tester`; (3) Autorize sweep — ORG session browsing, TESTER cookie injected; (4) export red rows, triage.
