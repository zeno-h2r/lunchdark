# Bugcrowd Submission Drafts — LaunchDarkly (zeno0)

Submission-ready English reports generated from the FINDING docs. Each is self-contained with copy-paste repro, negative controls, and honest severity arguments.

| # | File | Finding | Proposed severity | Submit? |
|---|------|---------|-------------------|---------|
| 1 | `SUBMISSION-1_P2_zero-privilege-token-and-demo-host-authz-bypass.md` | FINDING_002 + FINDING_004 (combined — same defect class, two hosts, zero-auth variant included) | **P2 (argue P1 on the SDK-key chain)** | **RECOMMENDED FIRST** — strongest report |
| 2 | `SUBMISSION-2_P3_observability_cross_tenant_injection.md` | FINDING_001 (4 verified unauth mutations, read isolation intact) | P3 | Submit after #1 (correlating disclosure: `/internal/config/anonymous` leaks the shared `observabilityProjectID`) |
| 3 | `SUBMISSION-3_P3_anonymous_bootstrap_internal_state_disclosure.md` | FINDING_003 (324 KB internal flag state, roster, incident comms) | P3 (P4 possible — honest counter-argument included) | Optional; submit last |

Submission-order rationale: #1 is self-sufficient and highest severity. #2 references data from #3's endpoint (shared project ID) — submitting #1 first, then #2, then #3 keeps each report's dependencies already in triage's hands.

Program notes respected in framing:
- "Client-side SDK keys (JS/mobile)" exclusion → reports anchor on **server-side `sdk-` keys + webhook HMAC signing secrets + broken access control**, not clientSideId.
- `demo.app.launchdarkly.com` framed as subdomain of in-scope `app.launchdarkly.com`.
- Observability ingestion host framed as backend of the product surface configured by the in-scope app.
