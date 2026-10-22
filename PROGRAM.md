# Program — LaunchDarkly Managed Bug Bounty Engagement

- Platform: Bugcrowd (`launchdarkly-mbb-og`) · Public · Full Safe Harbor
- Started 2026-05-19 · Status: in progress · Scope rating 2/4
- 53 vulnerabilities rewarded · avg payout last 3 mo $1,210 · triage ~5 days (75% accepted/rejected)

## Bounty tiers
- P1 $6,500–7,500 · P2 $2,500 · P3 $1,250 · P4 $150

## In scope
| Target | Notes | Known issues |
|---|---|---|
| app.launchdarkly.com | Frontend + /api/v2/ + /internal/ + /private/ | 28 |
| events.launchdarkly.com | SDK event recorder | 1 |
| stream.launchdarkly.com | Flag streaming for SDKs | 0 |
| LaunchDarkly Open Source SDKs | only repos ending in `-sdk` | 6 |
| docs.launchdarkly.com | static docs site | 0 |
| launchdarkly.com/docs | docs path on marketing site | 5 |

Stack (per brief): Elasticsearch, PostgreSQL, ReactJS, MongoDB, JavaScript / AWS, Go (events, stream).

## Auth model (verbatim intent from program brief)
- `/api/v2/` and `/internal/` are customer-facing: require valid `ldso` session cookie OR access token (`Authorization` header). Access tokens can be created from Account Settings in the UI.
- `/private/` APIs are NOT meant to allow authentication to any non-LaunchDarkly users and use a separate authentication mechanism. Any case where these endpoints are improperly accessible is worthy of note. → Highest-value target class: auth bypass here is a P1 candidate.
- Streamer (`stream.launchdarkly.com`) and Event Recorder (`events.launchdarkly.com`): SDK-facing; interested in general API findings and handler logic vulnerabilities. Test SDK↔server communication with SDK keys/client IDs generated from the UI.

## Focus areas
- Cross-organization (multi-tenant) isolation: cross-org IDOR, SQL injection, RCE
- Unauthorized data access across org boundaries
- Privilege escalation that bypasses org isolation controls
- Stored or reflected XSS · authentication issues · authorization issues · data exposure
- SSRF, RCE from misconfigurations, network-level access to internal services

## Out-of-scope hosts
blog.launchdarkly.com · launchdarkly.com · sandbox.launchdarkly.com · slack.launchdarkly.com · status.launchdarkly.com · launchdarkly.atlassian.net

## Key exclusions (condensed)
Third-party integrations/endpoints · availability/volumetric (DoS, rate-limit abuse, email bombing) · all social engineering · clickjacking without sensitive actions · CSRF on unauthenticated/non-sensitive forms · MITM/physical access · known-vulnerable libraries without working PoC · CSV injection without platform-specific impact · SSL/TLS best-practice gaps · service disruption · content spoofing/text injection without attack vector · rate limiting on non-auth endpoints · CSP best-practice gaps · cookie flags except `ldso` HttpOnly · email best practices · outdated-browser-only issues · uncommon-extension-only issues · version/banner/error disclosure · public zero-days patched <1 month (case-by-case) · tabnabbing · open redirect without additional impact · unlikely user interaction · non-SDK repo findings · dependency-scan-only results · client-side SDK keys (JS/mobile) · public web tokens (Algolia, TrackJS, etc.) · Jira ServiceDesk public registration · verification email spam · HTML injection in text fields or app-generated emails · password-reset link persistence after email change.

## Testing accounts
- Primary: zeno0@bugcrowdninja.com. Program prefers @bugcrowdninja.com signups; dual-account testing is sanctioned.
- Labels used in worklog: ORG account / TESTER account. Credentials are never stored in this repo.
