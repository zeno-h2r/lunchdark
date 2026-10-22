# Program: LaunchDarkly Managed Bug Bounty Engagement

- Platform: Bugcrowd
- Status: Public (as of Sep 02, 2025)
- Safe Harbor: Full
- Average payout: $454.54
- Validation time: ~5 days
- 53 vulnerabilities rewarded so far
- Accounts: personal or @bugcrowdninja.com signup (preferred)

## Bounty Tiers
- P1: $6500–$7500
- P2: $2500
- P3: $1250
- P4: $150

## In Scope
- https://launchdarkly.com/docs
- app.launchdarkly.com  ← PRIMARY TARGET
- LaunchDarkly Open Source SDKs (repos ending in -sdk)

## Focus Areas
- Cross-Organization (Multi-Tenant) Isolation: Cross-Org IDOR, SQLi, RCE
- Unauthorized data access across org boundaries: Cross-Org IDOR, SQLi, Stored XSS, Auth Bypass
- Privilege escalation bypassing org isolation
- Stored/Reflected XSS
- Authentication Issues
- Authorization Issues
- Data Exposure
- SSRF, RCE from misconfigurations, network-level access (internal port scanning / internal services)

## Out of Scope
- blog.launchdarkly.com, launchdarkly.com, sandbox.launchdarkly.com, slack.launchdarkly.com, status.launchdarkly.com, launchdarkly.atlassian.net

## Excluded Submission Types (condensed)
- Support team interfaces (chat bots, forms, ticket/notification generators)
- Third-party integrations and endpoints
- Availability/volumetric testing: DoS/DDoS, rate limiting bypass, email bombing, flooding
- ALL social engineering
- Clickjacking without sensitive actions; CSRF on unauthenticated/no-sensitive-action forms
- MITM or physical access attacks
- Known vulnerable libraries without working PoC
- CSV injection without LD-platform-specific vulnerability
- SSL/TLS config best practices
- Rate limiting/bruteforce on non-auth endpoints
- CSP best practices
- Missing HttpOnly/Secure flags (except ldso cookie)
- Email best practices (SPF/DKIM/DMARC)
- Outdated/unpatched browsers (2+ stable versions behind)
- Uncommon browser extension issues
- Open redirects without additional security impact
- Tabnabbing
- Issues requiring unlikely user interaction
- Non-SDK repos (not ending in -sdk)
- Dependency/scan results of source code
- Client-side SDK keys / public tokens (Algolia key, TrackJS token, etc.)
- Jira ServiceDesk public registration
- Verification email inbox spam
- HTML injection on text fields within app or app-generated emails
- Password reset link not expiring after email change
