"""Checks a deployed WAYMATE from inside its VM: every service answers on the
one hostname, federation is closed, and a user can sign in and get as far as
a LiveKit token for a call in their room, both the way current clients ask
for it and the way older ones do.

    python3 check.py DOMAIN

Run by deploy-test.sh while WAYS sign-in is off, so it can make an account
with a password. Standard library only.
"""

import base64
import json
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

domain = sys.argv[1]
base = f"https://{domain}"


def call(method, path, body=None, token=None, want=200):
    """One request; returns the parsed JSON body, or the text if it isn't JSON."""
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as err:
        status, raw = err.code, err.read()
    if status != want:
        sys.exit(f"FAIL {method} {path}: status {status}, want {want}: {raw[:400]!r}")
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode(errors="replace")


def check(what, ok):
    if not ok:
        sys.exit(f"FAIL {what}")
    print(f"ok   {what}")


# Every part answers on the one hostname.
check("Synapse answers", "versions" in call("GET", "/_matrix/client/versions"))
wellknown = call("GET", "/.well-known/matrix/client")
check("clients are pointed at the homeserver", wellknown["m.homeserver"]["base_url"] == base)
check(
    "clients are pointed at the call backend",
    wellknown["org.matrix.msc4143.rtc_foci"][0]["livekit_service_url"] == f"{base}/livekit/jwt",
)
issuer = call("GET", "/auth/.well-known/openid-configuration")["issuer"]
check("MAS answers under /auth/", issuer == f"{base}/auth/")
check("Synapse hands sign-in to MAS", call("GET", "/_matrix/client/v1/auth_metadata")["issuer"] == issuer)
check("the MAS sign-in page loads", "<html" in call("GET", "/auth/login").lower())
check("Element Web is served", "<title>" in call("GET", "/"))
config = call("GET", "/config.json")
check(
    "Element Web is fixed to this homeserver",
    config["default_server_config"]["m.homeserver"]["base_url"] == base and config["disable_custom_urls"] is True,
)
call("GET", "/livekit/jwt/healthz")
check("the MatrixRTC authorization service answers", True)
check("LiveKit answers", "OK" in call("GET", "/livekit/sfu/"))

# Federation is closed, and the admin APIs are not served.
call("GET", "/_matrix/federation/v1/version", want=404)
call("GET", "/_matrix/key/v2/server", want=404)
check("federation is closed", True)
call("GET", "/_synapse/admin/v1/server_version", want=404)
call("GET", "/_synapse/mas/is_localpart_available?localpart=x", want=404)
check("the admin APIs are not served", True)

# A user signs in.
handle = "t" + secrets.token_hex(4)
password = secrets.token_urlsafe(24)
subprocess.run(
    ["waymate-mas", "manage", "register-user", "--yes", "--password", password, handle],
    check=True,
    capture_output=True,
)
login = call(
    "POST",
    "/_matrix/client/v3/login",
    {"type": "m.login.password", "identifier": {"type": "m.id.user", "user": handle}, "password": password},
)
token, user_id, device_id = login["access_token"], login["user_id"], login["device_id"]
check("a new account signs in through MAS", user_id == f"@{handle}:{domain}")
check("Synapse accepts the session", call("GET", "/_matrix/client/v3/account/whoami", token=token)["user_id"] == user_id)

# They get as far as a LiveKit token for a call in their room.
transports = call("GET", "/_matrix/client/v1/rtc/transports", token=token)["transports"]
check("Synapse advertises the LiveKit transport", {t["type"] for t in transports} == {"m.livekit", "livekit"})
sfu = next(t["url"] for t in transports if t["type"] == "m.livekit")
room_id = call("POST", "/_matrix/client/v3/createRoom", {}, token=token)["room_id"]


def livekit_claims(jwt):
    payload = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


# The current way: through Synapse, which hands the request to the service.
jwt = call(
    "POST",
    "/_matrix/client/v1/rtc/livekit/get_token",
    {"url": sfu, "room_id": room_id, "slot_id": "m.call#ROOM", "member_id": secrets.token_hex(8)},
    token=token,
)["jwt"]
check("a call token through Synapse", livekit_claims(jwt)["video"]["roomJoin"] is True)

# The older way: straight to the service, proving who they are with OpenID.
openid = call("POST", f"/_matrix/client/v3/user/{urllib.parse.quote(user_id)}/openid/request_token", {}, token=token)
legacy = call("POST", "/livekit/jwt/sfu/get", {"room": room_id, "openid_token": openid, "device_id": device_id})
check(
    "a call token the older way",
    legacy["url"] == sfu and livekit_claims(legacy["jwt"])["video"]["roomJoin"] is True,
)

# Someone who is not in the room gets no token for it.
other = "t" + secrets.token_hex(4)
subprocess.run(
    ["waymate-mas", "manage", "register-user", "--yes", "--password", password, other],
    check=True,
    capture_output=True,
)
other_token = call(
    "POST",
    "/_matrix/client/v3/login",
    {"type": "m.login.password", "identifier": {"type": "m.id.user", "user": other}, "password": password},
)["access_token"]
status = None
try:
    urllib.request.urlopen(
        urllib.request.Request(
            f"{base}/_matrix/client/v1/rtc/livekit/get_token",
            data=json.dumps(
                {"url": sfu, "room_id": room_id, "slot_id": "m.call#ROOM", "member_id": secrets.token_hex(8)}
            ).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {other_token}"},
            method="POST",
        ),
        timeout=30,
    )
    status = 200
except urllib.error.HTTPError as err:
    status = err.code
check("no call token for a room they are not in", status in (403, 404))

print("PASS")
