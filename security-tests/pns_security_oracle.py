#!/usr/bin/env python3
"""PNS negative-path oracle for source-only mirror CI."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
PNS = ROOT / "src/main/kotlin/de/eudiwallet/backend/pns"
failures = []

def require(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)

api = (PNS / "PnsApi.kt").read_text(encoding="utf-8")
service = (PNS / "PnsService.kt").read_text(encoding="utf-8")
fcm = (PNS / "FcmConfiguration.kt").read_text(encoding="utf-8")
client = (PNS / "FcmPushClient.kt").read_text(encoding="utf-8")

require("@field:NotBlank" in api, "PNS API accepts blank registration tokens")
require("MAX_MPP_REGISTRATION_TOKEN_LENGTH" in api, "PNS API token upper bound missing")
require("mppRegistrationToken.isNotBlank()" in service, "PNS service lacks blank-token guard")
require("mppRegistrationToken.length <= MAX_MPP_REGISTRATION_TOKEN_LENGTH" in service, "PNS service lacks token upper bound")

for invariant in (
    'uri.scheme.equals("https", ignoreCase = true)',
    'uri.host.equals(FCM_HOST, ignoreCase = true)',
    "uri.rawUserInfo == null",
    "uri.port == -1 || uri.port == 443",
    "uri.rawQuery == null && uri.rawFragment == null",
    'uri.rawPath.isNullOrEmpty() || uri.rawPath == "/"',
    'URI("https", null, FCM_HOST, -1, null, null, null)',
):
    require(invariant in fcm, f"FCM origin invariant missing: {invariant}")

require("GOOGLE_PROJECT_ID.matches(config.projectId)" in fcm, "FCM project ID is not structurally bounded")
require("got ${config.baseUrl}" not in fcm, "FCM validation leaks configured endpoint into errors")
require("${ex.message}" not in client, "PNS transient errors expose exception messages")
require('"Bearer $accessToken"' in client, "expected FCM bearer handoff changed; re-review credential boundary")

if failures:
    print("PNS SECURITY ORACLE: FAIL", file=sys.stderr)
    for failure in failures:
        print(f" - {failure}", file=sys.stderr)
    raise SystemExit(1)

print("PNS SECURITY ORACLE: PASS")
