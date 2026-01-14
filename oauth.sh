#!/usr/bin/env bash
set -euo pipefail
umask 077

CLIENT_ID=${CLIENT_ID:-hytale-server}
SCOPE=${SCOPE:-"openid offline auth:server"}
AUTH_FILE=${AUTH_FILE:-/data/.auth.json}
OUTPUT_FORMAT="env"
PROFILE_USERNAME=${PROFILE_USERNAME:-${HYTALE_PROFILE_USERNAME:-}}
OWNER_UUID=${OWNER_UUID:-}
QUIET=${QUIET:-0}
TOKEN_BUFFER=${TOKEN_BUFFER:-120}

DEVICE_AUTH_URL="https://oauth.accounts.hytale.com/oauth2/device/auth"
TOKEN_URL="https://oauth.accounts.hytale.com/oauth2/token"
PROFILES_URL="https://account-data.hytale.com/my-account/get-profiles"
SESSION_URL="https://sessions.hytale.com/game-session/new"

log() {
  if [[ "${QUIET}" -eq 0 ]]; then
    printf '[oauth] %s\n' "$*" >&2
  fi
}

usage() {
  cat <<'EOF'
Usage: oauth.sh [options]

Options:
  --auth-file PATH           Location to persist OAuth credentials (default: /data/.auth.json)
  --owner-uuid UUID          Owner/player UUID to use for session creation
  --profile-username NAME    Preferred profile username (fallback to first profile)
  --output FORMAT            Output format: env (default) or json
  --quiet                    Reduce logging (only errors)
  --client-id ID             Override OAuth client id (default: hytale-server)
  --scope SCOPE              Override OAuth scope string
  -h, --help                 Display this help and exit

Environment overrides:
  CLIENT_ID, SCOPE, AUTH_FILE, OWNER_UUID, PROFILE_USERNAME, QUIET, TOKEN_BUFFER

The script writes identity/session tokens and OAuth credentials to /data/.auth.json
(unless overridden) and prints the tokens in the requested format.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auth-file)
      AUTH_FILE=$2; shift 2;;
    --owner-uuid)
      OWNER_UUID=$2; shift 2;;
    --profile-username)
      PROFILE_USERNAME=$2; shift 2;;
    --output)
      OUTPUT_FORMAT=${2,,}; shift 2;;
    --quiet)
      QUIET=1; shift;;
    --client-id)
      CLIENT_ID=$2; shift 2;;
    --scope)
      SCOPE=$2; shift 2;;
    -h|--help)
      usage; exit 0;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      usage; exit 1;;
  esac
done

OUTPUT_FORMAT=${OUTPUT_FORMAT,,}

epoch_now() {
  date -u +%s
}

iso_to_epoch() {
  local iso=$1
  python3 - "$iso" <<'PY' || return 1
import sys, datetime
iso = sys.argv[1]
try:
    if iso.endswith('Z'):
        iso = iso[:-1] + '+00:00'
    dt = datetime.datetime.fromisoformat(iso)
except ValueError:
    sys.exit(1)
print(int(dt.timestamp()))
PY
}

epoch_to_iso() {
  local epoch=$1
  python3 - "$epoch" <<'PY'
import sys, datetime
epoch = int(sys.argv[1])
print(datetime.datetime.utcfromtimestamp(epoch).replace(microsecond=0).isoformat() + "Z")
PY
}

load_auth_store() {
  python3 - "$AUTH_FILE" <<'PY'
import json, sys, os, shlex
path = sys.argv[1]
if not os.path.exists(path):
    sys.exit(0)
with open(path) as fh:
    data = json.load(fh)
for key, value in data.items():
    if value is None or isinstance(value, (dict, list)):
        continue
    print(f"AUTH_{key.upper()}={shlex.quote(str(value))}")
session = data.get("session")
if isinstance(session, dict):
    for key, value in session.items():
        if value is None:
            continue
        print(f"AUTH_SESSION_{key.upper()}={shlex.quote(str(value))}")
PY
}

parse_token_response() {
  local json=$1
  OAUTH_JSON="$json" python3 <<'PY'
import json, os, shlex, sys
payload = os.environ.get("OAUTH_JSON", "")
if not payload:
    sys.exit(0)
data = json.loads(payload)
def emit(k, v):
    print(f"{k}={shlex.quote(str(v))}")
if "error" in data:
    emit("ERROR", data.get("error_description") or data["error"])
    emit("ERROR_CODE", data["error"])
else:
    for key in ("access_token", "refresh_token", "expires_in", "token_type"):
        if key in data and data[key] is not None:
            emit(key.upper(), data[key])
PY
}

parse_device_response() {
  local json=$1
  OAUTH_JSON="$json" python3 <<'PY'
import json, os, shlex, sys
payload = os.environ.get("OAUTH_JSON", "")
if not payload:
    sys.exit(0)
data = json.loads(payload)
def emit(k, v):
    if v is not None:
        print(f"{k}={shlex.quote(str(v))}")
if "error" in data:
    emit("ERROR", data.get("error_description") or data["error"])
    emit("ERROR_CODE", data["error"])
else:
    emit("DEVICE_CODE", data.get("device_code"))
    emit("USER_CODE", data.get("user_code"))
    emit("VERIFICATION_URI", data.get("verification_uri"))
    emit("VERIFICATION_URI_COMPLETE", data.get("verification_uri_complete"))
    emit("INTERVAL", data.get("interval"))
    emit("EXPIRES_IN", data.get("expires_in"))
PY
}

parse_profiles_response() {
  python3 - <<'PY'
import json, os, sys
payload = os.environ.get("PROFILES_PAYLOAD", "")
if not payload:
    print(json.dumps({"error": "Empty profile response"}))
    sys.exit(0)
try:
    data = json.loads(payload)
except json.JSONDecodeError as exc:
    print(json.dumps({"error": f"Failed to parse profiles: {exc}"}))
    sys.exit(0)
profiles = data.get("profiles") or []
if not profiles:
    print(json.dumps({"error": "No profiles available for this account"}))
    sys.exit(0)
target = os.environ.get("PROFILE_USERNAME")
selected = None
if target:
    target_lower = target.lower()
    for profile in profiles:
        username = (profile.get("username") or "")
        if username.lower() == target_lower:
            selected = profile
            break
    if not selected:
        print(json.dumps({"error": f"Profile '{target}' not found in account"}))
        sys.exit(0)
else:
    selected = profiles[0]
uuid = selected.get("uuid")
username = selected.get("username")
if not uuid:
    print(json.dumps({"error": "Selected profile missing UUID"}))
    sys.exit(0)
print(json.dumps({"owner_uuid": uuid, "profile_username": username}))
PY
}

parse_session_response() {
  local json=$1
  OAUTH_JSON="$json" python3 <<'PY'
import json, os, shlex, sys
payload = os.environ.get("OAUTH_JSON", "")
if not payload:
    sys.exit(0)
data = json.loads(payload)
def emit(k, v):
    if v is not None:
        print(f"{k}={shlex.quote(str(v))}")
if "identityToken" not in data or "sessionToken" not in data:
    err = data.get("error_description") or data.get("error") or "Session response missing tokens"
    emit("ERROR", err)
else:
    emit("IDENTITY_TOKEN", data["identityToken"])
    emit("SESSION_TOKEN", data["sessionToken"])
    emit("SESSION_EXPIRES_AT", data.get("expiresAt"))
PY
}

save_auth_store() {
  python3 - "$AUTH_FILE" <<'PY'
import json, os, sys, datetime
path = sys.argv[1]
payload = {
    "access_token": os.environ.get("ACCESS_TOKEN"),
    "refresh_token": os.environ.get("REFRESH_TOKEN"),
    "expires_at": os.environ.get("EXPIRES_AT"),
    "owner_uuid": os.environ.get("OWNER_UUID_VALUE"),
    "updated_at": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
}
identity = os.environ.get("IDENTITY_TOKEN")
session = os.environ.get("SESSION_TOKEN")
session_expires = os.environ.get("SESSION_EXPIRES_AT")
if identity or session or session_expires:
    payload["session"] = {
        "identity_token": identity,
        "session_token": session,
        "expires_at": session_expires,
    }
tmp_path = f"{path}.tmp"
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(tmp_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
os.replace(tmp_path, path)
os.chmod(path, 0o600)
PY
}

access_token_valid() {
  local now epoch
  [[ -z "${ACCESS_TOKEN:-}" || -z "${EXPIRES_AT:-}" ]] && return 1
  if ! epoch=$(iso_to_epoch "$EXPIRES_AT"); then
    return 1
  fi
  now=$(epoch_now)
  (( epoch - now > TOKEN_BUFFER )) || return 1
  return 0
}

finalize_token_update() {
  local now expires_epoch adjusted
  [[ -n "${EXPIRES_IN:-}" ]] || EXPIRES_IN=3600
  EXPIRES_IN=${EXPIRES_IN%%.*}
  if ! [[ "${EXPIRES_IN}" =~ ^[0-9]+$ ]]; then
    EXPIRES_IN=3600
  fi
  now=$(epoch_now)
  expires_epoch=$(( now + EXPIRES_IN ))
  adjusted=$(( expires_epoch - TOKEN_BUFFER ))
  if (( adjusted <= now )); then
    adjusted=$(( now + EXPIRES_IN ))
  fi
  EXPIRES_AT=$(epoch_to_iso "$adjusted")
  if [[ -z "${REFRESH_TOKEN:-}" && -n "${AUTH_REFRESH_TOKEN:-}" ]]; then
    REFRESH_TOKEN=${AUTH_REFRESH_TOKEN}
  fi
  unset EXPIRES_IN
}

obtain_with_refresh() {
  [[ -n "${REFRESH_TOKEN:-}" ]] || return 1
  log "Refreshing OAuth access token..."
  local response assignments
  if ! response=$(curl -sS -X POST "$TOKEN_URL" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "client_id=${CLIENT_ID}" \
      --data-urlencode "grant_type=refresh_token" \
      --data-urlencode "refresh_token=${REFRESH_TOKEN}"); then
    log "Refresh request failed"
    return 1
  fi
  assignments=$(parse_token_response "$response")
  eval "$assignments"
  if [[ -n "${ERROR:-}" ]]; then
    log "Refresh error: ${ERROR}"
    unset ERROR ERROR_CODE
    return 1
  fi
  finalize_token_update
  log "Access token refreshed; expires at ${EXPIRES_AT}"
  unset ERROR_CODE
  return 0
}

obtain_with_device_flow() {
  log "Starting device authorization flow..."
  local device_response assignments user_code verification_uri verification_uri_complete device_code expires_in interval poll_interval deadline response token_assign
  if ! device_response=$(curl -sS -X POST "$DEVICE_AUTH_URL" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "client_id=${CLIENT_ID}" \
      --data-urlencode "scope=${SCOPE}"); then
    die "Failed to initiate device authorization"
  fi
  assignments=$(parse_device_response "$device_response")
  eval "$assignments"
  if [[ -n "${ERROR:-}" ]]; then
    die "Device authorization error: ${ERROR}"
  fi
  : "${DEVICE_CODE:?Missing device_code in response}"
  : "${USER_CODE:?Missing user_code in response}"
  : "${VERIFICATION_URI:?Missing verification_uri in response}"
  expires_in=${EXPIRES_IN:-600}
  interval=${INTERVAL:-5}
  if ! [[ "$interval" =~ ^[0-9]+$ ]]; then interval=5; fi
  if ! [[ "$expires_in" =~ ^[0-9]+$ ]]; then expires_in=600; fi
  poll_interval=$interval
  log "----------------------------------------"
  log "Visit: ${VERIFICATION_URI}"
  if [[ -n "${VERIFICATION_URI_COMPLETE:-}" ]]; then
    log "Quick link: ${VERIFICATION_URI_COMPLETE}"
  fi
  log "Enter code: ${USER_CODE}"
  log "Waiting for authorization (timeout ${expires_in}s)..."
  log "----------------------------------------"
  local start now error_code
  start=$(epoch_now)
  deadline=$(( start + expires_in ))
  while true; do
    now=$(epoch_now)
    if (( now >= deadline )); then
      die "Device authorization timed out"
    fi
    if ! response=$(curl -sS -X POST "$TOKEN_URL" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode "client_id=${CLIENT_ID}" \
        --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
        --data-urlencode "device_code=${DEVICE_CODE}"); then
      log "Polling request failed; retrying..."
      sleep "$poll_interval"
      continue
    fi
    token_assign=$(parse_token_response "$response")
    eval "$token_assign"
    if [[ -n "${ERROR:-}" ]]; then
      error_code=${ERROR_CODE:-}
      case "$error_code" in
        authorization_pending)
          sleep "$poll_interval"
          ;;
        slow_down)
          poll_interval=$(( poll_interval + 5 ))
          sleep "$poll_interval"
          ;;
        expired_token)
          die "Device authorization expired before completion"
          ;;
        access_denied|authorization_declined)
          die "Device authorization denied by user"
          ;;
        *)
          die "Unexpected device flow error: ${ERROR}"
          ;;
      esac
      unset ERROR ERROR_CODE ACCESS_TOKEN REFRESH_TOKEN EXPIRES_IN
      continue
    fi
    finalize_token_update
    log "Device authorization complete; access token expires at ${EXPIRES_AT}"
    unset ERROR ERROR_CODE
    return 0
  done
}

fetch_owner_uuid() {
  local response profile_json parse_error resolved_owner selected_username
  log "Fetching account profiles..."
  if ! response=$(curl -sS -X GET "$PROFILES_URL" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" \
      -H 'Accept: application/json'); then
    die "Failed to retrieve account profiles"
  fi

  profile_json=$(PROFILES_PAYLOAD="$response" PROFILE_USERNAME="$PROFILE_USERNAME" parse_profiles_response)
  if [[ -z "$profile_json" ]]; then
    die "Profile selection failed: empty response"
  fi
  parse_error=$(jq -r '.error // empty' <<<"$profile_json")
  if [[ -n "$parse_error" ]]; then
    die "$parse_error"
  fi
  resolved_owner=$(jq -r '.owner_uuid // empty' <<<"$profile_json")
  if [[ -z "$resolved_owner" ]]; then
    die "Profile parser did not return an owner UUID"
  fi
  OWNER_UUID=$resolved_owner
  selected_username=$(jq -r '.profile_username // empty' <<<"$profile_json")
  if [[ -n "$selected_username" ]]; then
    PROFILE_USERNAME=$selected_username
    log "Using profile '${selected_username}' (${OWNER_UUID})"
  else
    log "Using profile UUID ${OWNER_UUID}"
  fi
}

create_game_session() {
  local payload response assignments
  log "Creating new game session..."
  payload=$(python3 - "$OWNER_UUID" <<'PY'
import json, sys
uuid = sys.argv[1]
print(json.dumps({"uuid": uuid}))
PY
)
  if ! response=$(curl -sS -X POST "$SESSION_URL" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" \
      -H 'Content-Type: application/json' \
      -d "$payload"); then
    die "Failed to create game session"
  fi
  assignments=$(parse_session_response "$response")
  eval "$assignments"
  if [[ -n "${ERROR:-}" ]]; then
    die "$ERROR"
  fi
  if [[ -z "${SESSION_EXPIRES_AT:-}" ]]; then
    local now epoch iso
    now=$(epoch_now)
    epoch=$(( now + 3600 ))
    iso=$(epoch_to_iso "$epoch")
    SESSION_EXPIRES_AT=$iso
  fi
  log "Session created; valid until ${SESSION_EXPIRES_AT}"
  unset ERROR
}

output_env() {
  printf 'HTY_IDENTITY_TOKEN=%q\n' "$IDENTITY_TOKEN"
  printf 'HTY_SESSION_TOKEN=%q\n' "$SESSION_TOKEN"
  printf 'HTY_OWNER_UUID=%q\n' "$OWNER_UUID"
  printf 'HTY_SESSION_EXPIRES_AT=%q\n' "$SESSION_EXPIRES_AT"
  printf 'HTY_ACCESS_TOKEN=%q\n' "$ACCESS_TOKEN"
  printf 'HTY_ACCESS_TOKEN_EXPIRES_AT=%q\n' "$EXPIRES_AT"
}

output_json() {
  IDENTITY_TOKEN="$IDENTITY_TOKEN" SESSION_TOKEN="$SESSION_TOKEN" \
  OWNER_UUID_VALUE="$OWNER_UUID" SESSION_EXPIRES_AT="$SESSION_EXPIRES_AT" \
  ACCESS_TOKEN="$ACCESS_TOKEN" EXPIRES_AT="$EXPIRES_AT" \
  python3 - <<'PY'
import json, os
payload = {
    "identityToken": os.environ.get("IDENTITY_TOKEN"),
    "sessionToken": os.environ.get("SESSION_TOKEN"),
    "ownerUuid": os.environ.get("OWNER_UUID_VALUE"),
    "sessionExpiresAt": os.environ.get("SESSION_EXPIRES_AT"),
    "accessToken": os.environ.get("ACCESS_TOKEN"),
    "accessTokenExpiresAt": os.environ.get("EXPIRES_AT"),
}
print(json.dumps(payload, indent=2))
PY
}

if assignments=$(load_auth_store); then
  if [[ -n "$assignments" ]]; then
    eval "$assignments"
  fi
fi

ACCESS_TOKEN=${AUTH_ACCESS_TOKEN:-}
REFRESH_TOKEN=${AUTH_REFRESH_TOKEN:-}
EXPIRES_AT=${AUTH_EXPIRES_AT:-}
STORED_OWNER_UUID=${AUTH_OWNER_UUID:-}

if [[ -z "$OWNER_UUID" && -n "$STORED_OWNER_UUID" ]]; then
  OWNER_UUID=$STORED_OWNER_UUID
fi

if access_token_valid; then
  log "Using cached access token (expires at ${EXPIRES_AT})"
else
  if ! obtain_with_refresh; then
    obtain_with_device_flow
  fi
fi

[[ -n "${ACCESS_TOKEN:-}" ]] || die "Unable to obtain access token"
[[ -n "${REFRESH_TOKEN:-}" ]] || log "Warning: refresh token missing; future renewals may require re-authentication"

if [[ -z "$OWNER_UUID" ]]; then
  fetch_owner_uuid
fi

create_game_session

SESSION_EXPIRES_AT=${SESSION_EXPIRES_AT:-}
IDENTITY_TOKEN=${IDENTITY_TOKEN:-}
SESSION_TOKEN=${SESSION_TOKEN:-}

[[ -n "$IDENTITY_TOKEN" && -n "$SESSION_TOKEN" ]] || die "Failed to obtain identity/session tokens"

mkdir -p "$(dirname "$AUTH_FILE")"
ACCESS_TOKEN="$ACCESS_TOKEN" REFRESH_TOKEN="$REFRESH_TOKEN" \
EXPIRES_AT="$EXPIRES_AT" OWNER_UUID_VALUE="$OWNER_UUID" \
IDENTITY_TOKEN="$IDENTITY_TOKEN" SESSION_TOKEN="$SESSION_TOKEN" \
SESSION_EXPIRES_AT="$SESSION_EXPIRES_AT" \
save_auth_store

case "$OUTPUT_FORMAT" in
  env|"")
    output_env
    ;;
  json)
    output_json
    ;;
  *)
    die "Unsupported output format: $OUTPUT_FORMAT"
    ;;
esac
