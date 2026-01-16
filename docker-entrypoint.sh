#!/usr/bin/env bash
set -euo pipefail

AUTH_HELPER_PATH=""
AUTH_STORE_PATH=""
AUTH_REFRESH_MAINTENANCE_PID=""

log() {
    printf '[hytale-entrypoint] %s\n' "$*" >&2
}

die() {
    log "Fatal: $*"
    exit 1
}

run_user_command_if_requested() {
    if [[ $# -gt 0 && "$1" != -* ]]; then
        log "Delegating to user-supplied command: $*"
        exec "$@"
    fi
}

split_words() {
    local input=${1-}
    local -n _out=$2
    _out=()
    if [[ -n ${input// } ]]; then
        read -r -a _out <<<"$input"
    fi
}

resolve_python_bin() {
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' python3
        return 0
    fi
    if command -v python >/dev/null 2>&1; then
        printf '%s' python
        return 0
    fi
    return 1
}

sanitize_unsigned_integer() {
    local value=$1
    local default_value=$2
    local var_name=$3
    if [[ $value =~ ^[0-9]+$ ]]; then
        printf '%s' "$value"
        return
    fi
    if [[ -n ${value// } ]]; then
        log "Ignoring invalid ${var_name}='${value}' (expected non-negative integer)"
    fi
    printf '%s' "$default_value"
}

render_server_config() {
    local config_path=${HTY_CONFIG_PATH:-/data/config.json}
    local config_dir
    config_dir=$(dirname "$config_path")
    mkdir -p "$config_dir"

    local python_bin
    if ! python_bin=$(resolve_python_bin); then
        die "render_server_config requires python but it was not found in PATH"
    fi

    local server_name=${HTY_SERVER_NAME:-Hytale Server}
    local motd=${HTY_SERVER_MOTD:-Docker Hytale Server}
    local password=${HTY_SERVER_PASSWORD:-}
    local default_mode=${HTY_DEFAULT_GAME_MODE:-Adventure}
    local default_world=${HTY_DEFAULT_WORLD_NAME:-default}
    local max_players
    max_players=$(sanitize_unsigned_integer "$HTY_MAX_PLAYERS" 100 HTY_MAX_PLAYERS)
    local max_view_radius
    max_view_radius=$(sanitize_unsigned_integer "$HTY_MAX_VIEW_RADIUS" 32 HTY_MAX_VIEW_RADIUS)

    local tmp_file=""
    tmp_file=$(mktemp "${config_path}.XXXXXX") || tmp_file=""
    if [[ -z $tmp_file ]]; then
        log "Unable to allocate temporary file for config render; writing directly to ${config_path}"
        tmp_file="$config_path"
    fi

    if ! CONFIG_PATH="$config_path" \
         TMP_PATH="$tmp_file" \
         SERVER_NAME="$server_name" \
         MOTD="$motd" \
         PASSWORD="$password" \
         DEFAULT_WORLD="$default_world" \
         DEFAULT_MODE="$default_mode" \
         MAX_PLAYERS="$max_players" \
         MAX_VIEW_RADIUS="$max_view_radius" \
         "$python_bin" <<'PY'
import json
import os
import sys

baseline = {
    "Version": 3,
    "ServerName": "Hytale Server",
    "MOTD": "Docker Hytale Server",
    "Password": "",
    "MaxPlayers": 100,
    "MaxViewRadius": 32,
    "LocalCompressionEnabled": False,
    "Defaults": {
        "World": "default",
        "GameMode": "Adventure",
    },
    "ConnectionTimeouts": {
        "JoinTimeouts": {},
    },
    "RateLimit": {},
    "Modules": {},
    "LogLevels": {},
    "Mods": {},
    "DisplayTmpTagsInStrings": False,
    "PlayerStorage": {
        "Type": "Hytale",
    },
}

def clone(obj):
    return json.loads(json.dumps(obj))

config_path = os.environ["CONFIG_PATH"]
tmp_path = os.environ["TMP_PATH"]

def load_config(path, fallback):
    if not os.path.exists(path):
        return clone(fallback)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        print(f"[hytale-entrypoint] Existing config at {path} is invalid; regenerating from baseline", file=sys.stderr)
        return clone(fallback)
    if not isinstance(data, dict):
        print(f"[hytale-entrypoint] Existing config at {path} is invalid; regenerating from baseline", file=sys.stderr)
        return clone(fallback)
    return data

config = load_config(config_path, baseline)

defaults = config.get("Defaults")
if not isinstance(defaults, dict):
    defaults = {}
    config["Defaults"] = defaults

config["ServerName"] = os.environ["SERVER_NAME"]
config["MOTD"] = os.environ["MOTD"]
config["Password"] = os.environ["PASSWORD"]
config["MaxPlayers"] = int(os.environ["MAX_PLAYERS"])
config["MaxViewRadius"] = int(os.environ["MAX_VIEW_RADIUS"])
defaults["World"] = os.environ["DEFAULT_WORLD"]
defaults["GameMode"] = os.environ["DEFAULT_MODE"]

with open(tmp_path, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2, ensure_ascii=False)
    handle.write("\n")
PY
    then
        [[ "$tmp_file" != "$config_path" ]] && rm -f "$tmp_file"
        die "Failed to update ${config_path} using python"
    fi

    log "Updated server config at ${config_path}"
    chmod 0644 "$tmp_file"
    if [[ "$tmp_file" != "$config_path" ]]; then
        mv -f "$tmp_file" "$config_path"
    fi

    HTY_MAX_PLAYERS=$max_players
    HTY_MAX_VIEW_RADIUS=$max_view_radius
}

maybe_update_default_world_config() {
    local seed="${HTY_DEFAULT_WORLD_SEED:-}"
    local pvp="${HTY_PVP_ENABLED:-}"
    local fall="${HTY_FALL_DAMAGE_ENABLED:-}"

    if [[ -z ${seed// } && -z ${pvp// } && -z ${fall// } ]]; then
        return
    fi

    local python_bin
    if ! python_bin=$(resolve_python_bin); then
        die "Updating world config requires python but it was not found in PATH"
    fi

    local config_path=${HTY_CONFIG_PATH:-/data/config.json}
    local world_name="${HTY_DEFAULT_WORLD_NAME:-}"
    local world_name_provided="${HTY_DEFAULT_WORLD_NAME_WAS_SET:-0}"
    local tmp_path=""
    tmp_path=$(mktemp) || tmp_path=""
    if [[ -z $tmp_path ]]; then
        die "Unable to allocate temporary file for world config rewrite"
    fi

    local python_output=""
    if ! python_output=$(
        CONFIG_PATH="$config_path" \
        WORLD_NAME="$world_name" \
        WORLD_NAME_PROVIDED="$world_name_provided" \
        WORLD_SEED="$seed" \
        WORLD_PVP="$pvp" \
        WORLD_FALL="$fall" \
        TMP_PATH="$tmp_path" \
        "$python_bin" <<'PY'
import json
import os
import sys

config_path = os.environ.get("CONFIG_PATH", "/data/config.json")
world_name_provided = os.environ.get("WORLD_NAME_PROVIDED") == "1"
requested_world = os.environ.get("WORLD_NAME", "").strip()
seed_value = os.environ.get("WORLD_SEED", "")
pvp_value = os.environ.get("WORLD_PVP", "")
fall_value = os.environ.get("WORLD_FALL", "")
tmp_path = os.environ["TMP_PATH"]

if not world_name_provided:
    requested_world = ""

seed_set = bool(seed_value.strip())
pvp_set = bool(pvp_value.strip())
fall_set = bool(fall_value.strip())

if not (seed_set or pvp_set or fall_set):
    print("no_change", end="")
    sys.exit(0)

def resolve_world_name():
    if requested_world.strip():
        return requested_world.strip()
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                defaults = data.get("Defaults")
                if isinstance(defaults, dict):
                    world = defaults.get("World")
                    if isinstance(world, str) and world.strip():
                        return world.strip()
        except Exception:
            pass
    return "default"

world_name = resolve_world_name()
world_config_path = f"/data/universe/worlds/{world_name}/config.json"
config_exists = os.path.exists(world_config_path)

baseline = {
    "Version": 4,
    "Seed": 1768323044857,
    "IsPvpEnabled": False,
    "IsFallDamageEnabled": True,
}

def parse_bool(value):
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(value)

def load_config():
    if config_exists:
        try:
            with open(world_config_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return dict(baseline)

config = load_config()
changed = False

if seed_set:
    try:
        new_seed = int(seed_value, 10)
    except Exception as exc:
        print(f"[hytale-entrypoint] Invalid HTY_DEFAULT_WORLD_SEED value: {exc}", file=sys.stderr)
        sys.exit(1)
    if (not config_exists or "Seed" not in config) and config.get("Seed") != new_seed:
        config["Seed"] = new_seed
        changed = True

if pvp_set:
    try:
        new_pvp = parse_bool(pvp_value)
    except Exception as exc:
        print(f"[hytale-entrypoint] Invalid HTY_PVP_ENABLED value: {exc}", file=sys.stderr)
        sys.exit(1)
    if config.get("IsPvpEnabled") != new_pvp:
        config["IsPvpEnabled"] = new_pvp
        changed = True

if fall_set:
    try:
        new_fall = parse_bool(fall_value)
    except Exception as exc:
        print(f"[hytale-entrypoint] Invalid HTY_FALL_DAMAGE_ENABLED value: {exc}", file=sys.stderr)
        sys.exit(1)
    if config.get("IsFallDamageEnabled") != new_fall:
        config["IsFallDamageEnabled"] = new_fall
        changed = True

if not changed:
    print("no_change", end="")
    sys.exit(0)

os.makedirs(os.path.dirname(world_config_path), exist_ok=True)

with open(tmp_path, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2, ensure_ascii=False)
    handle.write("\n")

print(world_config_path, end="")
PY
    ); then
        rm -f "$tmp_path"
        die "Failed to update world config"
    fi

    if [[ $python_output == "no_change" ]]; then
        rm -f "$tmp_path"
        return
    fi

    chmod 0644 "$tmp_path"
    mv -f "$tmp_path" "$python_output"
    log "Updated world config at ${python_output}"
}

maybe_configure_permissions() {
    local permissions_path=/data/permissions.json
    local python_bin

    if [[ -z ${HTY_OWNER_UUID// } && -z ${HTY_OP_UUIDS// } ]]; then
        return
    fi

    if ! python_bin=$(resolve_python_bin); then
        die "Updating permissions requires python but it was not found in PATH"
    fi

    local permissions_dir
    permissions_dir=$(dirname "$permissions_path")
    mkdir -p "$permissions_dir"

    local tmp_path
    if ! tmp_path=$(mktemp "${permissions_path}.XXXXXX"); then
        die "Unable to allocate temporary file for permissions update"
    fi

    local python_output=""
    if ! python_output=$(
        PERMISSIONS_PATH="$permissions_path" \
        TMP_PATH="$tmp_path" \
        OWNER_UUID="$HTY_OWNER_UUID" \
        OP_OWNER="$HTY_OP_OWNER" \
        OP_UUIDS_RAW="$HTY_OP_UUIDS" \
        "$python_bin" <<'PY'
import json
import os
import sys
from collections import OrderedDict

TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


def parse_bool(value, name, default):
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES or normalized == "":
        return False
    print(f"[hytale-entrypoint] Ignoring invalid {name}='{value}' (expected boolean)", file=sys.stderr)
    return default


permissions_path = os.environ["PERMISSIONS_PATH"]
tmp_path = os.environ["TMP_PATH"]
owner_uuid = os.environ.get("OWNER_UUID", "").strip()
op_owner_raw = os.environ.get("OP_OWNER")
op_uuids_raw = os.environ.get("OP_UUIDS_RAW", "")

op_owner_enabled = parse_bool(op_owner_raw, "HTY_OP_OWNER", False)

uuid_candidates = []
if op_uuids_raw:
    tokens = op_uuids_raw.replace(",", " ").split()
    for token in tokens:
        token = token.strip()
        if token:
            uuid_candidates.append(token)

if op_owner_enabled and owner_uuid:
    uuid_candidates.append(owner_uuid)

unique_uuids = []
seen = set()
for token in uuid_candidates:
    if token in seen:
        continue
    seen.add(token)
    unique_uuids.append(token)

should_run = bool(unique_uuids)
if not should_run:
    print("no_change", end="")
    sys.exit(0)


def baseline_permissions():
    return OrderedDict([("users", {}), ("groups", {"Default": []})])


changed = False
if os.path.exists(permissions_path):
    try:
        with open(permissions_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        print(
            f"[hytale-entrypoint] Existing permissions at {permissions_path} is invalid; regenerating baseline",
            file=sys.stderr,
        )
        data = baseline_permissions()
        changed = True
    else:
        if not isinstance(data, dict):
            print(
                f"[hytale-entrypoint] Existing permissions at {permissions_path} is invalid; regenerating baseline",
                file=sys.stderr,
            )
            data = baseline_permissions()
            changed = True
        else:
            data = OrderedDict(data)
else:
    data = baseline_permissions()

users = data.get("users")
if not isinstance(users, dict):
    users = {}
    data["users"] = users
    changed = True

groups = data.get("groups")
if not isinstance(groups, dict):
    groups = {}
    data["groups"] = groups
    changed = True

op_permissions = groups.get("OP")
if not isinstance(op_permissions, list):
    op_permissions = []
    groups["OP"] = op_permissions
    changed = True
if "*" not in op_permissions:
    op_permissions.append("*")
    changed = True

default_permissions = groups.get("Default")
if not isinstance(default_permissions, list):
    default_permissions = []
    groups["Default"] = default_permissions
    changed = True

for uuid in unique_uuids:
    entry = users.get(uuid)
    if not isinstance(entry, dict):
        entry = {}
        users[uuid] = entry
        changed = True
    user_groups = entry.get("groups")
    if not isinstance(user_groups, list):
        user_groups = []
        entry["groups"] = user_groups
        changed = True
    if "Adventure" not in user_groups:
        user_groups.append("Adventure")
        changed = True
    if "OP" not in user_groups:
        user_groups.append("OP")
        changed = True

if not changed:
    print("no_change", end="")
    sys.exit(0)

with open(tmp_path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, ensure_ascii=False)
    handle.write("\n")

print("updated", end="")
PY
    ); then
        rm -f "$tmp_path"
        die "Failed to update permissions configuration"
    fi

    if [[ $python_output == "no_change" ]]; then
        rm -f "$tmp_path"
        return
    fi

    chmod 0644 "$tmp_path"
    mv -f "$tmp_path" "$permissions_path"
    log "Updated permissions config at ${permissions_path}"
}

ensure_downloader_binary() {
    if [[ ! -x "$HTY_DOWNLOADER_BINARY" ]]; then
        die "Downloader binary not found or not executable at $HTY_DOWNLOADER_BINARY"
    fi
}

build_downloader_args() {
    local -n _result=$1
    _result=()

    if [[ ${HTY_DOWNLOADER_SKIP_UPDATE_CHECK:-1} == 1 ]]; then
        _result+=("-skip-update-check")
    fi
    if [[ -n ${HTY_DOWNLOADER_PATCHLINE// } ]]; then
        _result+=("-patchline" "$HTY_DOWNLOADER_PATCHLINE")
    fi
    if [[ -n ${HTY_DOWNLOADER_EXTRA_ARGS// } ]]; then
        local extra_downloader_args=()
        split_words "$HTY_DOWNLOADER_EXTRA_ARGS" extra_downloader_args
        _result+=("${extra_downloader_args[@]}")
    fi
}

invoke_downloader() {
    if [[ $# -eq 0 ]]; then
        die "Downloader invocation requested without command"
    fi

    if [[ -t 1 && -t 2 ]]; then
        "$@"
        return
    fi

    log "Downloader stdout/stderr not connected to a TTY; wrapping invocation to stream progress"
    if command -v python3 >/dev/null 2>&1; then
        local status=0
        python3 - "$@" <<'PY'
import os
import pty
import sys

CR = '\r'
LF = '\n'


def master_read(fd):
    data = os.read(fd, 4096)
    if not data:
        return data
    crlf = (CR + LF).encode('utf-8')
    lf = LF.encode('utf-8')
    cr = CR.encode('utf-8')
    data = data.replace(crlf, lf)
    data = data.replace(cr, lf)
    return data


def main():
    cmd = sys.argv[1:]
    if not cmd:
        return 1
    try:
        status = pty.spawn(cmd, master_read=master_read)
    except Exception as exc:
        print(f"[hytale-entrypoint] Failed to create pseudo-terminal for downloader: {exc}", file=sys.stderr)
        return 1
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


if __name__ == "__main__":
    sys.exit(main())
PY
        status=$?
        if [[ $status -ne 0 ]]; then
            return $status
        fi
        return 0
    fi

    log "Pseudo-terminal helper unavailable (python3 not found); invoking downloader directly"
    "$@"
}

download_server_artifacts() {
    ensure_downloader_binary

    local downloader_home=${HTY_DOWNLOADER_HOME:-/opt/hytale/cache/downloader}
    local download_tmp=${HTY_DOWNLOAD_TMP:-"$downloader_home/hytale-package.zip"}
    local download_dir
    download_dir=$(dirname "$download_tmp")

    mkdir -p "$downloader_home" "$download_dir" /opt/hytale/bin /opt/hytale/assets

    log "Invoking downloader to fetch latest server package"
    log "  Downloader binary: $HTY_DOWNLOADER_BINARY"
    log "  Download target:   $download_tmp"

    local downloader_args=()
    build_downloader_args downloader_args

    export HOME="$downloader_home"
    if ! invoke_downloader "$HTY_DOWNLOADER_BINARY" "${downloader_args[@]}" -download-path "$download_tmp"; then
        die "Downloader failed to retrieve server package"
    fi

    if [[ ! -f "$download_tmp" ]]; then
        die "Downloader completed but expected archive $download_tmp was not produced"
    fi

    log "Extracting server artifacts from downloaded package"

    local extract_dir=${HTY_DOWNLOAD_EXTRACT:-"$downloader_home/extracted"}
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"

    unzip -q "$download_tmp" -d "$extract_dir"

    local jar_path
    jar_path=$(find "$extract_dir" -maxdepth 4 -type f -name HytaleServer.jar -print -quit) || true
    [[ -n $jar_path ]] || die "Unable to locate HytaleServer.jar inside downloaded package"
    install -m 644 "$jar_path" "$HTY_JAR"

    local assets_path
    assets_path=$(find "$extract_dir" -maxdepth 4 -type f -name Assets.zip -print -quit) || true
    [[ -n $assets_path ]] || die "Unable to locate Assets.zip inside downloaded package"
    install -m 644 "$assets_path" "$HTY_ASSETS"

    local aot_path
    aot_path=$(find "$extract_dir" -maxdepth 4 -type f -name HytaleServer.aot -print -quit) || true
    if [[ -n $aot_path ]]; then
        install -m 644 "$aot_path" "$HTY_AOT_CACHE"
        log "Extracted optional AOT cache (HytaleServer.aot)"
    fi

    if [[ ${HTY_KEEP_DOWNLOAD_ARCHIVE:-0} != 1 ]]; then
        rm -f "$download_tmp"
    fi
    if [[ ${HTY_KEEP_DOWNLOAD_EXTRACT:-0} != 1 ]]; then
        rm -rf "$extract_dir"
    fi

    HTY_FORCE_DOWNLOAD=0
}

get_downloader_version() {
    ensure_downloader_binary

    local downloader_args=()
    build_downloader_args downloader_args

    local downloader_home=${HTY_DOWNLOADER_HOME:-/opt/hytale/cache/downloader}
    mkdir -p "$downloader_home"

    local previous_home=""
    local previous_home_set=0
    if [[ -n ${HOME+x} ]]; then
        previous_home=$HOME
        previous_home_set=1
    fi
    export HOME="$downloader_home"

    local output=""
    if ! output=$("$HTY_DOWNLOADER_BINARY" "${downloader_args[@]}" --print-version 2>&1); then
        if [[ $previous_home_set -eq 1 ]]; then
            export HOME="$previous_home"
        else
            unset HOME
        fi
        log "Auto-update: downloader version check failed"
        local line=""
        while IFS= read -r line; do
            [[ -n ${line// } ]] || continue
            log "  downloader: $line"
        done <<<"$output"
        return 1
    fi

    output=${output//$'\r'/}
    local version_line=""
    while IFS= read -r version_line; do
        [[ -n ${version_line// } ]] || continue
        break
    done <<<"$output"

    if [[ $previous_home_set -eq 1 ]]; then
        export HOME="$previous_home"
    else
        unset HOME
    fi

    if [[ -n $version_line ]]; then
        printf '%s' "$version_line"
        return 0
    fi

    log "Auto-update: downloader version output was empty"
    return 1
}

get_current_server_version() {
    if [[ ! -f "$HTY_JAR" ]]; then
        return 1
    fi

    local output=""
    if ! output=$(java -jar "$HTY_JAR" --version 2>&1); then
        log "Auto-update: failed to query current server version"
        return 1
    fi

    output=${output//$'\r'/}
    local first_line=""
    if ! IFS= read -r first_line <<<"$output"; then
        log "Auto-update: server version output was empty"
        return 1
    fi

    if [[ $first_line =~ ([0-9]{4}\.[0-9]{2}\.[0-9]{2}-[0-9a-fA-F]+) ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
        return 0
    fi

    log "Auto-update: could not parse server version from output: $first_line"
    return 1
}

maintain_downloader_session() {
    local version=""
    if version=$(get_downloader_version); then
        printf '%s' "$version"
        return 0
    fi
    return 1
}

perform_auto_update_if_needed() {
    local latest_version=""
    if ! latest_version=$(maintain_downloader_session); then
        return
    fi

    local current_version=""
    if [[ -f "$HTY_JAR" ]]; then
        if ! current_version=$(get_current_server_version); then
            current_version=""
        fi
    fi

    if [[ ${HTY_FORCE_DOWNLOAD:-0} == 1 ]]; then
        log "Force download requested (HTY_FORCE_DOWNLOAD=1); refreshing server artifacts (latest ${latest_version})"
        download_server_artifacts
        return
    fi

    if [[ ${HTY_AUTO_UPDATE:-1} == 0 ]]; then
        if [[ -n $current_version ]]; then
            log "Auto-update disabled (HTY_AUTO_UPDATE=0); current version ${current_version}, latest ${latest_version}"
        else
            log "Auto-update disabled (HTY_AUTO_UPDATE=0); latest available version ${latest_version}"
        fi
        return
    fi

    if [[ -z $current_version ]]; then
        log "Auto-update: unable to determine current server version; refreshing artifacts via downloader"
        download_server_artifacts
        return
    fi

    if [[ "$current_version" == "$latest_version" ]]; then
        log "Auto-update: server already at latest version (${current_version})"
        return
    fi

    log "Auto-update: updating server from ${current_version} to ${latest_version}"
    download_server_artifacts
}

bootstrap_server_artifacts() {
    local need_download=0

    [[ -f "$HTY_JAR" ]] || need_download=1
    [[ -f "$HTY_ASSETS" ]] || need_download=1

    if [[ ${HTY_FORCE_DOWNLOAD:-0} == 1 ]]; then
        if [[ $need_download -eq 0 ]]; then
            log "Force download requested; refreshing server artifacts"
        fi
        need_download=1
    fi

    if [[ $need_download -eq 0 ]]; then
        return
    fi

    if [[ ${HTY_AUTO_DOWNLOAD:-1} == 0 ]]; then
        log "Auto-download disabled; expecting pre-populated server artifacts."
        die "Provide HytaleServer.jar at ${HTY_JAR} and Assets.zip at ${HTY_ASSETS}"
    fi

    log "Server artifacts missing; invoking downloader to fetch latest package"
    download_server_artifacts
}

prepare_runtime() {
    mkdir -p \
        "$(dirname "$HTY_JAR")" \
        "$(dirname "$HTY_ASSETS")" \
        "$(dirname "$HTY_AOT_CACHE")" \
        /opt/hytale/universe \
        /opt/hytale/mods \
        /opt/hytale/logs \
        /opt/hytale/cache
}

maybe_sync_curseforge_mods() {
    local helper=${CF_MODS_HELPER:-/usr/local/bin/curseforge-mods}
    local disable=${CF_MODS_DISABLE_UPDATES:-0}
    disable=${disable,,}

    if [[ -z ${CF_MODS// } ]]; then
        return
    fi

    if [[ $disable == 1 || $disable == true || $disable == yes || $disable == on ]]; then
        log "Skipping CurseForge mod synchronization (CF_MODS_DISABLE_UPDATES=${CF_MODS_DISABLE_UPDATES})"
        return
    fi

    if [[ ! -x "$helper" ]]; then
        log "CurseForge helper not executable at ${helper}; skipping mod synchronization"
        return
    fi

    log "Invoking CurseForge helper to synchronize mods"
    if ! "$helper"; then
        die "CurseForge mod synchronization failed"
    fi
}

normalize_auth_env() {
    if [[ -z ${HTY_OWNER_UUID:-} && -n ${OWNER_UUID:-} ]]; then
        HTY_OWNER_UUID=$OWNER_UUID
    fi
    if [[ -z ${OWNER_UUID:-} && -n ${HTY_OWNER_UUID:-} ]]; then
        OWNER_UUID=$HTY_OWNER_UUID
    fi
    if [[ -z ${HTY_AUTH_OWNER_UUID:-} && -n ${HTY_OWNER_UUID:-} ]]; then
        HTY_AUTH_OWNER_UUID=$HTY_OWNER_UUID
    fi
    if [[ -z ${HTY_AUTH_OWNER_UUID:-} && -n ${OWNER_UUID:-} ]]; then
        HTY_AUTH_OWNER_UUID=$OWNER_UUID
    fi
    if [[ -z ${HTY_AUTH_PROFILE:-} && -n ${PROFILE_USERNAME:-} ]]; then
        HTY_AUTH_PROFILE=$PROFILE_USERNAME
    fi
    if [[ -z ${PROFILE_USERNAME:-} && -n ${HTY_AUTH_PROFILE:-} ]]; then
        PROFILE_USERNAME=$HTY_AUTH_PROFILE
    fi
}

maybe_run_oauth_helper() {
    local helper=${HTY_AUTH_HELPER:-/usr/local/bin/hytale-oauth}
    if [[ -n ${AUTH_HELPER:-} ]]; then
        helper=$AUTH_HELPER
    fi
    local store=${HTY_AUTH_STORE:-/data/.auth.json}
    if [[ -n ${AUTH_FILE:-} ]]; then
        store=$AUTH_FILE
    fi

    AUTH_HELPER_PATH=$helper
    AUTH_STORE_PATH=$store

    if [[ ${HTY_SKIP_AUTH:-0} -eq 1 ]]; then
        log "Skipping OAuth helper per configuration"
        return 0
    fi

    if [[ -n ${HTY_IDENTITY_TOKEN:-} && -n ${HTY_SESSION_TOKEN:-} ]]; then
        return 0
    fi

    if [[ ! -x "$helper" ]]; then
        log "OAuth helper not found or not executable at ${helper}; skipping automatic server authentication"
        return 0
    fi

    local args=(--auth-file "$store" --output env)
    if [[ -n ${HTY_AUTH_OWNER_UUID:-} ]]; then
        args+=(--owner-uuid "$HTY_AUTH_OWNER_UUID")
    fi
    if [[ -n ${HTY_AUTH_PROFILE:-} ]]; then
        args+=(--profile-username "$HTY_AUTH_PROFILE")
    fi
    if [[ ${HTY_AUTH_QUIET:-0} -eq 1 ]]; then
        args+=(--quiet)
    fi

    log "Invoking OAuth helper to acquire identity/session tokens"
    local response
    if ! response=$("$helper" "${args[@]}"); then
        die "OAuth helper failed to obtain tokens"
    fi

    eval "$response"

    normalize_auth_env

    if [[ -z ${HTY_IDENTITY_TOKEN:-} || -z ${HTY_SESSION_TOKEN:-} ]]; then
        die "OAuth helper returned without identity/session tokens"
    fi

    if [[ -z ${HTY_OWNER_UUID:-} && -n ${HTY_AUTH_OWNER_UUID:-} ]]; then
        HTY_OWNER_UUID=$HTY_AUTH_OWNER_UUID
    fi
}

start_refresh_maintenance() {
    if [[ ${HTY_SKIP_AUTH:-0} -eq 1 ]]; then
        log "OAuth refresh maintenance disabled because HTY_SKIP_AUTH=1"
        return
    fi

    local helper=${AUTH_HELPER_PATH:-${HTY_AUTH_HELPER:-}}
    local store=${AUTH_STORE_PATH:-${HTY_AUTH_STORE:-}}
    local interval_seconds=""

    if [[ -z ${helper:-} || ! -x "$helper" ]]; then
        log "OAuth refresh maintenance disabled: helper not executable (${helper:-unset})"
        return
    fi
    if [[ -z ${store:-} ]]; then
        log "OAuth refresh maintenance disabled: auth store path not configured"
        return
    fi

    if [[ -n ${HTY_AUTH_REFRESH_INTERVAL_SECONDS:-} ]]; then
        if [[ ${HTY_AUTH_REFRESH_INTERVAL_SECONDS} =~ ^[0-9]+$ ]]; then
            interval_seconds=${HTY_AUTH_REFRESH_INTERVAL_SECONDS}
        else
            log "Ignoring invalid HTY_AUTH_REFRESH_INTERVAL_SECONDS='${HTY_AUTH_REFRESH_INTERVAL_SECONDS}'"
        fi
    fi
    if [[ -z ${interval_seconds:-} && -n ${HTY_AUTH_REFRESH_INTERVAL_DAYS:-} ]]; then
        if [[ ${HTY_AUTH_REFRESH_INTERVAL_DAYS} =~ ^[0-9]+$ ]]; then
            interval_seconds=$(( HTY_AUTH_REFRESH_INTERVAL_DAYS * 86400 ))
        else
            log "Ignoring invalid HTY_AUTH_REFRESH_INTERVAL_DAYS='${HTY_AUTH_REFRESH_INTERVAL_DAYS}'"
        fi
    fi

    if [[ -z ${interval_seconds:-} ]]; then
        log "OAuth refresh maintenance disabled: no valid interval configured"
        return
    fi
    if (( interval_seconds <= 0 )); then
        log "OAuth refresh maintenance disabled: interval ${interval_seconds}s is not positive"
        return
    fi

    log "Starting OAuth refresh maintenance loop (interval ${interval_seconds}s)"
    (
        set +e
        while true; do
            if ! kill -0 "$PPID" >/dev/null 2>&1; then
                log "OAuth refresh maintenance: parent process exited; stopping loop"
                exit 0
            fi
            if [[ ! -x "$helper" ]]; then
                log "OAuth refresh maintenance: helper not executable at ${helper}; retrying after interval"
                sleep "${interval_seconds}" || sleep 60
                continue
            fi
            if [[ ! -f "$store" ]]; then
                log "OAuth refresh maintenance: auth store ${store} not found; waiting for next interval"
                sleep "${interval_seconds}" || sleep 60
                continue
            fi
            local args=(--auth-file "$store" --output env --force-refresh --quiet)
            if [[ -n ${HTY_AUTH_OWNER_UUID:-} ]]; then
                args+=(--owner-uuid "$HTY_AUTH_OWNER_UUID")
            fi
            if [[ -n ${HTY_AUTH_PROFILE:-} ]]; then
                args+=(--profile-username "$HTY_AUTH_PROFILE")
            fi
            local helper_output=""
            local helper_status=0
            local tmp_err=""
            tmp_err=$(mktemp) || tmp_err=""
            if [[ -z $tmp_err ]]; then
                log "OAuth refresh maintenance: unable to allocate temp file for helper stderr; skipping iteration"
                sleep "${interval_seconds}" || sleep 60
                continue
            fi
            if FORCE_REFRESH=1 TOKEN_BUFFER=0 "$helper" "${args[@]}" > /dev/null 2> "$tmp_err"; then
                log "OAuth refresh maintenance: helper invocation succeeded"
            else
                helper_status=$?
                helper_output=$(<"$tmp_err")
                log "OAuth refresh maintenance: helper invocation failed (exit ${helper_status})"
                if [[ -n ${helper_output} ]]; then
                    while IFS= read -r helper_line; do
                        log "  helper: ${helper_line}"
                    done <<<"$helper_output"
                fi
            fi
            rm -f "$tmp_err"
            maintain_downloader_session >/dev/null 2>&1 || true
            sleep "${interval_seconds}" || sleep 60
        done
    ) &
    AUTH_REFRESH_MAINTENANCE_PID=$!
    export AUTH_REFRESH_MAINTENANCE_PID
}

build_command() {
    local -n _cmd_ref=$1
    local java_opts_array=()
    split_words "$JAVA_OPTS" java_opts_array

    local extra_args_array=()
    split_words "$HTY_EXTRA_ARGS" extra_args_array

    local server_args=()
    if [[ $# -gt 1 ]]; then
        local -a raw_server_args=("${@:2}")
        if [[ ${raw_server_args[0]:-} == -- ]]; then
            raw_server_args=("${raw_server_args[@]:1}")
        fi
        if [[ ${#raw_server_args[@]} -gt 0 ]]; then
            server_args=("${raw_server_args[@]}")
        fi
    fi

    log "Launching HytaleServer.jar"
    log "  HTY_JAR=${HTY_JAR}"
    log "  HTY_ASSETS=${HTY_ASSETS}"
    log "  HTY_BIND=${HTY_BIND}"
    log "  HTY_AUTH_MODE=${HTY_AUTH_MODE}"
    if [[ ${#java_opts_array[@]} -gt 0 ]]; then
        log "  JAVA_OPTS: ${java_opts_array[*]}"
    fi
    if [[ ${#extra_args_array[@]} -gt 0 ]]; then
        log "  Extra args: ${extra_args_array[*]}"
    fi
    if [[ -n ${HTY_IDENTITY_TOKEN// } ]]; then
        log "  Identity token provided"
    fi
    if [[ -n ${HTY_SESSION_TOKEN// } ]]; then
        log "  Session token provided"
    fi
    if [[ -n ${HTY_OWNER_UUID// } ]]; then
        log "  Owner UUID=${HTY_OWNER_UUID}"
    fi
    if [[ ${#server_args[@]} -gt 0 ]]; then
        log "  CLI args: ${server_args[*]}"
    fi

    _cmd_ref=(java)
    if [[ ${#java_opts_array[@]} -gt 0 ]]; then
        _cmd_ref+=("${java_opts_array[@]}")
    fi
    _cmd_ref+=(
        -jar "$HTY_JAR"
        --assets "$HTY_ASSETS"
        --bind "$HTY_BIND"
        --auth-mode "$HTY_AUTH_MODE"
    )
    local allow_op_normalized="${HTY_OP_SELF,,}"
    if [[ $allow_op_normalized == 1 || $allow_op_normalized == true || $allow_op_normalized == yes || $allow_op_normalized == on ]]; then
        _cmd_ref+=(--allow-op)
    fi
    local accept_plugins_normalized="${HTY_ACCEPT_EARLY_PLUGINS,,}"
    if [[ $accept_plugins_normalized == 1 || $accept_plugins_normalized == true || $accept_plugins_normalized == yes || $accept_plugins_normalized == on ]]; then
        _cmd_ref+=(--accept-early-plugins)
    fi
    if [[ -n ${HTY_IDENTITY_TOKEN// } ]]; then
        _cmd_ref+=(--identity-token "$HTY_IDENTITY_TOKEN")
    fi
    if [[ -n ${HTY_SESSION_TOKEN// } ]]; then
        _cmd_ref+=(--session-token "$HTY_SESSION_TOKEN")
    fi
    if [[ -n ${HTY_OWNER_UUID// } ]]; then
        _cmd_ref+=(--owner-uuid "$HTY_OWNER_UUID")
    fi
    if [[ ${#extra_args_array[@]} -gt 0 ]]; then
        _cmd_ref+=("${extra_args_array[@]}")
    fi
    if [[ ${#server_args[@]} -gt 0 ]]; then
        _cmd_ref+=("${server_args[@]}")
    fi
}

main() {
    run_user_command_if_requested "$@"

    : "${HTY_BIND:=0.0.0.0:5520}"
    : "${HTY_AUTH_MODE:=authenticated}"
    : "${HTY_ASSETS:=/opt/hytale/assets/Assets.zip}"
    : "${HTY_JAR:=/opt/hytale/server/HytaleServer.jar}"
    : "${HTY_AOT_CACHE:=/opt/hytale/server/HytaleServer.aot}"
    : "${HTY_IDENTITY_TOKEN:=}"
    : "${HTY_SESSION_TOKEN:=}"
    : "${HTY_OWNER_UUID:=}"
    : "${HTY_EXTRA_ARGS:=}"
    : "${JAVA_OPTS:=}"
    : "${HTY_DOWNLOADER_BINARY:=/bin/hytale-downloader}"
    : "${HTY_DOWNLOADER_HOME:=/opt/hytale/cache/downloader}"
    : "${HTY_DOWNLOADER_PATCHLINE:=}"
    : "${HTY_DOWNLOADER_EXTRA_ARGS:=}"
    : "${HTY_DOWNLOADER_SKIP_UPDATE_CHECK:=1}"
    : "${HTY_AUTO_DOWNLOAD:=1}"
    : "${HTY_FORCE_DOWNLOAD:=0}"
    : "${TZ:=UTC}"
    : "${HTY_AUTO_UPDATE:=${HTY_AUTO_DOWNLOAD:-1}}"
    : "${HTY_DOWNLOAD_TMP:=${HTY_DOWNLOADER_HOME%/}/hytale-package.zip}"
    : "${HTY_DOWNLOAD_EXTRACT:=${HTY_DOWNLOADER_HOME%/}/extracted}"
    : "${HTY_KEEP_DOWNLOAD_ARCHIVE:=0}"
    : "${HTY_KEEP_DOWNLOAD_EXTRACT:=0}"
    : "${HTY_AUTH_HELPER:=/usr/local/bin/hytale-oauth}"
    : "${HTY_AUTH_STORE:=/data/.auth.json}"
    : "${HTY_AUTH_OWNER_UUID:=}"
    : "${HTY_AUTH_PROFILE:=}"
    : "${HTY_AUTH_REFRESH_INTERVAL_SECONDS:=}"
    : "${HTY_AUTH_QUIET:=0}"
    : "${HTY_SKIP_AUTH:=0}"
    : "${HTY_SERVER_NAME:=Hytale Server}"
    : "${HTY_SERVER_MOTD:=Docker Hytale Server}"
    : "${HTY_SERVER_PASSWORD:=}"
    : "${HTY_DEFAULT_GAME_MODE:=Adventure}"
    local hty_default_world_name_was_set=0
    if [[ -n ${HTY_DEFAULT_WORLD_NAME+x} && -n ${HTY_DEFAULT_WORLD_NAME// } ]]; then
        hty_default_world_name_was_set=1
    fi
    HTY_DEFAULT_WORLD_NAME_WAS_SET=$hty_default_world_name_was_set
    : "${HTY_DEFAULT_WORLD_NAME:=default}"
    : "${HTY_MAX_PLAYERS:=100}"
    : "${HTY_MAX_VIEW_RADIUS:=32}"
    : "${HTY_CONFIG_PATH:=/data/config.json}"

    : "${HTY_OP_OWNER:=0}"
    : "${HTY_OP_UUIDS:=}"
    : "${HTY_OP_SELF:=0}"
    : "${HTY_ACCEPT_EARLY_PLUGINS:=0}"

    if [[ -n ${HTY_RCON_ENABLED+x} && -z ${RCON_ENABLED+x} ]]; then
        RCON_ENABLED=$HTY_RCON_ENABLED
    fi
    if [[ -n ${HTY_RCON_BIND+x} && -z ${RCON_BIND+x} ]]; then
        RCON_BIND=$HTY_RCON_BIND
    fi
    if [[ -n ${HTY_RCON_PASSWORD+x} && -z ${RCON_PASSWORD+x} ]]; then
        RCON_PASSWORD=$HTY_RCON_PASSWORD
    fi
    if [[ -n ${HTY_RCON_RESPONSE_TIMEOUT_MS+x} && -z ${RCON_RESPONSE_TIMEOUT_MS+x} ]]; then
        RCON_RESPONSE_TIMEOUT_MS=$HTY_RCON_RESPONSE_TIMEOUT_MS
    fi
    if [[ -n ${HTY_RCON_LOG_COMMANDS+x} && -z ${RCON_LOG_COMMANDS+x} ]]; then
        RCON_LOG_COMMANDS=$HTY_RCON_LOG_COMMANDS
    fi
    if [[ -n ${HTY_RCON_BINARY+x} && -z ${RCON_BINARY+x} ]]; then
        RCON_BINARY=$HTY_RCON_BINARY
    fi
    if [[ -n ${HTY_RCON_CHILD_COMMAND+x} && -z ${RCON_CHILD_COMMAND+x} ]]; then
        RCON_CHILD_COMMAND=$HTY_RCON_CHILD_COMMAND
    fi
    if [[ -n ${HTY_RCON_CHILD_DIR+x} && -z ${RCON_CHILD_DIR+x} ]]; then
        RCON_CHILD_DIR=$HTY_RCON_CHILD_DIR
    fi
    if [[ -n ${HTY_RCON_CHILD_ARG+x} && -z ${RCON_CHILD_ARG+x} ]]; then
        RCON_CHILD_ARG=$HTY_RCON_CHILD_ARG
    fi
    if [[ -n ${HTY_RCON_RESPAWN+x} && -z ${RCON_RESPAWN+x} ]]; then
        RCON_RESPAWN=$HTY_RCON_RESPAWN
    fi
    if [[ -n ${HTY_RCON_RESPAWN_BACKOFF_MS+x} && -z ${RCON_RESPAWN_BACKOFF_MS+x} ]]; then
        RCON_RESPAWN_BACKOFF_MS=$HTY_RCON_RESPAWN_BACKOFF_MS
    fi
    if [[ -n ${HTY_RCON_HOST+x} && -z ${RCON_HOST+x} ]]; then
        RCON_HOST=$HTY_RCON_HOST
    fi
    if [[ -n ${HTY_RCON_PORT+x} && -z ${RCON_PORT+x} ]]; then
        RCON_PORT=$HTY_RCON_PORT
    fi

    : "${RCON_ENABLED:=1}"
    : "${RCON_BIND:=0.0.0.0:25900}"
    : "${RCON_PASSWORD:=hytale}"
    : "${RCON_RESPONSE_TIMEOUT_MS:=2000}"
    : "${RCON_LOG_COMMANDS:=0}"
    : "${RCON_BINARY:=/usr/local/bin/rcon-cli}"
    : "${RCON_CHILD_COMMAND:=}"
    : "${RCON_CHILD_DIR:=/data}"
    : "${RCON_CHILD_ARG:=}"
    : "${RCON_RESPAWN:=0}"
    : "${RCON_RESPAWN_BACKOFF_MS:=5000}"
    : "${RCON_HOST:=127.0.0.1}"
    : "${RCON_PORT:=25900}"
    : "${CF_MODS_HELPER:=/usr/local/bin/curseforge-mods}"
    : "${CF_MODS_DISABLE_UPDATES:=0}"
    OWNER_UUID=${OWNER_UUID:-}
    PROFILE_USERNAME=${PROFILE_USERNAME:-}

    if [[ -n ${AUTH_HELPER:-} ]]; then
        HTY_AUTH_HELPER=$AUTH_HELPER
    fi
    if [[ -n ${AUTH_SCRIPT:-} ]]; then
        HTY_AUTH_HELPER=$AUTH_SCRIPT
    fi
    if [[ -n ${AUTH_FILE:-} ]]; then
        HTY_AUTH_STORE=$AUTH_FILE
    fi
    if [[ -n ${AUTH_OWNER_UUID:-} ]]; then
        HTY_AUTH_OWNER_UUID=$AUTH_OWNER_UUID
    fi
    if [[ -n ${AUTH_OWNER:-} ]]; then
        HTY_AUTH_OWNER_UUID=$AUTH_OWNER
    fi
    if [[ -n ${AUTH_PROFILE:-} ]]; then
        HTY_AUTH_PROFILE=$AUTH_PROFILE
    fi
    if [[ -n ${AUTH_PROFILE_USERNAME:-} ]]; then
        HTY_AUTH_PROFILE=$AUTH_PROFILE_USERNAME
    fi
    if [[ -n ${SKIP_AUTH:-} ]]; then
        HTY_SKIP_AUTH=$SKIP_AUTH
    fi
    if [[ -n ${SKIP_AUTH_BOOTSTRAP:-} ]]; then
        HTY_SKIP_AUTH=$SKIP_AUTH_BOOTSTRAP
    fi
    if [[ -n ${AUTH_SKIP:-} ]]; then
        HTY_SKIP_AUTH=$AUTH_SKIP
    fi
    if [[ -n ${AUTH_SKIP_BOOTSTRAP:-} ]]; then
        HTY_SKIP_AUTH=$AUTH_SKIP_BOOTSTRAP
    fi
    if [[ -n ${HTY_AUTH_SKIP:-} ]]; then
        HTY_SKIP_AUTH=$HTY_AUTH_SKIP
    fi
    if [[ -n ${HTY_SKIP_AUTH_BOOTSTRAP:-} ]]; then
        HTY_SKIP_AUTH=$HTY_SKIP_AUTH_BOOTSTRAP
    fi
    if [[ -z ${HTY_IDENTITY_TOKEN:-} && -n ${AUTH_IDENTITY_TOKEN:-} ]]; then
        HTY_IDENTITY_TOKEN=$AUTH_IDENTITY_TOKEN
    fi
    if [[ -z ${HTY_IDENTITY_TOKEN:-} && -n ${IDENTITY_TOKEN:-} ]]; then
        HTY_IDENTITY_TOKEN=$IDENTITY_TOKEN
    fi
    if [[ -z ${HTY_SESSION_TOKEN:-} && -n ${AUTH_SESSION_TOKEN:-} ]]; then
        HTY_SESSION_TOKEN=$AUTH_SESSION_TOKEN
    fi
    if [[ -z ${HTY_SESSION_TOKEN:-} && -n ${SESSION_TOKEN:-} ]]; then
        HTY_SESSION_TOKEN=$SESSION_TOKEN
    fi

    normalize_auth_env
    maybe_run_oauth_helper
    normalize_auth_env
    start_refresh_maintenance

    if [[ -z ${HTY_IDENTITY_TOKEN:-} || -z ${HTY_SESSION_TOKEN:-} ]]; then
        auth_mode_upper=$(printf '%s' "$HTY_AUTH_MODE" | tr '[:lower:]' '[:upper:]')
        if [[ $auth_mode_upper != OFFLINE ]]; then
            log "Warning: identity/session tokens unavailable; server may require manual authentication."
        fi
    fi

    prepare_runtime
    bootstrap_server_artifacts
    perform_auto_update_if_needed
    maybe_sync_curseforge_mods
    render_server_config
    maybe_update_default_world_config
    maybe_configure_permissions

    [[ -f "$HTY_JAR" ]] || die "HytaleServer.jar not available at $HTY_JAR after bootstrap"
    [[ -f "$HTY_ASSETS" ]] || die "Assets.zip not available at $HTY_ASSETS after bootstrap"

    if [[ -f "$HTY_AOT_CACHE" ]]; then
        JAVA_OPTS="${JAVA_OPTS} -XX:AOTCache=${HTY_AOT_CACHE}"
    elif [[ ${HTY_SKIP_AOT_LOG:-0} != 1 ]]; then
        log "AOT cache not found at ${HTY_AOT_CACHE}; proceeding without it."
    fi

    export TZ HTY_IDENTITY_TOKEN HTY_SESSION_TOKEN HTY_OWNER_UUID

    local cmd=()
    build_command cmd "$@"

    local rcon_enable_normalized="${RCON_ENABLED,,}"
    if [[ $rcon_enable_normalized == 1 || $rcon_enable_normalized == true || $rcon_enable_normalized == yes || $rcon_enable_normalized == on ]]; then
        local child_command="${RCON_CHILD_COMMAND:-${cmd[0]}}"
        if [[ -z ${child_command:-} ]]; then
            die "Unable to determine server launch command for RCON proxy"
        fi

        local rcon_args=(
            server
            --bind "$RCON_BIND"
            --password "$RCON_PASSWORD"
            --response-timeout-ms "$RCON_RESPONSE_TIMEOUT_MS"
            --child-command "$child_command"
            --child-dir "$RCON_CHILD_DIR"
        )
        local rcon_log_commands_normalized="${RCON_LOG_COMMANDS,,}"
        if [[ $rcon_log_commands_normalized == 1 || $rcon_log_commands_normalized == true || $rcon_log_commands_normalized == yes || $rcon_log_commands_normalized == on ]]; then
            rcon_args+=(--log-commands)
        fi
        if [[ -n ${RCON_CHILD_ARG:-} ]]; then
            rcon_args+=(--child-arg "$RCON_CHILD_ARG")
        fi
        for arg in "${cmd[@]:1}"; do
            rcon_args+=(--child-arg "$arg")
        done

        exec "$RCON_BINARY" "${rcon_args[@]}"
    fi

    exec "${cmd[@]}"
}

main "$@"
