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
    if ! "$HTY_DOWNLOADER_BINARY" "${downloader_args[@]}" -download-path "$download_tmp"; then
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
    exec "${cmd[@]}"
}

main "$@"
