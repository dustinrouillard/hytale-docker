# Hytale Docker Container

### First-Run Authentication

When you first run this docker container it will ask you to go through the device authentication process twice, the first time is for authenticating the game server, and the second one is for authenticating the Hytale Downloader CLI to download the assets and server jar file.

According to token lifecycles in the [following article](https://support.hytale.com/hc/en-us/articles/45328341414043-Server-Provider-Authentication-Guide#token-lifecycle), you should only have to do this again if your server is not started for more than 30 days as the refresh token lasts 30 days and is used to renew authentication to create a new game server session before starting.

### Key Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `TZ` | `UTC` | Timezone applied to the container (propagates to JVM and log timestamps). |
| `HTY_BIND` | `0.0.0.0:5520` | UDP bind address and port. |
| `HTY_AUTH_MODE` | `authenticated` | `authenticated` (default) or `offline`. |
| `HTY_IDENTITY_TOKEN` | _(empty)_ | Injects `--identity-token` when set. |
| `HTY_SESSION_TOKEN` | _(empty)_ | Injects `--session-token` when set. |
| `HTY_OWNER_UUID` | _(empty)_ | Injects `--owner-uuid` when set. |
| `HTY_AUTO_DOWNLOAD` | `1` | Toggle automatic artifact download (`0` disables). |
| `HTY_DOWNLOADER_PATCHLINE` | _(empty)_ | Override patchline (e.g., `pre-release`). |
| `HTY_DOWNLOADER_SKIP_UPDATE_CHECK` | `1` | Disable downloader self-update checks (set to `0` to enable). |
| `HTY_AUTH_OWNER_UUID` | _(empty)_ | Preferred owner UUID for session generation (falls back to the first profile). |
| `HTY_AUTH_PROFILE` | _(empty)_ | Preferred profile username; used when `HTY_AUTH_OWNER_UUID` is unspecified. |
| `HTY_AUTH_REFRESH_INTERVAL_DAYS` | `7` | Number of days between background OAuth refresh attempts (ignored when seconds value is provided). |
| `HTY_AUTH_REFRESH_INTERVAL_SECONDS` | _(empty)_ | Overrides the refresh interval in seconds; set to `0` or leave unset to disable the background refresher. |
| `HTY_SKIP_AUTH` | `0` | Set to `1` to bypass automatic OAuth bootstrap (expects tokens via env or file, and a pre-existing server jar with assets zip). |
| `CF_MODS` | _(empty)_ | Comma/space separated list of CurseForge slugs (optionally `slug:fileId`) to sync into `/data/mods`. |
| `CF_API_KEY` | _(empty)_ | CurseForge API key used for authenticated API and download requests. |
| `CF_MODS_DISABLE_UPDATES` | `0` | Set to `1` to skip CurseForge synchronization during startup. |

If `HTY_IDENTITY_TOKEN` / `HTY_SESSION_TOKEN` are not supplied, the entrypoint invokes `/usr/local/bin/hytale-oauth` to complete the device authentication flow automatically. Credentials are written to `/data/.auth.json`, and helper options accept the `AUTH_*` aliases (for example `AUTH_OWNER_UUID`, `AUTH_PROFILE`, `AUTH_HELPER`). After the initial bootstrap completes, the entrypoint schedules a background refresh loop that re-invokes the helper with `--force-refresh` on a default seven-day cadence (configurable via `HTY_AUTH_REFRESH_INTERVAL_SECONDS` or `HTY_AUTH_REFRESH_INTERVAL_DAYS`). Set `HTY_AUTH_REFRESH_INTERVAL_SECONDS=0` (or leave both interval variables empty) to disable the maintenance loop entirely. Set `HTY_SKIP_AUTH=1` (or `SKIP_AUTH=1`) to disable this bootstrap when you plan to manage tokens yourself.

### CurseForge Mod Downloads

Set `CF_API_KEY` to your CurseForge API key and populate `CF_MODS` with the mods you want (for example `adminui`, or `adminui:7447718` to pin a specific file). Use `CF_MODS_DISABLE_UPDATES=1` when you need to skip synchronization for whatever reason.

### Example: Use device OAuth for server assets, and server session creation
*The recommended way over supplying manual tokens*

```sh
docker run -d \
  --name hytale \
  -p 5520:5520/udp \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/main:/opt/hytale" \
  -v "/etc/machine-id:/etc/machine-id:ro" \
  ghcr.io/dustinrouillard/hytale-docker
```

#### Example: Running with mods auto downloaded from CurseForge

```sh
docker run -d \
  --name hytale \
  -p 5520:5520/udp \
  -e CF_API_KEY="YOUR_CF_API_KEY" \
  -e CF_MODS="adminui,spark" \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/main:/opt/hytale" \
  -v "/etc/machine-id:/etc/machine-id:ro" \
  ghcr.io/dustinrouillard/hytale-docker
```

### Example: Supplying Session Tokens manually
*You should just use the above option if you want to make it easy, since it handles all the oauth logic for you*

```sh
docker run -d \
  --name hytale \
  -p 5520:5520/udp \
  -e HTY_IDENTITY_TOKEN="IDENTITY_TOKEN" \
  -e HTY_SESSION_TOKEN="SESSION_TOKEN" \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/main:/opt/hytale" \
  -v "/etc/machine-id:/etc/machine-id:ro" \
  ghcr.io/dustinrouillard/hytale-docker
```

### Volumes to Persist

| Host Path (example) | Container Path | Contents |
| --- | --- | --- |
| `./main` | `/opt/hytale` | Server binaries, assets and download cache |
| `./data` | `/data` | World, mods, configs, and other server files |
| `/etc/machine-id` | `/etc/machine-id` | Machine ID for server identification [Optional currently] |
