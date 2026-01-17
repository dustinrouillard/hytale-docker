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
| `HTY_AUTH_PROFILE` | _(empty)_ | Preferred profile username, used when `HTY_AUTH_OWNER_UUID` is unspecified. |
| `HTY_AUTH_REFRESH_INTERVAL_DAYS` | `7` | Number of days between background OAuth refresh attempts (ignored when seconds value is provided). |
| `HTY_AUTH_REFRESH_INTERVAL_SECONDS` | _(empty)_ | Overrides the refresh interval in seconds, set to `0` or leave unset to disable the background refresher. |
| `HTY_SKIP_AUTH` | `0` | Set to `1` to bypass automatic OAuth bootstrap (expects tokens via env or file, and a pre-existing server jar with assets zip). |
| `HTY_SERVER_NAME` | `Hytale Server` | Sets the `ServerName` field written to the generated `config.json`. |
| `HTY_SERVER_MOTD` | `Docker Hytale Server` | Message-of-the-day stored in `config.json`. |
| `HTY_SERVER_PASSWORD` | _(empty)_ | Password players must provide when joining. |
| `HTY_DEFAULT_GAME_MODE` | `Adventure` | Sets `Defaults.GameMode` in the generated configuration. |
| `HTY_DEFAULT_WORLD_NAME` | `default` | Sets `Defaults.World` for new player spawns. |
| `HTY_DEFAULT_WORLD_SEED` | _(empty)_ | When set, writes a world config to `/data/universe/worlds/<world>/config.json` with the provided numeric seed. |
| `HTY_PVP_ENABLED` | _(empty)_ | When set, toggles `IsPvpEnabled` in the default world's config (`true`/`false`). |
| `HTY_FALL_DAMAGE_ENABLED` | _(empty)_ | When set, toggles `IsFallDamageEnabled` in the default world's config (`true`/`false`). |
| `HTY_OP_OWNER` | `0` | When set to `1`, automatically grants the owner UUID to the `OP` group inside `/data/permissions.json`. |
| `HTY_OP_UUIDS` | _(empty)_ | Comma/space separated UUIDs to grant `OP`, each user is ensured to belong to the `Adventure` and `OP` groups. |
| `HTY_OP_SELF` | `0` | When set to `1`, passes `--allow-op` to the server so players can run `/op self`. |
| `HTY_ACCEPT_EARLY_PLUGINS` | `0` | When set to `1`, passes `--accept-early-plugins`, unsupported early plugins may cause stability issues. |
| `HTY_MAX_PLAYERS` | `100` | Maximum simultaneous players permitted. |
| `HTY_MAX_VIEW_RADIUS` | `32` | Maximum chunk/view radius advertised by the server. |
| `CF_MODS` | _(empty)_ | Comma/space separated list of CurseForge slugs (optionally `slug:fileId`) to sync into `/data/mods`. |
| `CF_API_KEY` | _(empty)_ | CurseForge API key used for authenticated API and download requests. |
| `CF_MODS_DISABLE_UPDATES` | `0` | Set to `1` to skip CurseForge synchronization during startup. |
| `RCON_ENABLED` | `1` | Set to `1` to enable the RCON server. |
| `RCON_BIND` | `0.0.0.0:5520` | Address/port the RCON server will bind to. |
| `RCON_PASSWORD` | `hytale` | Shared secret required by clients. |

If `HTY_IDENTITY_TOKEN` / `HTY_SESSION_TOKEN` are not supplied, the entrypoint invokes our `hytale-oauth` utility to complete the device authentication flow automatically. Credentials are written to `/data/.auth.json`, and helper options accept the `HTY_AUTH_*` aliases (for example `HTY_AUTH_OWNER_UUID`, `HTY_AUTH_PROFILE`, `HTY_AUTH_HELPER`). After the initial bootstrap completes, the entrypoint schedules a background refresh loop that re-invokes the helper with `--force-refresh` on a default seven-day cadence (configurable via `HTY_AUTH_REFRESH_INTERVAL_SECONDS` or `HTY_AUTH_REFRESH_INTERVAL_DAYS`). Set `HTY_AUTH_REFRESH_INTERVAL_SECONDS=0` (or leave both interval variables empty) to disable the maintenance loop entirely. Set `HTY_SKIP_AUTH=1` to disable this bootstrap when you plan to manage tokens yourself.

### CurseForge Mod Downloads

Set `CF_API_KEY` to your CurseForge API key and populate `CF_MODS` with the mods you want (for example `adminui`, or `adminui:7447718` to pin a specific file). Use `CF_MODS_DISABLE_UPDATES=1` when you need to skip synchronization for whatever reason. The HyRCON mod ships preloaded in `/mods/HyRCON.jar`, so you can begin using remote console tooling immediately.

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
  -e CF_MODS="adminui,spark" \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/main:/opt/hytale" \
  -v "/etc/machine-id:/etc/machine-id:ro" \
  ghcr.io/dustinrouillard/hytale-docker
```

### Example: Supplying Session Tokens manually
*You should just use the above options if you want to make it easy, since it handles all the oauth logic for you*

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

### Example Docker Compose

```yaml
services:
  hytale:
    image: ghcr.io/dustinrouillard/hytale-docker
    restart: always
    ports:
      - 5520:5520/udp
      - 5520:5520/tcp # Optional if you want to expose the rcon port outside the container
    environment:
      CF_MODS: "adminui,spark" # Used to load mods from curseforge
      HTY_OP_OWNER: 1 # Grants the owner UUID OP status
      # RCON_PASSWORD: "secure_password"
    volumes:
      - ./data:/data
      - ./main:/opt/hytale
```

### Volumes to Persist

| Host Path (example) | Container Path | Contents |
| --- | --- | --- |
| `./main` | `/opt/hytale` | Server binaries, assets and download cache |
| `./data` | `/data` | World, mods, configs, and other server files |
| `/etc/machine-id` | `/etc/machine-id` | Machine ID for server identification [Optional currently] |

## Remote Console (RCON)

The container image also includes a TCP RCON server that wraps the Hytale server’s stdin/stdout so you can issue commands without attaching to the process. The bundled HyRCON mod powers this integration. When enabled, the RCON server listens on `0.0.0.0:5520` with the password `hytale`.

Remember to publish the TCP port when you run the container if you need remote access to the rcon server:

```sh
docker run -d \
  --name hytale \
  -p 5520:5520/udp \
  -p 5520:5520/tcp \
  -e RCON_PASSWORD="SecureRconPassword" \
  ghcr.io/dustinrouillard/hytale-docker
```

### CLI usage

The `hyrcon-client` binary is available inside the container. A compatibility symlink named `rcon-cli` is also present for existing scripts. Common examples:

- Execute a one-off command from inside the container, or outside with docker exec:

```sh
hyrcon-client client --command "/op add dstn"

docker exec hytale hyrcon-client client --command "/op add dstn"
```

- Start an interactive session from outside the container (replace the host if necessary):

```sh
hyrcon-client client --host 127.0.0.1 --port 5520 --interactive <-p password | or via RCON_PASSWORD env>
```

Currently this will only show you the first line of the console after the command is executed, I'd like to improve this, but it'd be far better if Hytale had a built-in RCON server to execute commands similar to other games. But you can see the full output by viewing the logs/container output.
