# Hytale Docker Container

### First-Run Authentication

When you first run this docker container it will ask you to go through the device authentication process twice, the first time is for authenticating the game server, and the second one is for authenticating the Hytale Downloader CLI to download the assets and server jar file.

You should only have to do this one time within a 30-day period according to token expiration in the [following article](https://support.hytale.com/hc/en-us/articles/45328341414043-Server-Provider-Authentication-Guide#token-lifecycle).

### Key Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
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
| `HTY_SKIP_AUTH` | `0` | Set to `1` to bypass automatic OAuth bootstrap (expects tokens via env or file, and a pre-existing server jar with assets zip). |

If `HTY_IDENTITY_TOKEN` / `HTY_SESSION_TOKEN` are not supplied, the entrypoint invokes `/usr/local/bin/hytale-oauth` to complete the device authentication flow automatically. Credentials are written to `/data/.auth.json`, and helper options accept the `AUTH_*` aliases (for example `AUTH_OWNER_UUID`, `AUTH_PROFILE`, `AUTH_HELPER`). Set `HTY_SKIP_AUTH=1` (or `SKIP_AUTH=1`) to disable this bootstrap when you plan to manage tokens yourself.

### Run: Use device OAuth for server assets, and server session creation

```sh
docker run -d \
  --name hytale \
  -p 5520:5520/udp \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/main:/opt/hytale" \
  ghcr.io/dustinrouillard/hytale
```

### Run: Supplying Session Tokens manually
*You should just use the above option if you want to make it easy, since it handles all the oauth logic for you*

```sh
docker run -d \
  --name hytale \
  -p 5520:5520/udp \
  -e HTY_IDENTITY_TOKEN="IDENTITY_TOKEN" \
  -e HTY_SESSION_TOKEN="SESSION_TOKEN" \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/main:/opt/hytale" \
  ghcr.io/dustinrouillard/hytale
```

### Volumes to Persist

| Host Path (example) | Container Path | Contents |
| --- | --- | --- |
| `./main` | `/opt/hytale` | Server binaries, assets and download cache |
| `./data` | `/data` | World, mods, configs, and other server files |
