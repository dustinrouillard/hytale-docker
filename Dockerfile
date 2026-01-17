# syntax=docker/dockerfile:1.5
FROM eclipse-temurin:25-jdk-jammy

ARG HYRCON_CLIENT_REPOSITORY=dustinrouillard/hyrcon-client
ARG HYRCON_CLIENT_ASSET_NAME=hyrcon-client-x86_64-unknown-linux-gnu
ARG HYRCON_MOD_REPOSITORY=dustinrouillard/hyrcon
ARG HYRCON_MOD_ASSET_PATTERN=^HyRCON-.*\\.jar$

LABEL org.opencontainers.image.title="Hytale Dedicated Server"
LABEL org.opencontainers.image.description="Container image for the Hytale dedicated server runtime"
LABEL org.opencontainers.image.licenses="Proprietary"

RUN apt-get update && apt-get install -y curl unzip ca-certificates python3 jq && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p \
      /bin \
      /mods \
      /opt/hytale/server \
      /opt/hytale/assets \
      /opt/hytale/cache \
      /data/universe \
      /data/mods \
      /data/logs

WORKDIR /data

RUN curl -fsSL https://downloader.hytale.com/hytale-downloader.zip -o /tmp/hytale-downloader.zip \
    && unzip -j /tmp/hytale-downloader.zip 'hytale-downloader-linux-amd64' -d /bin \
    && mv /bin/hytale-downloader-linux-amd64 /bin/hytale-downloader \
    && rm /tmp/hytale-downloader.zip \
    && chmod +x /bin/hytale-downloader

COPY --chmod=755 oauth.sh /usr/local/bin/hytale-oauth
COPY --chmod=755 docker-entrypoint.sh /usr/local/bin/hytale-entrypoint
COPY --chmod=755 curseforge-mods /usr/local/bin/curseforge-mods
RUN set -eux; \
    api_base="https://api.github.com/repos"; \
    client_release_json=$(curl -fsSL "${api_base}/${HYRCON_CLIENT_REPOSITORY}/releases/latest"); \
    client_asset_url=$(printf '%s\n' "$client_release_json" | jq -r --arg name "$HYRCON_CLIENT_ASSET_NAME" '.assets[] | select(.name == $name) | .browser_download_url' | head -n1); \
    if [ -z "${client_asset_url}" ] || [ "${client_asset_url}" = "null" ]; then echo "Unable to locate HyRCON client asset" >&2; exit 1; fi; \
    curl -fsSL "$client_asset_url" -o /usr/local/bin/hyrcon-client; \
    chmod +x /usr/local/bin/hyrcon-client; \
    ln -sfn /usr/local/bin/hyrcon-client /usr/local/bin/rcon-cli; \
    mod_release_json=$(curl -fsSL "${api_base}/${HYRCON_MOD_REPOSITORY}/releases/latest"); \
    mod_asset_url=$(printf '%s\n' "$mod_release_json" | jq -r --arg pattern "$HYRCON_MOD_ASSET_PATTERN" '.assets[] | select(.name | test($pattern)) | select(.name | endswith("-sources.jar") | not) | .browser_download_url' | head -n1); \
    if [ -z "${mod_asset_url}" ] || [ "${mod_asset_url}" = "null" ]; then echo "Unable to locate HyRCON mod asset" >&2; exit 1; fi; \
    mod_asset_name=$(basename "$mod_asset_url"); \
    curl -fsSL "$mod_asset_url" -o "/mods/${mod_asset_name}"; \
    chmod 0644 "/mods/${mod_asset_name}"

ENV PATH=/bin:/opt/hytale/server:${PATH} \
    HTY_BIND=0.0.0.0:5520 \
    HTY_AUTH_MODE=authenticated \
    HTY_ASSETS=/opt/hytale/assets/Assets.zip \
    HTY_JAR=/opt/hytale/server/HytaleServer.jar \
    HTY_AOT_CACHE=/opt/hytale/server/HytaleServer.aot \
    HTY_IDENTITY_TOKEN= \
    HTY_SESSION_TOKEN= \
    HTY_OWNER_UUID= \
    HTY_DOWNLOADER_BINARY=/bin/hytale-downloader \
    HTY_DOWNLOADER_HOME=/opt/hytale/cache/downloader \
    HTY_DOWNLOADER_PATCHLINE= \
    HTY_DOWNLOADER_EXTRA_ARGS= \
    HTY_DOWNLOADER_SKIP_UPDATE_CHECK=1 \
    HTY_AUTO_DOWNLOAD=1 \
    HTY_DOWNLOAD_TMP=/opt/hytale/cache/hytale-package.zip \
    HTY_DOWNLOAD_EXTRACT=/opt/hytale/cache/extracted \
    HTY_KEEP_DOWNLOAD_ARCHIVE=0 \
    HTY_KEEP_DOWNLOAD_EXTRACT=0 \
    HTY_AUTH_HELPER=/usr/local/bin/hytale-oauth \
    HTY_AUTH_STORE=/data/.auth.json \
    AUTH_FILE=/data/.auth.json \
    HTY_AUTH_OWNER_UUID= \
    OWNER_UUID= \
    HTY_AUTH_PROFILE= \
    PROFILE_USERNAME= \
    HTY_AUTH_REFRESH_INTERVAL_DAYS=7 \
    HTY_AUTH_REFRESH_INTERVAL_SECONDS= \
    HTY_AUTH_QUIET=0 \
    HTY_SKIP_AUTH=0 \
    HTY_EXTRA_ARGS= \
    JAVA_OPTS= \
    RCON_PASSWORD=hytale \
    RCON_BIND=0.0.0.0:5522 \
    RCON_ENABLED=1 \
    RCON_BINARY=/usr/local/bin/hyrcon-client \
    CF_API_KEY='$2a$10$bL4bIL5pUWqfcO7KQtnMReakwtfHbNKh6v1uTpKlzhwoueEJQnPnm' \
    CF_MODS= \
    CF_MODS_DIR=/data/mods \
    CF_MANIFEST_PATH=/data/.cf-manifest.json \
    CF_DATA_ROOT=/data \
    CF_API_BASE_URL=https://api.curseforge.com/v1 \
    CF_GAME_ID=70216 \
    CF_HTTP_RETRIES=3 \
    CF_HTTP_TIMEOUT=60 \
    CF_MODS_HELPER=/usr/local/bin/curseforge-mods \
    CF_MODS_DISABLE_UPDATES=0

EXPOSE 5520/udp 5520/tcp

ENTRYPOINT ["/usr/local/bin/hytale-entrypoint"]

CMD []
