# syntax=docker/dockerfile:1.5
FROM rust:1.92-bookworm AS rcon-builder
WORKDIR /workspace
COPY utils/rcon-cli/ /workspace/
RUN cargo build --release

FROM eclipse-temurin:25-jdk-jammy

LABEL org.opencontainers.image.title="Hytale Dedicated Server"
LABEL org.opencontainers.image.description="Container image for the Hytale dedicated server runtime"
LABEL org.opencontainers.image.licenses="Proprietary"

RUN apt-get update && apt-get install -y curl unzip ca-certificates python3 jq && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p \
      /bin \
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
COPY --from=rcon-builder /workspace/target/release/rcon-cli /usr/local/bin/rcon-cli

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
    RCON_BIND=0.0.0.0:25900 \
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

EXPOSE 5520/udp 25900/tcp

ENTRYPOINT ["/usr/local/bin/hytale-entrypoint"]

CMD []
