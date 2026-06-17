FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716 AS downloader

ARG TARGETARCH
ARG TARGETVARIANT
ARG RELEASE_TAG
ARG RELEASE_SHA256_AMD64
ARG RELEASE_SHA256_ARM64
ARG RELEASE_SHA256_ARMV5
ARG RELEASE_SHA256_ARMV7
ARG RELEASE_SHA256_MIPS64LE

RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  unzip \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /out

RUN set -eux; \
  test -n "${RELEASE_TAG}"; \
  test "${RELEASE_TAG}" != "latest"; \
  case "${TARGETARCH}" in \
  amd64) \
  ARTIFACT="MasterDnsVPN_Server_Linux_AMD64.zip"; PREFIX="MasterDnsVPN_Server_Linux_AMD64"; RELEASE_SHA256="${RELEASE_SHA256_AMD64}" ;; \
  arm64) \
  ARTIFACT="MasterDnsVPN_Server_Linux_ARM64.zip"; PREFIX="MasterDnsVPN_Server_Linux_ARM64"; RELEASE_SHA256="${RELEASE_SHA256_ARM64}" ;; \
  arm) \
  case "${TARGETVARIANT}" in \
  v5) ARTIFACT="MasterDnsVPN_Server_Linux_ARMV5.zip"; PREFIX="MasterDnsVPN_Server_Linux_ARMV5"; RELEASE_SHA256="${RELEASE_SHA256_ARMV5}" ;; \
  v7|"") ARTIFACT="MasterDnsVPN_Server_Linux_ARMV7.zip"; PREFIX="MasterDnsVPN_Server_Linux_ARMV7"; RELEASE_SHA256="${RELEASE_SHA256_ARMV7}" ;; \
  *) echo "Unsupported ARM variant: ${TARGETVARIANT}" >&2; exit 1 ;; \
  esac ;; \
  mips64le) \
  ARTIFACT="MasterDnsVPN_Server_Linux_MIPS64LE.zip"; PREFIX="MasterDnsVPN_Server_Linux_MIPS64LE"; RELEASE_SHA256="${RELEASE_SHA256_MIPS64LE}" ;; \
  *) \
  echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
  esac; \
  test -n "${RELEASE_SHA256}"; \
  curl -fsSL --retry 3 --retry-delay 2 \
  -o /tmp/masterdnsvpn.zip \
  "https://github.com/masterking32/MasterDnsVPN/releases/download/${RELEASE_TAG}/${ARTIFACT}"; \
  echo "${RELEASE_SHA256}  /tmp/masterdnsvpn.zip" | sha256sum -c -; \
  unzip -q /tmp/masterdnsvpn.zip -d /out; \
  rm -f /tmp/masterdnsvpn.zip; \
  BIN="$(find /out -type f -name "${PREFIX}_v*" | sort -V | tail -n1)"; \
  if [ -z "${BIN}" ]; then echo "Could not find extracted binary for ${PREFIX}" >&2; exit 1; fi; \
  mv "${BIN}" /out/masterdnsvpn; \
  chmod 0755 /out/masterdnsvpn; \
  find /out -type f ! -path /out/masterdnsvpn -delete

FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716

LABEL org.opencontainers.image.source=https://github.com/masterking32/MasterDnsVPN

ENV DEBIAN_FRONTEND=noninteractive \
  APP_DIR=/opt/masterdnsvpn \
  DATA_DIR=/data \
  CONFIG_FILE=server_config.toml \
  KEY_FILE=encrypt_key.txt

RUN apt-get update && apt-get install -y --no-install-recommends \
  bash \
  ca-certificates \
  tini \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --system --gid 10001 masterdnsvpn \
  && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin masterdnsvpn \
  && mkdir -p /opt/masterdnsvpn /data \
  && chown 10001:10001 /data

COPY --from=downloader /out/masterdnsvpn /opt/masterdnsvpn/masterdnsvpn
COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY server_config.toml.simple /opt/masterdnsvpn/server_config.toml.simple

RUN chmod 0755 /opt/masterdnsvpn/masterdnsvpn /usr/local/bin/docker-entrypoint.sh

WORKDIR /data

EXPOSE 53/tcp 53/udp
VOLUME ["/data"]

USER 10001:10001
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["-nowait"]
