# syntax=docker/dockerfile:1.7

FROM node:24-bookworm-slim AS testssl-source

ARG TESTSSL_TAG=v3.2.4
ARG TESTSSL_COMMIT=97763a411c525720a5f9bd9d2cded416b10f210a
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${TESTSSL_TAG}" https://github.com/testssl/testssl.sh.git /source/testssl \
    && test "$(git -C /source/testssl rev-parse HEAD)" = "${TESTSSL_COMMIT}" \
    && test -f /source/testssl/LICENSE \
    && test -x /source/testssl/testssl.sh

FROM node:24-bookworm-slim

LABEL org.opencontainers.image.title="Cresswell bounded TLS scanner" \
      org.opencontainers.image.description="Fixed-profile testssl.sh TLS evidence service" \
      org.opencontainers.image.licenses="GPL-2.0-only" \
      org.opencontainers.image.source="https://github.com/TheDudesRepo/dmarc" \
      org.opencontainers.image.vendor="Cresswell" \
      io.cresswell.testssl.source="https://github.com/testssl/testssl.sh" \
      io.cresswell.testssl.version="3.2.4" \
      io.cresswell.testssl.commit="97763a411c525720a5f9bd9d2cded416b10f210a"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      bash \
      bsdextrautils \
      ca-certificates \
      dnsutils \
      openssl \
      procps \
      tini \
      util-linux \
      xxd \
    && rm -rf /var/lib/apt/lists/* \
    && test -x /usr/bin/prlimit \
    && /usr/bin/prlimit --fsize=393216:393216 -- /usr/bin/true \
    && groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/scanner --shell /usr/sbin/nologin scanner

# testssl.sh is unmodified and its complete corresponding source, upstream
# license, mappings, and data files remain available inside the distributed
# image at /opt/testssl.
COPY --from=testssl-source --chown=10001:10001 /source/testssl /opt/testssl
RUN bundled_openssl="/opt/testssl/bin/openssl.$(uname -s).$(uname -m)" \
    && test -x "${bundled_openssl}" \
    && "${bundled_openssl}" version >/dev/null

WORKDIR /opt/scanner
COPY --chown=10001:10001 package.json contract.schema.json THIRD_PARTY_NOTICES.md README.md ./
COPY --chown=10001:10001 src ./src

ENV NODE_ENV=production \
    PORT=8080 \
    TESTSSL_PATH=/opt/testssl/testssl.sh

USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

ENTRYPOINT ["/usr/bin/tini", "--"]
# Limit the whole non-root service UID, including all testssl subprocesses.
CMD ["prlimit", "--nproc=48:48", "--nofile=160:160", "--", "node", "src/main.mjs"]
