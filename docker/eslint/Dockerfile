# LabSecurity ESLint: pinned Node image + the exact dependency tree of package-lock.json (verified 2026-11-17).
# node:24-alpine (Node.js 24, MIT) digest read from the Docker Hub API on 2026-11-17.
FROM docker.io/library/node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5

ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false

WORKDIR /opt/labsec/eslint
COPY package.json package-lock.json eslint.config.mjs ./
# `npm ci` installs exactly what the lockfile says (integrity hashes included) and runs no install scripts.
RUN npm ci --ignore-scripts --omit=dev \
 && chmod -R a+rX /opt/labsec

# The scan runs as the invoking host user; the work copy is mounted read-only at /src.
WORKDIR /src
ENTRYPOINT ["/opt/labsec/eslint/node_modules/.bin/eslint"]
