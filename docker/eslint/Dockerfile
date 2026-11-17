# LabSecurity ESLint: pinned Node image + the exact dependency tree of package-lock.json (verified 2026-11-17).
# node:24-alpine (Node.js 24, MIT) digest read from the Docker Hub API on 2026-11-17.
FROM docker.io/library/node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5

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
