# syntax=docker/dockerfile:1
#
# Portvakt's container images, built from the repository root (the build context):
#
#   docker build -f deploy/Dockerfile --target server    -t portvakt-server .
#   docker build -f deploy/Dockerfile --target admin     -t portvakt-admin .
#   docker build -f deploy/Dockerfile --target mock-idp  -t portvakt-mock-idp .   # dev/test only
#   docker build -f deploy/Dockerfile --target demo      -t portvakt-demo .       # dev/test only
#
# `server` and `admin` are the production images: compiled JavaScript (no tsx, no TypeScript, no
# devDependencies), production dependencies only, NODE_ENV=production, a numeric non-root user,
# no npm in the final image, nothing written at run time (read-only root filesystem), no secrets.
# `mock-idp` (the mock upstream IdPs and the dev seed) and `demo` (the TypeScript demo service)
# exist for evaluation and the end-to-end suite only; they are labelled as such and the mock IdP
# refuses NODE_ENV=production.
#
# Base images are pinned by digest (tag kept for readers) as in deploy/images.Dockerfile, where
# `npm run images:check` verifies they are the same; Dependabot's docker ecosystem updates both.
#
# Build arguments for the OCI labels: VERSION, REVISION (the git commit), SOURCE (repository URL),
# CREATED (RFC 3339 build time).

ARG VERSION=1.0.0
ARG REVISION=unknown
ARG SOURCE=unknown
ARG CREATED=unknown

# --- Build: every workspace's dependencies, then the compiled output and the SPA builds. -------
FROM node:24-alpine@sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f AS build
WORKDIR /src
# The lockfile covers every workspace, so npm ci needs each workspace's package.json.
COPY package.json package-lock.json ./
COPY apps/admin/package.json apps/admin/
COPY apps/login/package.json apps/login/
COPY apps/mock-idp/package.json apps/mock-idp/
COPY apps/server/package.json apps/server/
COPY packages/design-system/package.json packages/design-system/
COPY packages/fonts/package.json packages/fonts/
COPY packages/http-kit/package.json packages/http-kit/
COPY packages/sdk-node/package.json packages/sdk-node/
COPY examples/demo-service/package.json examples/demo-service/
COPY e2e/package.json e2e/
# Install scripts stay off, as in CI (nothing in the tree needs one).
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.base.json tsconfig.node.json tsconfig.vite.json ./
COPY packages packages
COPY apps apps
COPY examples/demo-service examples/demo-service
# Libraries first (tsc -b follows the project references), then the apps and the SPAs; the
# server's dev build (with the dev seed) is for the mock-idp image only.
RUN npm run build -w packages/http-kit -w packages/sdk-node \
 && npm run build -w apps/server -w apps/login -w apps/admin -w apps/mock-idp -w examples/demo-service \
 && npx tsc -b apps/server/tsconfig.build-dev.json

# --- Production dependencies, one tree per image (npm ci limited to the workspace). ------------
FROM node:24-alpine@sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f AS manifests
WORKDIR /app
COPY --from=build /src/package.json /src/package-lock.json ./
COPY --from=build /src/apps/admin/package.json apps/admin/
COPY --from=build /src/apps/login/package.json apps/login/
COPY --from=build /src/apps/mock-idp/package.json apps/mock-idp/
COPY --from=build /src/apps/server/package.json apps/server/
COPY --from=build /src/packages/design-system/package.json packages/design-system/
COPY --from=build /src/packages/fonts/package.json packages/fonts/
COPY --from=build /src/packages/http-kit/package.json packages/http-kit/
COPY --from=build /src/packages/sdk-node/package.json packages/sdk-node/
COPY --from=build /src/examples/demo-service/package.json examples/demo-service/
COPY --from=build /src/e2e/package.json e2e/

FROM manifests AS server-deps
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund -w @portvakt/server

FROM manifests AS admin-deps
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund -w @portvakt/admin

FROM manifests AS mock-idp-deps
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund -w @portvakt/mock-idp -w @portvakt/server

FROM manifests AS demo-deps
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund -w @portvakt/demo-service

# --- Runtime base: Node without npm, npx, corepack or yarn. ------------------------------------
# The package managers are removed and the result is copied into an empty image, so they are not
# merely hidden by a later layer (smaller images, nothing that installs code at run time).
FROM node:24-alpine@sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f AS node-slim
RUN rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx       /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-*  && mkdir -p /app

FROM scratch AS runtime
COPY --from=node-slim / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin     NODE_ENV=production
WORKDIR /app
# A numeric user without a home or shell entry; files stay root-owned and read-only to it.
USER 10001:10001

# --- portvakt-server: the broker, its CLIs and the login UI. -----------------------------------
FROM runtime AS server
ARG VERSION
ARG REVISION
ARG SOURCE
ARG CREATED
LABEL org.opencontainers.image.title="portvakt-server" \
      org.opencontainers.image.description="Portvakt identity broker: OIDC provider per tenant, upstream OIDC and SAML federation, admin API and login UI" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="MIT"
COPY --from=server-deps /app /app
COPY --from=build /src/packages/http-kit/dist packages/http-kit/dist
COPY --from=build /src/apps/server/dist apps/server/dist
COPY --from=build /src/apps/server/migrations apps/server/migrations
COPY --from=build /src/apps/login/dist apps/login/dist
WORKDIR /app/apps/server
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
  CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.PORT || 3000}/healthz`).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
# Other commands of the same image (relative to /app/apps/server):
#   node dist/db/migrate-cli.js        migrations as MIGRATION_DATABASE_URL, grants the runtime role
#   node dist/audit/prune-cli.js       audit retention (AUDIT_RETENTION), as the owner role
#   node dist/db/rewrap-cli.js         re-wraps secrets after a MASTER_KEY rotation
#   node dist/config/check-cli.js      problems and warnings of the configuration (names only)
CMD ["node", "dist/main.js"]

# --- portvakt-admin: the admin portal's BFF and SPA. -------------------------------------------
FROM runtime AS admin
ARG VERSION
ARG REVISION
ARG SOURCE
ARG CREATED
LABEL org.opencontainers.image.title="portvakt-admin" \
      org.opencontainers.image.description="Portvakt admin portal: backend for frontend (Portvakt SDK) and single-page application" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="MIT"
COPY --from=admin-deps /app /app
COPY --from=build /src/packages/http-kit/dist packages/http-kit/dist
COPY --from=build /src/packages/sdk-node/dist packages/sdk-node/dist
COPY --from=build /src/apps/admin/dist apps/admin/dist
WORKDIR /app/apps/admin
EXPOSE 3400
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.ADMIN_PORT || 3400}/healthz`).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
# Also: node dist/migrate-sessions.js (creates the session table, ADMIN_MIGRATION_DATABASE_URL).
CMD ["node", "dist/main.js"]

# --- portvakt-mock-idp: development and test only. ---------------------------------------------
FROM runtime AS mock-idp
ARG VERSION
ARG REVISION
ARG SOURCE
ARG CREATED
LABEL org.opencontainers.image.title="portvakt-mock-idp" \
      org.opencontainers.image.description="NOT FOR PRODUCTION. Mock upstream IdPs (OIDC and SAML) and the dev seed of Portvakt, for evaluation and end-to-end tests: it signs anyone in." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="MIT" \
      se.portvakt.image.production="false"
# The mock refuses NODE_ENV=production.
ENV NODE_ENV=development
COPY --from=mock-idp-deps /app /app
COPY --from=build /src/packages/http-kit/dist packages/http-kit/dist
COPY --from=build /src/apps/mock-idp/dist apps/mock-idp/dist
COPY --from=build /src/apps/mock-idp/personas.json apps/mock-idp/personas.json
COPY --from=build /src/apps/server/dist-dev apps/server/dist-dev
COPY --from=build /src/apps/server/migrations apps/server/migrations
WORKDIR /app/apps/mock-idp
EXPOSE 4500
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.MOCK_IDP_PORT || 4500}/healthz`).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
# Also: node /app/apps/server/dist-dev/dev/seed-cli.js (the demo tenant; refuses production).
CMD ["node", "dist/main.js"]

# --- portvakt-demo: the TypeScript demo service (Tjänst A/B); development and test only. -------
FROM runtime AS demo
ARG VERSION
ARG REVISION
ARG SOURCE
ARG CREATED
LABEL org.opencontainers.image.title="portvakt-demo" \
      org.opencontainers.image.description="NOT FOR PRODUCTION. Portvakt demo service (Express, @portvakt/sdk-node), run as Tjänst A and B for evaluation and end-to-end tests." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="MIT" \
      se.portvakt.image.production="false"
COPY --from=demo-deps /app /app
COPY --from=build /src/packages/sdk-node/dist packages/sdk-node/dist
COPY --from=build /src/examples/demo-service/dist examples/demo-service/dist
WORKDIR /app/examples/demo-service
EXPOSE 3100
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.PORT || 3100}/healthz`).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "dist/main.js"]
