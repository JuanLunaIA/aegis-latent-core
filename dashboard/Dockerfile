# syntax=docker/dockerfile:1.7

ARG NODE_IMAGE=node:22.18.0-bookworm-slim@sha256:752ea8a2f758c34002a0461bd9f1cee4f9a3c36d48494586f60ffce1fc708e0e

FROM ${NODE_IMAGE} AS dependencies
WORKDIR /workspace
ENV NEXT_TELEMETRY_DISABLED=1

COPY sdk/typescript/package.json sdk/typescript/package-lock.json ./sdk/typescript/
RUN --mount=type=cache,target=/root/.npm \
    npm ci --ignore-scripts --prefix sdk/typescript

COPY dashboard/package.json dashboard/package-lock.json ./dashboard/
RUN --mount=type=cache,target=/root/.npm \
    npm ci --ignore-scripts --prefix dashboard

FROM dependencies AS builder
WORKDIR /workspace

COPY sdk/typescript/src ./sdk/typescript/src
COPY sdk/typescript/tsconfig.json sdk/typescript/tsconfig.build.json ./sdk/typescript/
RUN npm run build --prefix sdk/typescript

COPY dashboard/src ./dashboard/src
COPY dashboard/next-env.d.ts dashboard/next.config.ts dashboard/tsconfig.json ./dashboard/
RUN npm run build --prefix dashboard

FROM ${NODE_IMAGE} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000

RUN groupadd --system --gid 10001 nextjs \
    && useradd --system --uid 10001 --gid nextjs --home-dir /nonexistent --shell /usr/sbin/nologin nextjs

COPY --from=builder --chown=nextjs:nextjs /workspace/dashboard/.next/standalone ./
COPY --from=builder --chown=nextjs:nextjs /workspace/dashboard/.next/static ./dashboard/.next/static

USER 10001:10001
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/').then(r=>{if(!r.ok)throw Error(String(r.status))}).catch(()=>process.exit(1))"]
CMD ["node", "dashboard/server.js"]
