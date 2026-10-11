# __APP_NAME__ app image (SDK-API §15). Base pinned by digest: node:24-slim (multi-arch index digest).
# Bump the tag and the digest together; CI pins the built image by digest in the release record.

FROM node:24-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS build
WORKDIR /app
ENV CI=true COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json tsconfig.build.json ./
COPY scripts ./scripts
COPY src ./src
RUN pnpm run build && pnpm prune --prod

FROM node:24-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json tealbrick.manifest.json ./
COPY migrations ./migrations
# Standard manifest location in every opt2 image (tb-exec default --manifest path).
COPY tealbrick.manifest.json /opt/tb/tealbrick.manifest.json
# Data volume mount point (manifest runtime.volumes "data"); TB_DATA_DIR=/data, TB_BACKUP_DIR=/data/backup (C28).
RUN mkdir -p /data/backup && chown -R node:node /data
USER node
EXPOSE 8080
CMD ["node", "dist/main.js"]
