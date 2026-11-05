# Build from the repository root:  docker build -f docker/Dockerfile -t osmosecure:local .
# No secrets are baked in. Pass credentials at runtime (env_file or -e) and mount your config.
FROM node:22-slim AS build
WORKDIR /app/cli
COPY cli/package.json cli/package-lock.json ./
RUN npm ci
COPY cli/tsconfig.json ./
COPY cli/scripts ./scripts
COPY cli/src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-slim
ENV NODE_ENV=production \
    OSMOSECURE_DATA_DIR=/data
WORKDIR /app
COPY --from=build /app/cli/package.json ./package.json
COPY --from=build /app/cli/node_modules ./node_modules
COPY --from=build /app/cli/dist ./dist
RUN mkdir -p /data /config && chown -R node:node /data /config
USER node
VOLUME ["/data"]
WORKDIR /config
# The claude-cli triage backend needs the claude binary, which this image does not include.
# Use TRIAGE_BACKEND=anthropic-api here, or extend the image yourself.
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["watch", "--config", "/config/osmosecure.config.json"]
