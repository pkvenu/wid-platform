FROM node:20-alpine AS builder
WORKDIR /build

# Mirror monorepo layout so file: dependency resolves
COPY shared/data-plane-core/ ./shared/data-plane-core/
COPY services/ext-authz-adapter/package*.json ./services/ext-authz-adapter/

WORKDIR /build/services/ext-authz-adapter
RUN npm install --omit=dev --install-links
RUN npm cache clean --force

FROM node:20-alpine
RUN apk add --no-cache wget tini
WORKDIR /app
COPY --from=builder /build/services/ext-authz-adapter/node_modules ./node_modules
COPY services/ext-authz-adapter/src/ ./src/
COPY services/ext-authz-adapter/proto/ ./proto/
COPY services/ext-authz-adapter/package.json ./
RUN chmod -R 755 /app

EXPOSE 9191 8080
HEALTHCHECK --interval=5s --timeout=2s --retries=10 \
  CMD wget -qO- http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "src/adapter.js"]
