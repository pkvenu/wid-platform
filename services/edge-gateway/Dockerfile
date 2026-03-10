FROM node:20-alpine AS builder
WORKDIR /build

COPY shared/data-plane-core/ ./shared/data-plane-core/
COPY services/edge-gateway/package*.json ./services/edge-gateway/

WORKDIR /build/services/edge-gateway
RUN npm install --omit=dev --install-links 2>/dev/null || true
RUN npm cache clean --force 2>/dev/null || true

FROM node:20-alpine
RUN apk add --no-cache wget tini iptables ip6tables
WORKDIR /app
COPY --from=builder /build/services/edge-gateway/node_modules/ ./node_modules/
COPY services/edge-gateway/src/ ./src/
COPY services/edge-gateway/package.json ./
COPY services/edge-gateway/scripts/ ./scripts/
RUN chmod -R 755 /app

EXPOSE 15001 15006 15000
HEALTHCHECK --interval=5s --timeout=2s --retries=10 \
  CMD wget -qO- http://localhost:15000/healthz || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "src/gateway.js"]
