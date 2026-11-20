# ============================================================================
# FAH-Adblock – (c) 2026 Fabian Hammer
# ============================================================================
FROM node:24-alpine

RUN apk add --no-cache tzdata
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY src/ ./src/
COPY public/ ./public/
COPY tools/health.js tools/dnsprobe.mjs ./tools/
COPY BUILD_VERSION ./

ENV NODE_ENV=production DATEN_DIR=/app/data TZ=Europe/Berlin
VOLUME ["/app/data"]
# Port 53 braucht NET_BIND_SERVICE (compose: cap_add), der Rest der Rechte wird verworfen
HEALTHCHECK --interval=30s --timeout=6s --start-period=30s --retries=3 CMD ["node", "tools/health.js"]
CMD ["node", "src/start.js"]
