FROM node:20-alpine AS base
WORKDIR /app

# Install deps
COPY server/package.json ./
RUN npm install --omit=dev

# Copy server source
COPY server/ ./server/
COPY src/proof/validator.js ./src/proof/validator.js
COPY src/proof/fingerprint.js ./src/proof/fingerprint.js

WORKDIR /app/server

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3001/health || exit 1

CMD ["node", "index.js"]
