# Multi-stage build for mcp-guardian
# Runtime has zero npm dependencies — only the compiled JS is needed.

FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

# --- Runtime stage ---
FROM node:20-alpine

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./
COPY guardian.example.yaml ./guardian.yaml

ENTRYPOINT ["node", "dist/index.js"]
CMD ["--config", "/app/guardian.yaml"]
