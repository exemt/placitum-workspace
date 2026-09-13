# Сборки нет: node исполняет TypeScript напрямую, срезая типы -- тот же приём,
# что у backend и inspectors/test, и по той же причине: правится и
# перезапускается это чаще, чем нужен отдельный шаг компиляции.

FROM node:24-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY public ./public

USER node

ENV PORT=8080 \
    APP_NAME=shop \
    APP_LOG=info

# busybox wget есть в базовом alpine-образе, отдельный curl не нужен.
HEALTHCHECK --interval=5s --timeout=2s --start-period=3s --retries=5 \
    CMD ["wget", "--spider", "-q", "http://127.0.0.1:8080/healthz"]

CMD ["node", "src/main.ts"]
