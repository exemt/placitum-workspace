# wrk + крошечный HTTP-триггер. Генератор живёт рядом со стендом и не
# пересоздаёт nginx. Каталог кейсов приезжает томом (tests/load), не образом.

FROM node:22-alpine
RUN apk add --no-cache wrk
WORKDIR /app
COPY server.mjs ./
COPY wrk ./wrk
ENV TARGET=http://haproxy:8080 \
    PORT=8090 \
    LOADGEN_CASES=/tests/load/cases.mjs
EXPOSE 8090
CMD ["node", "server.mjs"]
