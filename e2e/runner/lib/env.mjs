/**
 * Адреса сервисов окружения deploy/. По умолчанию — опубликованные на хосте
 * порты из deploy/docker-compose.yml, раннер рассчитан на запуск с хоста, а
 * не изнутри compose-сети. Переопределяются переменными окружения — тот же
 * приём, что у WAF_E2E_*, EDGE, CONTROLLER и т.п. в tests/*.sh.
 */

function pick(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}

export function loadEnv() {
  return {
    controller: pick("WAF_E2E_CONTROLLER", "http://127.0.0.1:8080"),
    edge: pick("WAF_E2E_EDGE", "http://127.0.0.1:8081"),
    redis: pick("WAF_E2E_REDIS", "redis://127.0.0.1:6379"),
    clickhouse: pick("WAF_E2E_CLICKHOUSE", "http://127.0.0.1:8123"),
    clickhouseUser: pick("WAF_E2E_CLICKHOUSE_USER", "waf"),
    clickhousePassword: pick("WAF_E2E_CLICKHOUSE_PASSWORD", "waf"),
    clickhouseDb: pick("WAF_E2E_CLICKHOUSE_DB", "waf"),
    spaceName: pick("WAF_E2E_SPACE", "default"),
    // Три ноды edge-0N из deploy/docker-compose.yml — используются для
    // housekeeping-фильтра ключей Redis (tests/runner/lib/redis.mjs).
    nodes: ["edge-01", "edge-02", "edge-03"],
  };
}
