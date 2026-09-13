/**
 * Прямой HTTP к ClickHouse (:8123, logger/schema/008_audit_v3.sql, таблица
 * waf.audit) — независимая от waf-search сверка: то, что нашлось через API
 * контроллера, должно быть видно и напрямую в обменнике.
 */

export async function chQuery(env, sql) {
  const url = new URL(env.clickhouse);
  url.searchParams.set("query", sql);
  url.searchParams.set("default_format", "JSONEachRow");
  url.searchParams.set("database", env.clickhouseDb);

  const res = await fetch(url, {
    headers: {
      "X-ClickHouse-User": env.clickhouseUser,
      "X-ClickHouse-Key": env.clickhousePassword,
    },
    signal: AbortSignal.timeout(10_000),
  });

  const text = await res.text();

  if (!res.ok) {
    throw new Error(`clickhouse ${res.status}: ${text.slice(0, 300)}`);
  }

  return text
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line));
}

function escapeSql(value) {
  return value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

/** Число различных ray с uri, начинающимся с заданного префикса. */
export async function countByUriPrefix(env, prefix) {
  const escaped = escapeSql(prefix);
  const rows = await chQuery(
    env,
    `SELECT count(DISTINCT ray) AS n FROM waf.audit WHERE uri LIKE '${escaped}%'`,
  );

  return Number(rows[0]?.n ?? 0);
}

/** Число различных ray по любому из префиксов (две e2e-ручки). */
export async function countByUriPrefixes(env, prefixes) {
  const clause = prefixes
    .map((p) => `uri LIKE '${escapeSql(p)}%'`)
    .join(" OR ");
  const rows = await chQuery(
    env,
    `SELECT count(DISTINCT ray) AS n FROM waf.audit WHERE ${clause}`,
  );

  return Number(rows[0]?.n ?? 0);
}
