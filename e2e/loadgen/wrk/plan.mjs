/**
 * План для wrk/script.lua: один шаблон запроса и правила его размножения
 * (случайный адрес, уникальный query, добор размеров). Пишется во временный
 * .lua, wrk читает его в init() каждого потока.
 */

const KB = 1024;

export const SIZE_TAGS = ["orig", "1k", "8k", "64k", "256k", "1m"];
export const META_TAGS = ["orig", "1k", "8k", "64k", "256k"];

const SIZE = {
  orig: 0,
  "1k": 1 * KB,
  "8k": 8 * KB,
  "64k": 64 * KB,
  "256k": 256 * KB,
  "1m": 1024 * KB,
};

/*
 * Веса корзин: крупные редкие, чтобы высокая ступень оставалась про rps, а не
 * про полосу. Выбранные корзины равновероятны только когда их одна-две.
 */
const WEIGHT = { orig: 40, "1k": 30, "8k": 15, "64k": 8, "256k": 5, "1m": 2 };

/**
 * Пулы адресов для флага random_ip. `public` -- отбраковка зарезервированных
 * диапазонов прямо в Lua; остальные -- явные CIDR.
 */
export const IP_POOLS = {
  public: [],
  private: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  testnet: ["203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"],
};

export function writePlanLua(plan) {
  const t = plan.target;
  const headers = { Host: t.host };

  for (const row of t.headers) {
    headers[row.name] = row.value;
  }

  const pools = (IP_POOLS[plan.flags.random_ip] ?? []).map(cidrRange);
  /*
   * Список адресов вместо случайных: повторяемость. Кейс приносит настоящие
   * префиксы (страны, ASN, свои списки), генератор разворачивает их в пул
   * заданного размера и обходит по порядку. Один и тот же прогон шлёт один и
   * тот же набор адресов; порядок внутри потока тоже один и тот же, но
   * чередование между потоками зависит от их числа.
   */
  const walk = plan.flags.ip_walk ?? null;
  const walkCidrs = (walk?.cidrs ?? []).map(cidrRange);
  const lines = [
    "return {",
    `  method = ${luaStr(t.method)},`,
    `  path = ${luaStr(t.path)},`,
    `  paths = { ${(t.paths ?? []).map((p) => luaStr(p)).join(", ")} },`,
    `  headers = ${luaHeaders(headers)},`,
    `  body = ${luaStr(t.body ?? "")},`,
    `  expect = ${Number(t.expect)},`,
    `  unique = ${plan.flags.unique ? "true" : "false"},`,
    `  ip_mode = ${luaStr(plan.flags.random_ip ?? "")},`,
    `  ip_pools = { ${pools.map((p) => `{base=${p.base}, size=${p.size}}`).join(", ")} },`,
    `  ip_walk = { ${walkCidrs.map((p) => `{base=${p.base}, size=${p.size}}`).join(", ")} },`,
    `  ip_walk_count = ${walk === null ? 0 : Number(walk.count) || 0},`,
    `  body_pads = ${luaPads(plan.sizes.body)},`,
    `  header_pads = ${luaPads(plan.sizes.headers)},`,
    `  arg_pads = ${luaPads(plan.sizes.args)},`,
    "}",
    "",
  ];

  return lines.join("\n");
}

function cidrRange(cidr) {
  const [addr, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw ?? 32);
  const parts = addr.split(".").map(Number);
  const base = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const size = 2 ** (32 - bits);
  return { base, size };
}

function luaPads(tags) {
  const rows = (tags ?? []).filter((tag) => SIZE[tag] !== undefined);

  if (rows.length === 0) {
    return "{ {bytes=0, w=1} }";
  }

  return `{ ${rows.map((tag) => `{bytes=${SIZE[tag]}, w=${WEIGHT[tag]}}`).join(", ")} }`;
}

function luaHeaders(headers) {
  const rows = Object.entries(headers).map(([k, v]) => `[${luaStr(k)}]=${luaStr(v)}`);
  return `{ ${rows.join(", ")} }`;
}

function luaStr(s) {
  return `"${String(s)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")}"`;
}
