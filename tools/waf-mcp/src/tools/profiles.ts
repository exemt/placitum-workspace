/**
 * Карта роутеров профилей: у каждого инспектора свой раздел API, но форма
 * одна — список, документ, PUT, restore. modsec и ip исторически живут не
 * под `/profiles`, отсюда таблица, а не шаблон строки.
 */

export const INSPECTORS = [
  "modsec",
  "ip",
  "auth",
  "captcha",
  "json",
  "counter",
  "vlai",
  "action",
  "cookie",
  "rewrite",
] as const;

export type InspectorName = (typeof INSPECTORS)[number];

export function profilesBase(inspector: InspectorName): string {
  switch (inspector) {
    case "modsec":
      return "/rule-sets";
    case "ip":
      return "/ip-profiles";
    default:
      return `/${inspector}/profiles`;
  }
}

/**
 * Каналы издания. Ключи совпадают с каналами сходимости контроллера, пути —
 * с `ChannelSpec.send`: правка живёт в базе, пока её не издали в KV.
 */
export const SEND_PATHS: Record<string, string> = {
  nginx: "/config/send",
  agent: "/agent/send",
  rules: "/rules/send",
  ip: "/ip-profiles/send",
  auth: "/auth/send",
  captcha: "/captcha/send",
  json: "/json/send",
  action: "/action/send",
  cookie: "/cookie/send",
  counter: "/counter/send",
  vlai: "/vlai/send",
  rewrite: "/rewrite/send",
};

/** Канал сходимости, который издаёт профили этого инспектора. */
export function channelOf(inspector: InspectorName): string {
  return inspector === "modsec" ? "rules" : inspector;
}

/**
 * Ссылка на профиль: uuid как есть, имя — через список. Списки разных
 * роутеров кладут массив под разными ключами, поэтому берётся первый
 * массив в ответе.
 */
export function resolveRef(
  listRow: unknown,
  ref: string,
): { uuid: string } | { error: string; known: string[] } {
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(ref)) {
    return { uuid: ref };
  }

  const rows = firstArray(listRow);
  const named = rows.filter(
    (r) => typeof r === "object" && r !== null && "name" in r,
  ) as { name: unknown; uuid?: unknown }[];

  const hit = named.find((r) => r.name === ref);

  if (hit !== undefined && typeof hit.uuid === "string") {
    return { uuid: hit.uuid };
  }

  return {
    error: `"${ref}" not found`,
    known: named
      .map((r) => (typeof r.name === "string" ? r.name : ""))
      .filter((n) => n !== ""),
  };
}

export function firstArray(row: unknown): unknown[] {
  if (Array.isArray(row)) {
    return row;
  }
  if (typeof row === "object" && row !== null) {
    for (const value of Object.values(row)) {
      if (Array.isArray(value)) {
        return value;
      }
    }
  }
  return [];
}
