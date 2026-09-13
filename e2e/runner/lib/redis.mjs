/**
 * Housekeeping-проверка в Redis — то же, что делают mine()/keys() в
 * tests/body/body.sh, но с явным best-effort: если Redis недосягаем с хоста
 * (например раннер гоняют без опубликованного порта), проверка помечается
 * как пропущенная, а не проваленной.
 */

import Redis from "ioredis";

/**
 * @param {string} url
 * @param {(client: import("ioredis").Redis) => Promise<T>} fn
 * @returns {Promise<{ok: true, value: T} | {ok: false, error: string}>}
 * @template T
 */
export async function withRedis(url, fn) {
  const client = new Redis(url, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    connectTimeout: 3_000,
  });

  try {
    await client.connect();
    const value = await fn(client);
    return { ok: true, value };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    client.disconnect();
  }
}

/** Ключи модуля (edge-0N:...), оставленные нашими нодами. */
export async function moduleKeys(client, nodes) {
  const keys = await client.keys("*");
  const prefixes = nodes.map((n) => `${n}:`);
  return keys.filter((k) => prefixes.some((p) => k.startsWith(p)));
}

/** Число ключей модуля (edge-0N:...), оставленных нашими нодами. */
export async function moduleKeyCount(client, nodes) {
  return (await moduleKeys(client, nodes)).length;
}

/** Тело -- ключ без суффикса :hdr/:arg. Их агент должен снять после архива. */
export function bodyKeys(keys) {
  return keys.filter((k) => !k.endsWith(":hdr") && !k.endsWith(":arg"));
}
