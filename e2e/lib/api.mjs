/*
 * Клиент API контроллера для e2e. Ничего, кроме HTTP: ни знания о сущностях,
 * ни порядка их заведения -- это в stand.mjs.
 *
 * Адрес -- WAF_CONTROLLER (умолчание http://127.0.0.1:8080), пространство --
 * WAF_E2E_SPACE (умолчание default), как у остальных прогонов.
 *
 * Сбой -- исключение, не process.exit(): на Windows stdout асинхронный, и
 * exit сразу после console.error глотает сообщение.
 */

export const CONTROLLER = process.env.WAF_CONTROLLER ?? "http://127.0.0.1:8080";
export const SPACE = process.env.WAF_E2E_SPACE ?? "default";

export class ApiError extends Error {
  constructor(method, path, status, body) {
    super(`${method} ${path} -> ${status} ${typeof body === "string" ? body.slice(0, 400) : JSON.stringify(body).slice(0, 400)}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.path = path;
    this.method = method;
  }
}

export async function connect(base = CONTROLLER, spaceName = SPACE) {
  const ctrl = base.replace(/\/$/, "");

  const call = async (method, path, body, { timeoutMs = 30_000, allow = [] } = {}) => {
    const res = await fetch(ctrl + path, {
      method,
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    let json = text;

    try {
      json = JSON.parse(text);
    } catch {
      /* не JSON -- отдаём как есть, в ошибке это видно */
    }

    if (!res.ok && !allow.includes(res.status)) {
      throw new ApiError(method, path, res.status, json);
    }

    return { status: res.status, body: json };
  };

  const api = async (method, path, body, opts) => (await call(method, path, body, opts)).body;

  const spaces = await api("GET", "/api/spaces");
  const space = (spaces.spaces ?? []).find((s) => s.name === spaceName);

  if (space === undefined) {
    throw new Error(`пространство ${spaceName} не найдено`);
  }

  const base2 = `/api/${space.uuid}`;

  return {
    ctrl,
    scope: space.uuid,
    base: base2,
    call,
    api,
    /** Тот же вызов, но путь дописывается к пространству. */
    get: (p, opts) => api("GET", base2 + p, undefined, opts),
    post: (p, body, opts) => api("POST", base2 + p, body, opts),
    put: (p, body, opts) => api("PUT", base2 + p, body, opts),
    del: (p, opts) => call("DELETE", base2 + p, undefined, { allow: [404], ...opts }),
  };
}
