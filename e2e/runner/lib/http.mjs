/**
 * Тонкие обёртки над fetch. Два вида запроса: JSON к API контроллера/поиска
 * (fetchJson) и произвольный запрос к краю nginx, где важен только код ответа
 * и заголовки, а тело ответа не разбирается (rawRequest).
 */

export async function fetchJson(url, opts = {}) {
  const { method = "GET", headers = {}, body, timeoutMs = 10_000 } = opts;
  const hasBody = body !== undefined;

  const res = await fetch(url, {
    method,
    headers: hasBody ? { "content-type": "application/json", ...headers } : headers,
    body: hasBody ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
  });

  const text = await res.text();
  let json = null;

  if (text.length > 0) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }

  return { status: res.status, headers: res.headers, json, text };
}

export async function rawRequest(url, opts = {}) {
  const { method = "GET", headers = {}, body, timeoutMs = 10_000 } = opts;

  const res = await fetch(url, {
    method,
    headers,
    body,
    signal: AbortSignal.timeout(timeoutMs),
  });

  // Тело ответа не нужно, но сокет нужно освободить, а не бросить с чтением
  // на середине.
  await res.arrayBuffer().catch(() => {});

  return { status: res.status, headers: res.headers };
}
