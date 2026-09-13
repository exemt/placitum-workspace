/*
 * Фикстуры эталона: то, на что опираются наборы и чего нет ни в поставке, ни в примере
 * первой инициализации. Заводится через API перед снятием эталона (e2e.sh baseline) и
 * идемпотентно: повторный запуск ничего не плодит, расходящуюся запись приводит к нужной.
 *
 *     node e2e/fixtures/stand.mjs
 *
 * Контроллер — WAF_CONTROLLER (умолчание http://127.0.0.1:8080), пространство — default.
 */

const CTRL = (process.env.WAF_CONTROLLER ?? "http://127.0.0.1:8080").replace(/\/$/, "");

async function call(method, path, body) {
  const res = await fetch(CTRL + path, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = text;

  try {
    json = JSON.parse(text);
  } catch {
    /* не JSON — отдаём как есть */
  }

  return { status: res.status, body: json };
}

function must(res, want, what) {
  if (res.status !== want) {
    throw new Error(`${what} -> ${res.status} ${JSON.stringify(res.body).slice(0, 300)}`);
  }

  return res.body;
}

const spaces = must(await call("GET", "/api/spaces"), 200, "GET /api/spaces");
const scope = (spaces.spaces ?? []).find((s) => s.name === "default")?.uuid;

if (scope === undefined) {
  throw new Error("нет пространства default");
}

/*
 * Ответ отказа error. Маршруты наборов пишут `waf_exception request deny response=error`,
 * чтобы отказ шины был виден своим кодом, а в поставке такой записи нет.
 *
 * Без page, как у поставочных записей: `page=` у записи каталога — named location (`@…`), а не
 * имя объекта «Страницы». Имя объекта контроллер принимает и печатает как есть, а nginx -t на
 * узле отвечает «page= expects a named location», и узел не применяет поколение целиком.
 */
const DENY = { name: "error", type: "http", spec: { status: 503 } };

const listed = must(await call("GET", `/api/${scope}/deny-responses`), 200, "GET deny-responses");
const row = (listed.deny_responses ?? []).find((r) => r.name === DENY.name);

if (row === undefined) {
  must(await call("POST", `/api/${scope}/deny-responses`, DENY), 201, `POST deny-responses ${DENY.name}`);
  console.log(`ответ отказа ${DENY.name}: заведён (${JSON.stringify(DENY.spec)})`);
} else if ((row.type ?? "http") === DENY.type && JSON.stringify(row.spec ?? {}) === JSON.stringify(DENY.spec)) {
  console.log(`ответ отказа ${DENY.name}: уже есть`);
} else {
  must(await call("PUT", `/api/${scope}/deny-responses/${row.uuid}`, DENY), 200, `PUT deny-responses ${DENY.name}`);
  console.log(`ответ отказа ${DENY.name}: приведён к ${JSON.stringify(DENY.spec)}, было ${JSON.stringify(row.spec)}`);
}
