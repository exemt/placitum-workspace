/*
 * Заводит стенд под витрину (../testapp): апстрим, наборы, три источника входа
 * и их профили, профили счётчика, модификатора, контракта и капчи, объявления
 * инспекторов, сервер shop.waf.test с маршрутами -- и издаёт каналы.
 *
 *     node deploy/stand-shop.mjs
 *
 * Идемпотентно: существующее обновляется, недостающее заводится. Гонять можно
 * сколько угодно раз -- в том числе после перезапуска приложения, когда у него
 * сменился ключ RS256 (пара генерируется на старте, см. testapp/README.md).
 *
 * Контроллер -- WAF_CONTROLLER (умолчание http://127.0.0.1:8080). Публичный
 * ключ берётся у самого приложения через nats-box: с хоста до него не достучаться.
 */

import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

const CTRL = process.env.WAF_CONTROLLER ?? "http://127.0.0.1:8080";
const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = "shop.waf.test";

async function api(method, path, body) {
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
    /* не JSON -- отдаём как есть, в ошибке это видно */
  }

  if (!res.ok) {
    throw new Error(`${method} ${path} -> ${res.status} ${text.slice(0, 500)}`);
  }

  return json;
}

const say = (...parts) => console.log(" ", ...parts);

const spaces = await api("GET", "/api/spaces");
const scope = spaces.spaces.find((s) => s.name === "default").uuid;
const base = `/api/${scope}`;
console.log(`пространство ${scope}`);

/* --- апстрим ------------------------------------------------------------ */

console.log("апстрим");
const upstreams = (await api("GET", `${base}/upstreams`)).upstreams ?? [];
let app = upstreams.find((u) => u.name === "app");

if (app === undefined) {
  app = await api("POST", `${base}/upstreams`, {
    name: "app",
    method: "round_robin",
    peers: [{ host: "app", port: 8080, weight: 1 }],
  });
  say("app -> app:8080 заведён");
} else {
  say("app уже есть");
}

/*
 * Веб-лицо калитки: форму входа и её POST обслуживает отдельный процесс
 * auth-http, а не приложение. Сам инспектор на своём адресе только пропускает
 * (AUTH_SELF) -- рисует форму именно этот апстрим.
 */
let authHttp = upstreams.find((u) => u.name === "auth-http");

if (authHttp === undefined) {
  authHttp = await api("POST", `${base}/upstreams`, {
    name: "auth-http",
    method: "round_robin",
    peers: [{ host: "auth-http", port: 8080, weight: 1 }],
  });
  say("auth-http -> auth-http:8080 заведён");
} else {
  say("auth-http уже есть");
}

/* --- сервер ------------------------------------------------------------- */

/*
 * Сервер заводится раньше источников и профилей: и форма входа (login.uri),
 * и адрес виджета капчи привязаны к серверу, и без него контроллер отвечает
 * server_required.
 */
console.log("сервер");
const serversNow = (await api("GET", `${base}/servers`)).servers ?? [];
let server = serversNow.find((s) => s.name === SERVER);

if (server === undefined) {
  server = await api("POST", `${base}/servers`, {
    name: SERVER,
    server_names: [SERVER],
    enabled: true,
    nginx: {
      root: "/var/www",
      realIpFrom: ["0.0.0.0/0", "::/0"],
      realIpHeader: "X-Forwarded-For",
      errorPages: [400, 401, 403, 429].map((code) => ({
        codes: [code],
        status: code,
        target: "/pages/$waf_deny_name$waf_deny_ext",
      })),
    },
    waf: {
      enabled: true,
      capture: ["headers args body"],
      preview: ["headers=16k/2k", "args=8k/1k", "body=8k"],
      denyMode: "deterministic",
      onAbsent: "block",
      onBusError: "block",
      deadlineMs: 2000,
      deadlinePolicy: "block",
      debugHeader: true,
      actionMax: 192,
      actionsMax: 16,
      scoreDeny: { response: "suspicious", threshold: 100 },
      cookieDefaults: { secure: false, httpOnly: true, sameSite: "Lax" },
      localChecks: [
        { action: "block", dataset: "shop_banned", response: "too_many", variable: "$binary_remote_addr" },
      ],
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "modsec", wave: 1 },
      ],
      responseInspectors: "none",
    },
  });
  say(`${SERVER} заведён`);

  const ports = (await api("GET", `${base}/ports`)).ports ?? [];
  const http8080 = ports.find((p) => p.name === "http-8080");
  await api("POST", `${base}/servers/${server.uuid}/ports`, {
    port_id: http8080.uuid,
    default_server: true,
  });
  say(`слушатель ${http8080.name} привязан`);
} else {
  say(`${SERVER} уже есть`);
}


/* --- маршруты ----------------------------------------------------------- */

console.log("маршруты");
const headers = (extra = []) => [
  { name: "Host", value: "$host" },
  { name: "X-Forwarded-For", value: "$proxy_add_x_forwarded_for" },
  { name: "X-Forwarded-Proto", value: "$scheme" },
  ...extra,
];

const proxy = (extra = []) => ({ proxySetHeaders: headers(extra), proxyHttpVersion: "1.1" });

/*
 * Превью не может быть шире снимка: `nginx -t` отвергает конфиг словами
 * «waf_preview headers is wider than capture». Сервер снимает тело, поэтому
 * маршруту, снимающему только заголовки и параметры, нужен и свой урезанный
 * набор превью -- унаследованный от сервера включал бы body.
 */
const PREVIEW_NO_BODY = ["headers=16k/2k", "args=8k/1k"];
/*
 * Обезвреживание, а НЕ подстановка. `headers.unset` на фазе запроса модуль не
 * поддерживает, поэтому единственный способ обнулить присланный клиентом
 * `X-WAF-User: admin` -- перезаписать его пустым. Ставится это на маршруты,
 * где калитки НЕТ; на закрытых наоборот нельзя -- пустое значение затрёт то,
 * что подставила сама калитка, и приложение увидит гостя вместо вошедшего.
 */
const noSpoof = [{ name: "X-WAF-User", value: '""' }, { name: "X-WAF-Groups", value: '""' }];

const routes = [
  {
    /* Страницы отказа: тела лежат на ноде, инспекторов тут нет по построению. */
    match: "named",
    path: "waf_deny",
    handler: "static",
    upstream_id: null,
    nginx: { root: "/var/lib/waf/store/pages", ssi: true, ssiTypes: ["*"], tryFiles: ["/$waf_deny_name.html", "/blocked.html", "=404"] },
    waf: { enabled: false },
    position: 10,
  },
  {
    match: "prefix",
    path: "/pages/",
    handler: "static",
    upstream_id: null,
    nginx: {
      root: "/var/lib/waf/store",
      internal: true,
      ssi: true,
      ssiTypes: ["*"],
      /*
       * `=404` в хвосте обязателен. Последний аргумент try_files nginx всегда
       * трактует как внутренний редирект, а не как файл: без терминатора
       * `/pages/blocked.html` заворачивает запрос обратно в этот же location,
       * и отказ без собственной страницы (counter_limit, у него page=@blocked)
       * даёт цикл перенаправлений и 500 вместо 429.
       */
      tryFiles: ["/pages/$waf_deny_name$waf_deny_ext", "/pages/$waf_deny_name.html", "/pages/blocked.html", "=404"],
    },
    waf: { enabled: false },
    position: 15,
  },
  {
    match: "exact",
    path: "/healthz",
    nginx: proxy(),
    waf: { enabled: false },
    position: 20,
  },
  {
    /*
     * Адрес формы входа. Инспекторов на нём нет: форма приезжает телом отказа
     * (gate.inline), калитка отдаёт её сама, а маршрут нужен, чтобы адрес
     * вообще существовал -- источник с login.uri сверяется с маршрутами
     * сервера и без него не сохраняется.
     */
    match: "prefix",
    path: "/waf/login",
    /*
     * Форму и её POST обслуживает веб-лицо калитки, не приложение. Инспекторов
     * тут нет по построению: POST формы приходит без доверенной куки, и калитка,
     * стой она здесь, отправляла бы клиента на вход бесконечно.
     */
    upstream_id: authHttp.uuid,
    upstream_uri: "",
    nginx: proxy([{ name: "X-WAF-Return", value: '""' }]),
    waf: {
      capture: ["none"],
      preview: ["none"],
      localRates: [{ key: "$binary_remote_addr", rate: "10r/s", burst: 10, response: "too_many" }],
      requestInspectors: "none",
      responseInspectors: "none",
    },
    position: 21,
  },
  {
    /* Тот же случай, что и у формы входа: адрес виджета капчи обязан существовать. */
    match: "prefix",
    path: "/waf/captcha",
    nginx: proxy(),
    waf: {
      capture: ["none"],
      preview: ["none"],
      localRates: [{ key: "$binary_remote_addr", rate: "10r/s", burst: 10, response: "too_many" }],
      requestInspectors: "none",
      responseInspectors: "none",
    },
    position: 22,
  },
  {
    /* Статика: вызова инспекторов нет вовсе, и это явный none, а не пустой набор. */
    match: "prefix",
    path: "/static/",
    nginx: proxy(noSpoof),
    waf: { capture: ["none"], preview: ["none"], requestInspectors: "none", responseInspectors: "none" },
    position: 25,
  },
  {
    /* Сокет: рукопожатие судят ip и modsec, кадры -- modsec, обе стороны правит модификатор. */
    match: "prefix",
    path: "/socket/",
    protocol: "websocket",
    nginx: { proxyHeaders: "websocket", proxySetHeaders: headers(), proxyHttpVersion: "1.1", proxyReadTimeoutMs: 3600000 },
    waf: {
      capture: ["request headers args", "frame:c2s body=64k", "frame:s2c body=64k"],
      preview: PREVIEW_NO_BODY,
      bodyLimit: "frame:c2s 64k",
      bodyLimitPolicy: "block",
      frameDeadlineMs: 500,
      frameDeadlinePolicy: "block",
      frameScoreDeny: { response: "ws_policy", threshold: 50 },
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "modsec", wave: 1 },
      ],
      frameInspectors: [
        { name: "modsec", wave: 0, timeoutMs: 200 },
        { name: "rewrite", wave: 1, timeoutMs: 200 },
      ],
      responseInspectors: "none",
    },
    position: 30,
  },
  {
    /*
     * Вход и выход приложения: калитка подсматривает их на фазе ответа, и для
     * этого маршрут обязан снимать тело запроса и заголовки ответа.
     */
    match: "exact",
    path: "/api/login",
    nginx: proxy(),
    waf: {
      /*
       * Тело ответа снимается ради предиката `json: ok=true` у источника:
       * без него калитка видит только заголовки и предикат молча не срабатывает
       * -- вход выглядит удачным, а сессия не выучена (AUTH_NO_SESSION дальше).
       */
      capture: ["request headers args body", "response headers body"],
      responseHold: "gate",
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "auth-app", wave: 1, weight: 0 },
      ],
      responseDeadlineMs: 3000,
      responseDeadlinePolicy: "pass",
      responseInspectors: [{ name: "auth-app", wave: 0 }],
    },
    position: 35,
  },
  {
    match: "exact",
    path: "/api/logout",
    nginx: proxy(),
    waf: {
      capture: ["request headers args body", "response headers body"],
      responseHold: "gate",
      requestInspectors: [{ name: "auth-app", wave: 0, weight: 0 }],
      responseDeadlineMs: 3000,
      responseDeadlinePolicy: "pass",
      responseInspectors: [{ name: "auth-app", wave: 0 }],
    },
    position: 36,
  },
  {
    match: "prefix",
    path: "/api/private/",
    nginx: proxy(),
    waf: {
      capture: ["request headers args"],
      preview: PREVIEW_NO_BODY,
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "auth-jwt", wave: 1, weight: 0 },
      ],
      responseInspectors: "none",
    },
    position: 40,
  },
  {
    /* Контракт судит обе стороны: тело запроса и тело ответа. */
    match: "prefix",
    path: "/api/",
    nginx: proxy(),
    waf: {
      capture: ["request headers args body", "response headers body"],
      bodyLimit: "response 4m",
      bodyLimitPolicy: "pass",
      responseHold: "gate",
      localRates: [{ key: "$binary_remote_addr", rate: "50r/s", burst: 50, response: "too_many" }],
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "modsec", wave: 1 },
        { name: "json", wave: 2 },
      ],
      responseDeadlineMs: 3000,
      responseDeadlinePolicy: "pass",
      responseInspectors: [{ name: "json", wave: 0 }],
    },
    position: 45,
  },
  {
    match: "prefix",
    path: "/account",
    nginx: proxy(),
    waf: {
      capture: ["request headers args"],
      preview: PREVIEW_NO_BODY,
      redirectAllow: ["/waf/login"],
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "auth-any", wave: 1, weight: 0 },
      ],
      responseInspectors: "none",
    },
    position: 50,
  },
  {
    match: "prefix",
    path: "/admin",
    nginx: proxy(),
    waf: {
      capture: ["request headers args"],
      preview: PREVIEW_NO_BODY,
      redirectAllow: ["/waf/login"],
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "auth-admins", wave: 1, weight: 0 },
      ],
      responseInspectors: "none",
    },
    position: 55,
  },
  {
    match: "prefix",
    path: "/profile",
    nginx: proxy(),
    waf: {
      capture: ["request headers args"],
      preview: PREVIEW_NO_BODY,
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "auth-app", wave: 1, weight: 0 },
      ],
      responseInspectors: "none",
    },
    position: 60,
  },
  {
    /* Каталог: карточки считает счётчик, виджет капчи приезжает телом ответа. */
    match: "prefix",
    path: "/catalog",
    nginx: proxy(noSpoof),
    waf: {
      capture: ["request headers args", "response headers body"],
      preview: PREVIEW_NO_BODY,
      bodyLimit: "response 4m",
      bodyLimitPolicy: "pass",
      responseHold: "gate",
      scoreDeny: { response: "blocked", threshold: 50 },
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "modsec", wave: 1 },
        { name: "counter", wave: 2 },
        { name: "captcha-inline", wave: 3, weight: 0 },
      ],
      responseDeadlineMs: 3000,
      responseDeadlinePolicy: "pass",
      responseInspectors: [
        { name: "rewrite", wave: 0, timeoutMs: 2500 },
        { name: "counter", wave: 1 },
      ],
    },
    position: 65,
  },
  {
    match: "prefix",
    path: "/item/",
    nginx: proxy(noSpoof),
    waf: {
      capture: ["request headers args", "response headers body"],
      preview: PREVIEW_NO_BODY,
      bodyLimit: "response 4m",
      bodyLimitPolicy: "pass",
      responseHold: "gate",
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "modsec", wave: 1 },
      ],
      responseDeadlineMs: 3000,
      responseDeadlinePolicy: "pass",
      responseInspectors: [{ name: "rewrite", wave: 0, timeoutMs: 2500 }],
    },
    position: 70,
  },
  {
    /* Тело запроса крупное и уезжает в обменник; на отказе -- в архив. */
    match: "exact",
    path: "/upload",
    /* waf_body_limit не может быть шире client_max_body_size: nginx отрежет тело
     * раньше модуля, и `nginx -t` на это ругается прямо. */
    nginx: { ...proxy(noSpoof), clientMaxBodySize: "16m" },
    waf: {
      capture: ["request headers args body"],
      archive: ["request headers args body ttl=1h when=deny"],
      bodyLimit: "request 16m",
      bodyLimitPolicy: "block",
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "modsec", wave: 1 },
      ],
      responseInspectors: "none",
    },
    position: 75,
  },
];

const server_id = server.uuid;
const existing = (await api("GET", `${base}/servers/${server_id}/locations`)).locations ?? [];

for (const route of routes) {
  const doc = {
    handler: "proxy",
    protocol: "http",
    upstream_id: app.uuid,
    upstream_uri: null,
    return_status: null,
    return_page: null,
    return_url: null,
    enabled: true,
    raw: false,
    raw_nginx: "",
    ...route,
  };
  const row = existing.find((l) => l.path === route.path && l.match === route.match);

  if (row !== undefined) {
    await api("PUT", `${base}/locations/${row.uuid}`, { ...doc, uuid: row.uuid, server_id });
    say(`${route.path} обновлён`);
  } else {
    await api("POST", `${base}/servers/${server_id}/locations`, doc);
    say(`${route.path} заведён`);
  }
}

/* Корень builtin: он уже есть, ему правится только начинка. */
const root = existing.find((l) => l.path === "/" && l.match === "prefix");

if (root !== undefined) {
  await api("PUT", `${base}/locations/${root.uuid}`, {
    uuid: root.uuid,
    server_id,
    match: "prefix",
    path: "/",
    position: root.position,
    enabled: true,
    handler: "proxy",
    protocol: "http",
    upstream_id: app.uuid,
    upstream_uri: null,
    return_status: null,
    return_page: null,
    return_url: null,
    raw: false,
    raw_nginx: "",
    nginx: { ...proxy(noSpoof), proxyReadTimeoutMs: 90000 },
    waf: {
      capture: ["request headers args body", "response headers body"],
      archive: ["request headers args body ttl=1h when=deny"],
      bodyLimit: "response 4m",
      bodyLimitPolicy: "pass",
      responseHold: "gate",
      scoreDeny: { response: "blocked", threshold: 50 },
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "modsec", wave: 1 },
      ],
      responseDeadlineMs: 3000,
      responseDeadlinePolicy: "pass",
      responseInspectors: [{ name: "rewrite", wave: 0, timeoutMs: 2500 }],
    },
  });
  say("/ обновлён");
}

/* --- наборы ------------------------------------------------------------- */

console.log("наборы");
let datasets = (await api("GET", `${base}/datasets`)).datasets ?? [];

async function dataset(name, spec) {
  const row = datasets.find((d) => d.name === name);

  if (row !== undefined) {
    say(`${name} уже есть`);
    return row;
  }

  const made = await api("POST", `${base}/datasets`, { name, ...spec });
  datasets = (await api("GET", `${base}/datasets`)).datasets ?? [];
  say(`${name} заведён`);
  return datasets.find((d) => d.name === name) ?? made;
}

const dsUsers = await dataset("shop_users", {
  description: "Учётки витрины: разделы по группам",
  kind: "list",
  type: "string",
  active: false,
});

const dsSessions = await dataset("shop_sessions", {
  description: "Живые сессии витрины: истина калитки, удаление записи завершает сессию",
  kind: "list",
  type: "string",
  active: true,
  ttl: "8h",
});

const dsAppSessions = await dataset("shop_app_sessions", {
  description: "Доверенные куки приложения (провайдер app)",
  kind: "list",
  type: "string",
  active: true,
});

const dsCleared = await dataset("shop_cleared", {
  description: "Живые клиренсы капчи витрины",
  kind: "list",
  type: "string",
  active: true,
  ttl: "24h",
});

/*
 * in_nginx обязателен: набор проверяется локальным слоем на самом краю
 * (waf_local_check), а туда попадают только объявленные как waf_local_dataset.
 * Без этого сборка конфига падает на local_dataset_not_declared.
 */
const dsBanned = await dataset("shop_banned", {
  description: "Адреса, забаненные счётчиком выдачи",
  kind: "list",
  type: "ip",
  active: true,
  ttl: "5m",
  in_nginx: true,
});

if (dsBanned.in_nginx !== true) {
  await api("PUT", `${base}/datasets/${dsBanned.uuid}`, { in_nginx: true });
  say("shop_banned объявлен для локального слоя");
}

/* У контентного набора обязателен тип содержимого: контракт -- JSON. */
const contentTypes = (await api("GET", `${base}/content-types`)).content_types ?? [];
const jsonType = contentTypes.find((t) => t.name === "json");

const dsApi = await dataset("shop_api", {
  description: "Контракт витрины: OpenAPI, по которому судит инспектор контракта",
  kind: "content",
  type: "string",
  active: false,
  content_type_id: jsonType.uuid,
});

/* Контракт берём у самого приложения: так он не расходится с кодом. */
const spec = execFileSync(
  "docker",
  ["compose", "exec", "-T", "nats-box", "wget", "-qO-", "http://app:8080/openapi.json"],
  { cwd: HERE, env: { ...process.env, MSYS_NO_PATHCONV: "1" }, encoding: "utf8" },
);

if (!spec.trimStart().startsWith("{")) {
  throw new Error(`контракт не пришёл: ${spec.slice(0, 200)}`);
}

await api("PUT", `${base}/datasets/${dsApi.uuid}/content`, {
  name: "shop_api",
  blob: Buffer.from(spec, "utf8").toString("base64"),
});
say(`контракт залит, ${spec.length} байт`);

/* --- учётки ------------------------------------------------------------- */

console.log("учётки");
const known = (await api("GET", `${base}/datasets/${dsUsers.uuid}/addresses`)).addresses ?? [];

for (const [login, password, groups] of [
  ["alice", "alice-pw", ["users"]],
  ["bob", "bob-pass", ["users", "admins"]],
]) {
  if (known.some((a) => a.address.startsWith(`${login}:`))) {
    say(`${login} уже есть`);
    continue;
  }

  const line = await api("POST", `${base}/auth/user-line`, { login, password, groups });
  await api("POST", `${base}/datasets/${dsUsers.uuid}/addresses`, { address: line.line });
  say(`${login} заведён (${groups.join(", ")})`);
}

/* --- источники входа ---------------------------------------------------- */

console.log("источники входа");
const pem = execFileSync(
  "docker",
  ["compose", "exec", "-T", "nats-box", "wget", "-qO-", "http://app:8080/keys/jwt.pub"],
  { cwd: HERE, env: { ...process.env, MSYS_NO_PATHCONV: "1" }, encoding: "utf8" },
);

if (!pem.includes("-----BEGIN")) {
  throw new Error(`публичный ключ не пришёл: ${pem.slice(0, 120)}`);
}

const sources = (await api("GET", `${base}/auth/sources`)).sources ?? [];

async function source(name, description, doc, serverId = null) {
  const row = sources.find((s) => s.name === name);

  if (row !== undefined) {
    await api("PUT", `${base}/auth/sources/${row.uuid}`, { server_id: serverId, doc });
    say(`${name} обновлён`);
    return;
  }

  await api("POST", `${base}/auth/sources`, { name, description, server_id: serverId, doc });
  say(`${name} заведён`);
}

/* Свой вход: форму, куку и список держит калитка, приложение о нём не знает. */
await source("shop-login", "Вход на витрину (провайдер local)", {
  login: { uri: "/waf/login", title: "Вход на витрину", note: "", page: "" },
  session: { cookie: "waf_sid_shop", ttl_s: 8 * 3600 },
  list: { sessions: "shop_sessions", ttl_s: 8 * 3600 },
  provider: "local",
  providers: { local: { users: "shop_users" } },
}, server.uuid);

/*
 * Вход приложения: калитка его подсматривает на фазе ответа. Предикаты ровно
 * те, что держит приложение: удача ставит НОВУЮ куку и отвечает ok:true.
 */
await source("shop-app", "Кука витрины, доверие через подглядывание входа", {
  login: { uri: "" },
  list: { sessions: "shop_app_sessions" },
  provider: "app",
  providers: {
    app: {
      cookie: "sid",
      learn: {
        login: { uri: "/api/login", method: "POST" },
        logout: { uri: "/api/logout", method: "POST" },
        success: { status: [200], cookie_new: true, json: { path: "ok", equals: "true" } },
        user: { from: "body.form", field: "username" },
      },
    },
  },
});

await source("shop-jwt", "Токен витрины (RS256, публичный ключ приложения)", {
  login: { uri: "" },
  provider: "jwt",
  providers: {
    jwt: {
      header: "authorization",
      prefix: "Bearer",
      verify: { alg: "RS256", key: pem, leeway_s: 30 },
      claims: { user: "email", groups: "groups" },
    },
  },
});

/* --- профили калитки ---------------------------------------------------- */

console.log("профили калитки");
const authProfiles = (await api("GET", `${base}/auth/profiles`)).profiles ?? [];

const gate = (over = {}) => ({
  redirectMethods: ["GET", "HEAD"],
  redirectStatus: 303,
  denyResponse: "auth_required",
  htmlOnly: true,
  groups: [],
  forbiddenResponse: "auth_forbidden",
  inline: false,
  ...over,
});

async function authProfile(name, description, doc) {
  const row = authProfiles.find((p) => p.name === name);

  if (row !== undefined) {
    await api("PUT", `${base}/auth/profiles/${row.uuid}`, { name, description, doc });
    say(`${name} обновлён`);
    return;
  }

  await api("POST", `${base}/auth/profiles`, { name, description, doc });
  say(`${name} заведён`);
}

await authProfile("shop-any", "Личный раздел: любой вошедший", {
  source: "shop-login",
  gate: gate({ inline: true }),
  trigger: { prior: [], reauthAfterS: 300 },
});

await authProfile("shop-admins", "Админка: только группа admins", {
  source: "shop-login",
  gate: gate({ groups: ["admins"], inline: true }),
  trigger: { prior: [], reauthAfterS: 300 },
});

await authProfile("shop-app", "Сессия приложения: подглядывание входа", {
  source: "shop-app",
  gate: gate({ redirectMethods: [] }),
  trigger: { prior: [], reauthAfterS: 300 },
});

await authProfile("shop-jwt", "Токен приложения", {
  source: "shop-jwt",
  gate: gate({ redirectMethods: [] }),
  trigger: { prior: [], reauthAfterS: 300 },
});

/* --- счётчик: корзина выдачи -------------------------------------------- */

console.log("счётчик");
const shared = (await api("GET", `${base}/counter/shared`)).shared ?? { counters: {}, subjects: {} };

await api("PUT", `${base}/counter/shared`, {
  shared: {
    counters: {
      ...shared.counters,
      /*
       * Корзина выдачи: единица -- карточка, а не запрос. Скребок на per=48
       * жжёт её вчетверо быстрее, чем читатель на per=12, и именно это
       * отличие счётчик и должен ловить.
       */
      shop_objects: { unit: "obj", axes: { ip: { max: 240, loss: 4 }, sess: { max: 240, loss: 4 } } },
    },
    subjects: { ...shared.subjects, sess: { cookie: "waf_cid" } },
  },
});
say("корзина shop_objects на месте");

const counterProfiles = (await api("GET", `${base}/counter/profiles`)).profiles ?? [];
const counterDoc = {
  description: "Витрина: считаем отданные карточки, судим по адресу",
  trigger: { prior: [] },
  request: {
    enabled: true,
    judge: [
      { counter: "shop_objects", axis: "ip", at: 60, action: "score", score: 40, code: "SHOP_HOT" },
      { counter: "shop_objects", axis: "ip", at: 95, action: "deny", score: 0, code: "SHOP_SCRAPE" },
    ],
    denyResponse: "counter_limit",
    outcomes: [
      {
        on: "level",
        at: 95,
        below: false,
        eq: false,
        if: { counter: "shop_objects", axis: "ip" },
        to: "",
        do: "",
        apply: "",
        delta: null,
        value: null,
        counter: "",
        marker: "",
        group: "",
        set: "",
        headers: null,
        args: null,
        body: null,
        when: [],
        list: "shop_banned",
        write: "addr",
        ttlS: 300,
        code: "SHOP_BAN",
      },
    ],
  },
  response: {
    enabled: true,
    measure: [
      {
        /* Метка `obj=<id>` ровно одна на карточку -- см. testapp/src/view.ts. */
        if: { status: [200], contentType: ["text/html", "application/json"], methods: [], direction: [], opcode: [] },
        source: "regex_count",
        regex: "obj=\\d+",
        per: null,
        counter: "shop_objects",
        axes: ["ip"],
      },
    ],
  },
  frame: { enabled: true, measure: [], judge: [], denyResponse: "ws_policy", outcomes: [] },
};

const counterRow = counterProfiles.find((p) => p.name === "shop");

if (counterRow !== undefined) {
  await api("PUT", `${base}/counter/profiles/${counterRow.uuid}`, {
    name: "shop",
    description: counterDoc.description,
    doc: counterDoc,
  });
  say("профиль shop обновлён");
} else {
  await api("POST", `${base}/counter/profiles`, {
    name: "shop",
    description: counterDoc.description,
    doc: counterDoc,
  });
  say("профиль shop заведён");
}

/* --- модификатор -------------------------------------------------------- */

console.log("модификатор");
const rewriteProfiles = (await api("GET", `${base}/rewrite/profiles`)).profiles ?? [];
const group = (name, over) => ({
  name,
  default: true,
  on: "response",
  status: [],
  contentType: [],
  direction: [],
  opcode: [],
  body: [],
  headers: [],
  ...over,
});

const rewriteDoc = {
  description: "Витрина: вырезать рекламу, замаскировать метки и номера, снять служебный заголовок",
  denyResponse: "rewrite_failed",
  groups: [
    group("noads", {
      status: [200],
      contentType: ["text/html"],
      /* Контрольный блок рядом обязан выжить: если исчез -- правило бьёт шире. */
      body: [{ op: "remove", pattern: "<!-- waf:ads -->[\\s\\S]*?<!-- /waf:ads -->", to: "", text: "", maxMatches: 1 }],
    }),
    group("mask", {
      status: [200],
      contentType: ["text/html", "application/json"],
      body: [
        { op: "replace", pattern: "canary-([0-9a-f]{8})", to: "masked-$1", text: "", maxMatches: null },
        { op: "replace", pattern: "\\b(\\d{4})[ ]?\\d{8}[ ]?(\\d{4})\\b", to: "$1********$2", text: "", maxMatches: null },
        { op: "remove", pattern: "debug-token=[0-9a-f]+", to: "", text: "", maxMatches: null },
      ],
    }),
    group("anchors", {
      status: [200],
      contentType: ["text/html"],
      body: [
        { op: "insert_before", pattern: "</head>", to: "", text: "<meta name=\"waf\" content=\"anchor-head\">", maxMatches: 1 },
        { op: "insert_after", pattern: "<!-- waf:anchor:body -->", to: "", text: "<!-- правил модификатор -->", maxMatches: 1 },
      ],
    }),
    group("hdrs", {
      headers: [
        { op: "unset", name: "X-App-Secret", value: "" },
        { op: "set", name: "X-Rewrote", value: "shop" },
      ],
    }),
    /*
     * Сторона c2s, а не s2c, и это ограничение контроллера, а не замысла:
     * модуль разбирает `waf_inspect frame:s2c` (ngx_http_waf_directives.c),
     * но компилятор печатает вызов кадровых инспекторов всегда как frame:c2s
     * (compile/nginx-emit.ts) -- объявить инспектора на ответной стороне из
     * конфигурации сейчас нельзя. Снимать s2c при этом можно: waf_capture
     * frame:s2c на маршруте стоит, кадры в аудит уезжают.
     */
    group("frames", {
      on: "frame",
      direction: ["c2s"],
      body: [{ op: "replace", pattern: "canary-([0-9a-f]{8})", to: "masked-$1", text: "", maxMatches: null }],
    }),
  ],
  prior: [],
};

const rewriteRow = rewriteProfiles.find((p) => p.name === "shop");

if (rewriteRow !== undefined) {
  await api("PUT", `${base}/rewrite/profiles/${rewriteRow.uuid}`, {
    name: "shop",
    description: rewriteDoc.description,
    doc: rewriteDoc,
  });
  say("профиль shop обновлён");
} else {
  await api("POST", `${base}/rewrite/profiles`, {
    name: "shop",
    description: rewriteDoc.description,
    doc: rewriteDoc,
  });
  say("профиль shop заведён");
}

/* --- контракт ----------------------------------------------------------- */

console.log("контракт");
const jsonProfiles = (await api("GET", `${base}/json/profiles`)).profiles ?? [];
const jsonDefault = jsonProfiles.find((p) => p.name === "default");
const jsonDoc = {
  ...structuredClone(jsonDefault.doc),
  description: "Витрина: контракт /api по OpenAPI приложения",
  schema: { kind: "openapi", source: dsApi.uuid, basePath: "" },
};

/*
 * Поставочный `default` тоже надо починить, иначе канал не издаётся вовсе:
 * компилятор собирает ВСЕ профили разом, а у поставочного `schema.source`
 * пуст -- и он же обязателен ("schema.source is required"). Это состояние
 * досталось от поставки, а не от витрины. Пока в пространстве один контракт,
 * честнее всего указать его же: профиль на маршрутах не стоит и ничего не судит.
 */
const jsonDefaultDoc = {
  ...structuredClone(jsonDefault.doc),
  schema: { kind: "openapi", source: dsApi.uuid, basePath: "" },
};

if (jsonDefault.doc?.schema?.source !== dsApi.uuid) {
  await api("PUT", `${base}/json/profiles/${jsonDefault.uuid}`, {
    name: "default",
    description: jsonDefault.description,
    doc: jsonDefaultDoc,
  });
  say("default: подставлена схема (поставочный пуст и канал без неё не издаётся)");
}

const jsonRow = jsonProfiles.find((p) => p.name === "shop");

if (jsonRow !== undefined) {
  await api("PUT", `${base}/json/profiles/${jsonRow.uuid}`, {
    name: "shop",
    description: jsonDoc.description,
    doc: jsonDoc,
  });
  say("профиль shop обновлён");
} else {
  await api("POST", `${base}/json/profiles`, {
    name: "shop",
    description: jsonDoc.description,
    doc: jsonDoc,
  });
  say("профиль shop заведён");
}

/* --- капча -------------------------------------------------------------- */

console.log("капча");
const captchaProfiles = (await api("GET", `${base}/captcha/profiles`)).profiles ?? [];
const captchaDefault = captchaProfiles.find((p) => p.name === "default");
/* Профиль капчи требует сервера: без него сохранение отвечает server_required. */
const captchaDoc = {
  ...structuredClone(captchaDefault.doc),
  path: "/waf/captcha",
  note: "Слишком много просмотров подряд. Подтвердите, что вы не робот.",
  gate: { ...structuredClone(captchaDefault.doc.gate), inline: true },
  clearance: { ...structuredClone(captchaDefault.doc.clearance), list: "shop_cleared" },
};

const captchaRow = captchaProfiles.find((p) => p.name === "shop-inline");

if (captchaRow !== undefined) {
  await api("PUT", `${base}/captcha/profiles/${captchaRow.uuid}`, {
    name: "shop-inline",
    description: "Витрина: виджет телом ответа на том же адресе",
    server_id: server.uuid,
    doc: captchaDoc,
  });
  say("профиль shop-inline обновлён");
} else {
  await api("POST", `${base}/captcha/profiles`, {
    name: "shop-inline",
    description: "Витрина: виджет телом ответа на том же адресе",
    server_id: server.uuid,
    doc: captchaDoc,
  });
  say("профиль shop-inline заведён");
}

/* --- объявления --------------------------------------------------------- */

console.log("объявления");
const http = await api("GET", `${base}/http`);
const inspectors = { ...(http.waf?.inspectors ?? {}) };
const want = {
  "auth-any": { process: "auth2", profile: "shop-any" },
  "auth-admins": { process: "auth2", profile: "shop-admins" },
  "auth-app": { process: "auth2", profile: "shop-app" },
  "auth-jwt": { process: "auth2", profile: "shop-jwt" },
  "captcha-inline": { process: "captcha", profile: "shop-inline" },
  counter: { profile: "shop" },
  rewrite: { profile: "shop" },
  json: { profile: "shop" },
};

let changed = false;

for (const [name, decl] of Object.entries(want)) {
  if (JSON.stringify(inspectors[name] ?? null) !== JSON.stringify(decl)) {
    inspectors[name] = decl;
    changed = true;
  }
}

if (changed) {
  await api("PUT", `${base}/http`, {
    nginx_main: http.nginx_main,
    nginx: http.nginx,
    waf_http: http.waf_http,
    waf: { ...(http.waf ?? {}), inspectors },
    raw: http.raw,
    raw_nginx: http.raw_nginx,
  });
  say(`объявлены: ${Object.keys(want).join(", ")}`);
} else {
  say("объявления уже на месте");
}

/* --- издание ------------------------------------------------------------ */

console.log("издание");

for (const [channel, path] of [
  ["auth", "/auth/send"],
  ["captcha", "/captcha/send"],
  ["counter", "/counter/send"],
  ["rewrite", "/rewrite/send"],
  ["json", "/json/send"],
  ["nginx", "/config/send"],
]) {
  await api("POST", `${base}${path}`);
  say(`${channel} издан`);
}

console.log("готово");
