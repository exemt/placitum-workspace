/*
 * Фикстуры сценария tests/auth/sessions.sh на стенде: внешние источники
 * калитки (jwt по ключу Juice Shop, app по куке echo-бэкенда), их профили,
 * объявления auth-jwt / auth-app, маршруты на juice.waf.test, апстрим backend,
 * набор доверенных сессий и учётка lalafo для своей сессии. Идемпотентно:
 * существующее обновляется, каналы auth и nginx издаются в конце.
 *
 *     node tests/auth/sessions-fixtures.mjs
 *
 * Контроллер -- WAF_CONTROLLER (умолчание http://127.0.0.1:8080). Публичный
 * ключ Juice Shop берётся из самого приложения через nats-box: с хоста до
 * него не достучаться.
 */

import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const CTRL = process.env.WAF_CONTROLLER ?? "http://127.0.0.1:8080";
const DEPLOY = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "deploy");

async function api(method, path, body) {
  const res = await fetch(CTRL + path, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  if (!res.ok) {
    throw new Error(`${method} ${path} -> ${res.status} ${text.slice(0, 400)}`);
  }
  return json;
}

const PEM = execFileSync(
  "docker",
  ["compose", "exec", "-T", "nats-box", "curl", "-s", "http://juice-shop:3000/encryptionkeys/jwt.pub"],
  { cwd: DEPLOY, env: { ...process.env, MSYS_NO_PATHCONV: "1" }, encoding: "utf8" },
);
if (!PEM.includes("-----BEGIN")) {
  throw new Error("Juice Shop public key is not PEM: " + PEM.slice(0, 80));
}

const spaces = await api("GET", "/api/spaces");
const scope = spaces.spaces.find((s) => s.name === "default").uuid;
const base = `/api/${scope}`;
console.log("scope", scope);

/* --- каталог: процессу auth2 разрешена фаза ответа --------------------- */
const catalog = await api("GET", `${base}/inspectors`);
const auth2 = (catalog.inspectors ?? catalog).find((row) => row.subject === "waf.req.auth");
if (auth2 && !auth2.phases.includes("response")) {
  await api("PUT", `${base}/inspectors/${auth2.uuid}`, { phases: ["request", "response"] });
  console.log("catalog", auth2.name, "phases += response");
}

/* --- апстрим backend --------------------------------------------------- */
const ups = await api("GET", `${base}/upstreams`);
const upstreams = ups.upstreams ?? ups;
let backend = upstreams.find((u) => u.name === "backend");
if (!backend) {
  backend = await api("POST", `${base}/upstreams`, {
    name: "backend",
    method: "round_robin",
    peers: [{ host: "backend", port: 8080, weight: 1 }],
  });
  console.log("upstream backend created");
}
const juice = upstreams.find((u) => u.name === "juice");
if (!juice) {
  throw new Error("upstream juice is missing on the stand");
}

/* --- набор доверенных сессий приложения -------------------------------- */
const ds = await api("GET", `${base}/datasets`);
let sessions = ds.datasets.find((d) => d.name === "echo_sessions");
if (!sessions) {
  sessions = await api("POST", `${base}/datasets`, {
    name: "echo_sessions",
    description: "Доверенные сессии echo-приложения (провайдер app)",
    kind: "list",
    type: "string",
    active: true,
  });
  console.log("dataset echo_sessions created");
}

/* --- источники входа --------------------------------------------------- */
const srcs = await api("GET", `${base}/auth/sources`);

async function upsertSource(name, description, doc) {
  const row = srcs.sources.find((s) => s.name === name);
  if (row) {
    await api("PUT", `${base}/auth/sources/${row.uuid}`, { doc });
    console.log("source", name, "updated");
  } else {
    await api("POST", `${base}/auth/sources`, { name, description, server_id: null, doc });
    console.log("source", name, "created");
  }
}

await upsertSource("juice-jwt", "Токен Juice Shop (RS256, публичный ключ приложения)", {
  login: { uri: "" },
  provider: "jwt",
  providers: {
    jwt: {
      header: "authorization",
      prefix: "Bearer",
      verify: { alg: "RS256", key: PEM, leeway_s: 30 },
      claims: { user: "data.email", groups: "data.role" },
    },
  },
});

await upsertSource("echo-app", "Кука echo-приложения, доверие через подглядывание входа", {
  login: { uri: "" },
  provider: "app",
  list: { sessions: "echo_sessions" },
  providers: {
    app: {
      cookie: "sid",
      learn: {
        login: { uri: "/set-cookie", method: "POST" },
        // Выход обязан отвечать телом: на 204 фаза ответа не запускается.
        logout: { uri: "/status/202", method: "POST" },
        success: { status: [200], cookie_new: true },
        user: { from: "args", field: "user" },
      },
    },
  },
});

/* --- профили ----------------------------------------------------------- */
const profs = await api("GET", `${base}/auth/profiles`);
const gate = {
  redirectMethods: [],
  redirectStatus: 303,
  denyResponse: "auth_required",
  htmlOnly: true,
  groups: [],
  forbiddenResponse: "auth_forbidden",
  inline: false,
};
for (const name of ["juice-jwt", "echo-app"]) {
  if (!profs.profiles.find((p) => p.name === name)) {
    await api("POST", `${base}/auth/profiles`, {
      name,
      description: `Сценарий сессий в аудите: ${name}`,
      doc: { source: name, gate, trigger: { prior: [], reauthAfterS: 300 } },
    });
    console.log("profile", name, "created");
  }
}

/* --- учётка lalafo для своей сессии ------------------------------------ */
const users = ds.datasets.find((d) => d.name === "lalafo_users");
const addrs = await api("GET", `${base}/datasets/${users.uuid}/addresses`);
if (!addrs.addresses.find((a) => a.address.startsWith("tmpsmoke:"))) {
  const line = await api("POST", `${base}/auth/user-line`, {
    login: "tmpsmoke",
    password: "list-truth-1",
    groups: [],
  });
  await api("POST", `${base}/datasets/${users.uuid}/addresses`, { address: line.line });
  console.log("user tmpsmoke created");
}

/* --- объявления: имя вызова -> процесс и профиль ------------------------ */
const http = await api("GET", `${base}/http`);
const inspectors = { ...(http.waf?.inspectors ?? {}) };
let declared = false;
for (const [name, profile] of [["auth-jwt", "juice-jwt"], ["auth-app", "echo-app"]]) {
  const want = { process: "auth2", profile };
  if (JSON.stringify(inspectors[name] ?? null) !== JSON.stringify(want)) {
    inspectors[name] = want;
    declared = true;
  }
}
if (declared) {
  await api("PUT", `${base}/http`, {
    nginx_main: http.nginx_main,
    nginx: http.nginx,
    waf_http: http.waf_http,
    waf: { ...(http.waf ?? {}), inspectors },
    raw: http.raw,
    raw_nginx: http.raw_nginx,
  });
  console.log("declared auth-jwt, auth-app");
}

/* --- маршруты на juice.waf.test ---------------------------------------- */
const servers = await api("GET", `${base}/servers`);
const server = (servers.servers ?? servers).find((s) => s.name === "juice.waf.test");
const locs = await api("GET", `${base}/servers/${server.uuid}/locations`);
const existing = locs.locations ?? locs;

const proxyHeaders = (withUser) => [
  { name: "Host", value: "$host" },
  { name: "X-Forwarded-For", value: "$proxy_add_x_forwarded_for" },
  { name: "X-Forwarded-Proto", value: "$scheme" },
  ...(withUser ? [{ name: "X-WAF-User", value: '""' }] : []),
];

const routes = [
  {
    match: "exact",
    path: "/rest/user/whoami",
    upstream_id: juice.uuid,
    nginx: { proxySetHeaders: proxyHeaders(true), proxyHttpVersion: "1.1" },
    waf: {
      capture: ["request headers args"],
      localChecks: [],
      requestInspectors: [
        { name: "ip", wave: 0 },
        { name: "auth-jwt", wave: 1, weight: 0 },
      ],
      responseInspectors: "none",
    },
  },
  {
    match: "exact",
    path: "/set-cookie",
    upstream_id: backend.uuid,
    nginx: { proxySetHeaders: proxyHeaders(false), proxyHttpVersion: "1.1" },
    waf: {
      capture: ["request headers args body", "response headers"],
      localChecks: [],
      responseHold: "gate",
      requestInspectors: [{ name: "auth-app", wave: 0, weight: 0 }],
      responseDeadlineMs: 3000,
      responseInspectors: [{ name: "auth-app", wave: 0 }],
      responseDeadlinePolicy: "pass",
    },
  },
  /*
   * Две калитки на одном пути: кука приложения на первой волне, чужой токен
   * на второй. Секция sessions на проводе -- массив ровно ради этого случая,
   * и проверить его можно только там, где обе калитки сказали своё.
   */
  {
    match: "prefix",
    path: "/echo/",
    upstream_id: backend.uuid,
    nginx: { proxySetHeaders: proxyHeaders(true), proxyHttpVersion: "1.1" },
    waf: {
      capture: ["request headers args"],
      localChecks: [],
      requestInspectors: [
        { name: "auth-app", wave: 0, weight: 0 },
        { name: "auth-jwt", wave: 1, weight: 0 },
      ],
      responseInspectors: "none",
    },
  },
  {
    match: "prefix",
    path: "/status/",
    upstream_id: backend.uuid,
    nginx: { proxySetHeaders: proxyHeaders(true), proxyHttpVersion: "1.1" },
    waf: {
      capture: ["request headers args", "response headers"],
      localChecks: [],
      responseHold: "gate",
      requestInspectors: [{ name: "auth-app", wave: 0, weight: 0 }],
      responseDeadlineMs: 3000,
      responseInspectors: [{ name: "auth-app", wave: 0 }],
      responseDeadlinePolicy: "pass",
    },
  },
];

for (const route of routes) {
  const doc = {
    ...route,
    position: 25,
    enabled: true,
    handler: "proxy",
    protocol: "http",
    upstream_uri: null,
    return_status: null,
    return_page: null,
    return_url: null,
    raw: false,
    raw_nginx: "",
  };
  const row = existing.find((l) => l.path === route.path && l.match === route.match);
  if (row) {
    await api("PUT", `${base}/locations/${row.uuid}`, { ...doc, uuid: row.uuid, server_id: server.uuid });
    console.log("route", route.path, "updated");
  } else {
    await api("POST", `${base}/servers/${server.uuid}/locations`, doc);
    console.log("route", route.path, "created");
  }
}

/* --- издание ----------------------------------------------------------- */
await api("POST", `${base}/auth/send`);
console.log("auth channel sent");
await api("POST", `${base}/config/send`);
console.log("nginx channel sent");
