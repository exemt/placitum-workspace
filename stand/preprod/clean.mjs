// Чистая установка глазами пользователя -- то, что он видит сразу после install.sh:
//
//     node clean.mjs [контроллер] [контейнер узла]    умолчания http://127.0.0.1:8080 и placitum-edge-1
//
// В панели один сервер -- сама панель, её пулы ходят в контейнеры с resolve, ни
// примеров, ни тестовых объектов, ни внутреннего сервера на 18081. Все каналы
// конфигурации сошлись (nobody -- канал без получателя в этой установке), флот и
// контейнеры здоровы, в конфигурации узла то же, что в базе.
//
// Код выхода 1, если хоть что-то не сошлось. Смотрит API контроллера мимо калитки,
// на loopback, и docker на этой же машине.
import { execFileSync } from "node:child_process";

const API = process.argv[2] ?? "http://127.0.0.1:8080";
const EDGE = process.argv[3] ?? "placitum-edge-1";

let failed = 0;

function check(label, ok, detail = "") {
  console.log(`${ok ? "ok  " : "FAIL"} ${label}${detail ? ` -- ${detail}` : ""}`);
  if (!ok) {
    failed += 1;
  }
}

async function get(path) {
  const res = await fetch(API + path);
  if (!res.ok) {
    throw new Error(`${path} -> ${res.status}`);
  }
  return res.json();
}

const rows = (body, key) => (Array.isArray(body) ? body : (body?.[key] ?? []));

const { spaces } = await get("/api/spaces");
check("одно пространство default", spaces.length === 1 && spaces[0].name === "default", spaces.map((s) => s.name).join(", "));
const base = `/api/${spaces[0].uuid}`;

const servers = rows(await get(`${base}/servers`), "servers");
check(
  "один сервер -- панель",
  servers.length === 1 && servers[0].name === "panel",
  servers.map((s) => `${s.name} ${JSON.stringify(s.server_names)}`).join("; "),
);

const upstreams = rows(await get(`${base}/upstreams`), "upstreams");
check(
  "пулы панели: panel и panel-login, узлы с resolve",
  upstreams.map((u) => u.name).sort().join(",") === "panel,panel-login" &&
    upstreams.every((u) => (u.peers ?? []).every((p) => p.resolve === true)),
  upstreams
    .map((u) => `${u.name}: ${(u.peers ?? []).map((p) => `${p.host}:${p.port}${p.resolve ? " resolve" : ""}`).join(", ")}`)
    .join("; "),
);

const ports = rows(await get(`${base}/ports`), "ports");
check("нет внутреннего порта 18081", !ports.some((p) => p.port === 18081), ports.map((p) => `${p.name} ${p.address}:${p.port}`).join("; "));

const http = await get(`${base}/http`);
check("resolver в http", (http.nginx?.resolver ?? []).length > 0, (http.nginx?.resolver ?? []).join(" "));
check(
  "объявлен только инспектор калитки панели",
  Object.keys(http.waf?.inspectors ?? {}).join(",") === "auth-panel",
  Object.keys(http.waf?.inspectors ?? {}).join(", "),
);

const datasets = rows(await get(`${base}/datasets`), "datasets");
check("нет схемы-примера", !datasets.some((d) => d.name === "example-openapi.json"), `${datasets.length} наборов`);

if (servers.length > 0) {
  const locations = rows(await get(`${base}/servers/${servers[0].uuid}/locations`), "locations");
  check(
    "пути панели",
    locations.length === 5,
    locations.map((l) => `${l.match === "exact" ? "= " : l.match === "regex" ? "~ " : ""}${l.path}`).join("; "),
  );
}

// Сразу после рассылки канал бывает посреди применения (converging): это не
// расхождение, а минута ожидания. Расхождение -- то, что не сошлось за неё.
const settled = (list) => list.length > 0 && list.every((c) => c.state === "ok" || c.state === "nobody");
let { channels = [] } = await get(`${base}/convergence`);

for (let waited = 0; !settled(channels) && waited < 60; waited += 3) {
  await new Promise((resolve) => setTimeout(resolve, 3000));
  ({ channels = [] } = await get(`${base}/convergence`));
}

check("каналы сошлись", settled(channels), channels.map((c) => `${c.id}=${c.state}`).join(" "));

const fleet = await get("/api/fleet");
const members = ["agents", "inspectors", "stores", "services"].flatMap((key) =>
  (fleet[key] ?? []).map((m) => ({ key, name: m.name ?? m.health?.node_id ?? m.uuid, status: m.status })),
);
const notUp = members.filter((m) => m.status !== undefined && m.status !== "up");
check(
  "флот: все участники up",
  members.length > 0 && notUp.length === 0,
  `${members.length} участников${notUp.length ? `; не up: ${notUp.map((m) => `${m.key}/${m.name}=${m.status}`).join(", ")}` : ""}`,
);

const ps = execFileSync("docker", [
  "ps",
  "-a",
  "--filter",
  "label=com.docker.compose.project=placitum",
  "--format",
  "{{.Names}}|{{.State}}|{{.Status}}",
])
  .toString()
  .trim()
  .split("\n")
  .filter((line) => line !== "");
const sick = ps.filter((line) => {
  const [, state, status] = line.split("|");
  return state !== "running" || /unhealthy|starting/.test(status);
});
check("контейнеры: все running, с пробой -- healthy", ps.length > 0 && sick.length === 0, `${ps.length} шт.${sick.length ? `; ${sick.join("; ")}` : ""}`);

const conf = execFileSync("docker", ["exec", EDGE, "nginx", "-T"], { stdio: ["ignore", "pipe", "ignore"] }).toString();
check("узел: resolver в http", /\n\s*resolver 127\.0\.0\.11/.test(conf));
check("узел: пул panel в zone, узел с resolve", /upstream panel \{[^}]*zone\s+upstream_panel 64k;[^}]*server\s+controller:8080 resolve;/s.test(conf));
check("узел: пул panel-login в zone, узел с resolve", /upstream panel-login \{[^}]*zone\s+upstream_panel-login 64k;[^}]*server\s+auth-http:8080 resolve;/s.test(conf));
check("узел: внутреннего сервера 18081 нет", !conf.includes("18081"));
check("узел: сервер panel на 8081", /listen 8081 default_server;\s*server_name panel;/.test(conf));

console.log(failed === 0 ? "\nчистая установка: всё сходится" : `\nчистая установка: не сходится ${failed}`);
process.exitCode = failed === 0 ? 0 : 1;
