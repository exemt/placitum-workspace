/**
 * Триггер wrk по HTTP. Сам wrk бьёт в HAProxy живого стенда;
 * docker compose up/restart здесь нет.
 *
 * GET  /healthz
 * GET  /cases   каталог кейсов tests/load/cases.mjs (перечитывается по mtime)
 * GET  /run     состояние последнего / текущего прогона
 * POST /run     старт; 409 если уже идёт. Тело -- план:
 *               { case, target: {host, method, path, headers, body, expect},
 *                 flags: {random_ip, unique}, sizes: {body, headers, args},
 *                 steps: [{rate, duration_s}] }
 *
 * Один прогон = ступени по очереди, на каждую свой запуск wrk с одним и тем же
 * планом. После каждой ступени -- её сводка (wrk/parse.mjs), после всех --
 * суд ступеней по порогам кейса и снимок NATS.
 */

import { spawn } from "node:child_process";
import { statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join, resolve } from "node:path";
import { IP_POOLS, META_TAGS, SIZE_TAGS, writePlanLua } from "./wrk/plan.mjs";
import { mergeWrk, parseWrk } from "./wrk/parse.mjs";

const PORT = Number(process.env.PORT ?? 8090);
const TARGET = process.env.TARGET ?? "http://haproxy:8080";
const RUNNER = process.env.LOADGEN_RUNNER === "host" ? "host" : "docker";
const HERE = dirname(fileURLToPath(import.meta.url));
const CASES_PATH = resolve(
  process.env.LOADGEN_CASES ?? join(HERE, "..", "..", "tests", "load", "cases.mjs"),
);
// Умолчание wrk -- 2s, и оно молчаливое: запрос, не уложившийся в него, не даёт
// выборки в гистограмму, но держит соединение все 2 секунды. На прогоне 600 rps
// это съедало 63% бюджета соединений. Значение задаётся явно.
const WRK_TIMEOUT = process.env.WRK_TIMEOUT ?? "10s";
// Соединений на единицу плана. wrk закрытопетлевой: потолок = connections /
// (латентность + пауза), поэтому множитель -- это и есть допущение о среднем
// цикле. 0.25 означало «250 мс», по факту цикл 414 мс.
const WRK_CONN_PER_RPS = Number(process.env.WRK_CONN_PER_RPS ?? 0.5);
// wrk на высокой ступени съедает все CPU контейнера, и этот сервер перестаёт
// отвечать панели -- прогон выглядит пропавшим. wrk уступает: nice, не квота.
const WRK_NICE = process.env.WRK_NICE ?? "10";
const NATS_MONITOR = (process.env.NATS_MONITOR ?? "http://nats:8222").replace(/\/$/, "");

const METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const MAX_STEPS = 10;
const MIN_RATE = 1;
const MAX_RATE = 20000;
const MIN_DUR = 1;
const MAX_DUR = 120;
const MAX_TOTAL_S = 600;
const MAX_HEADERS = 32;
/* Путей в одном плане: кейс из нескольких маршрутов, а не каталог сайта. */
const MAX_PATHS = 16;
const MAX_BODY = 64 * 1024;
const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/;
const CIDR4 = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
/* Пул обхода: сколько адресов и из скольких префиксов их разворачивать. */
const MAX_WALK = 5_000_000;
const MAX_WALK_CIDRS = 4096;

/* Чем считать ступень чистой, если кейс порогов не назвал. */
const DEFAULT_CLEAN = { unexpected_pct: 1, fails: 0, sockets: 0, p99_ms: null };

/** @type {Record<string, unknown>} */
let run = idle();

function idle() {
  return {
    status: "idle",
    runner: RUNNER,
    target: TARGET,
    limits: limits(),
  };
}

function limits() {
  return {
    max_steps: MAX_STEPS,
    min_rate: MIN_RATE,
    max_rate: MAX_RATE,
    min_duration_s: MIN_DUR,
    max_duration_s: MAX_DUR,
    max_total_s: MAX_TOTAL_S,
    max_headers: MAX_HEADERS,
    max_body: MAX_BODY,
    ip_pools: Object.keys(IP_POOLS),
    max_walk: MAX_WALK,
    max_walk_cidrs: MAX_WALK_CIDRS,
    size_tags: SIZE_TAGS,
    meta_tags: META_TAGS,
  };
}

function publicState() {
  return run;
}

/* --- кейсы -------------------------------------------------------------- */

let casesCache = { mtime: 0, rows: [], error: null };

/**
 * Каталог перечитывается, когда файл изменился: правка кейса не требует
 * рестарта. Свежий import -- через query в URL модуля; старые копии остаются в
 * кеше загрузчика, но их единицы и они крошечные.
 */
async function loadCases() {
  let mtime = 0;

  try {
    mtime = statSync(CASES_PATH).mtimeMs;
  } catch (err) {
    casesCache = { mtime: 0, rows: [], error: `cases: ${err.message}` };
    return casesCache;
  }

  if (mtime === casesCache.mtime) {
    return casesCache;
  }

  try {
    const mod = await import(`${pathToFileURL(CASES_PATH).href}?t=${mtime}`);
    const rows = Array.isArray(mod.cases) ? mod.cases : [];
    casesCache = { mtime, rows, error: null };
  } catch (err) {
    casesCache = { mtime, rows: [], error: `cases: ${err.message}` };
  }

  return casesCache;
}

/* --- план --------------------------------------------------------------- */

function asInt(v, min, max) {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isInteger(n) || n < min || n > max) {
    return null;
  }
  return n;
}

function parseTags(raw, allowed) {
  if (raw === undefined || raw === null) {
    return ["orig"];
  }
  if (!Array.isArray(raw)) {
    return null;
  }
  const tags = [];
  for (const tag of raw) {
    if (typeof tag !== "string" || !allowed.includes(tag)) {
      return null;
    }
    if (!tags.includes(tag)) {
      tags.push(tag);
    }
  }
  return tags;
}

function parseHeaders(raw) {
  if (raw === undefined || raw === null) {
    return [];
  }
  if (!Array.isArray(raw) || raw.length > MAX_HEADERS) {
    return null;
  }
  const out = [];
  for (const row of raw) {
    const name = typeof row?.name === "string" ? row.name.trim() : "";
    const value = typeof row?.value === "string" ? row.value.trim() : "";
    if (!HEADER_NAME.test(name) || /[\r\n]/.test(value) || value.length > 8192) {
      return null;
    }
    if (name.toLowerCase() === "host") {
      continue;
    }
    out.push({ name, value });
  }
  return out;
}

function parsePlan(body) {
  const t = body?.target ?? {};
  const host = typeof t.host === "string" ? t.host.trim() : "";
  if (host === "" || !/^[A-Za-z0-9.-]+(:\d+)?$/.test(host)) {
    return { error: "bad_host" };
  }
  const method = typeof t.method === "string" ? t.method.toUpperCase() : "GET";
  if (!METHODS.includes(method)) {
    return { error: "bad_method" };
  }
  const path = typeof t.path === "string" ? t.path.trim() : "";
  if (!path.startsWith("/") || /[\s]/.test(path) || path.length > 4096) {
    return { error: "bad_path" };
  }
  /*
   * Несколько путей в одном плане: поток шлёт их по кругу, поровну. Нужны
   * кейсу, у которого предмет -- не один маршрут, а контур из нескольких:
   * поднимать по прогону на маршрут значило бы мерить их порознь, а они делят
   * и списки, и инспекторов.
   */
  let paths = [];

  if (t.paths !== undefined && t.paths !== null) {
    if (!Array.isArray(t.paths) || t.paths.length > MAX_PATHS) {
      return { error: "bad_paths" };
    }

    for (const row of t.paths) {
      const one = typeof row === "string" ? row.trim() : "";

      if (!one.startsWith("/") || /[\s]/.test(one) || one.length > 4096) {
        return { error: "bad_paths" };
      }

      paths.push(one);
    }
  }
  const headers = parseHeaders(t.headers);
  if (headers === null) {
    return { error: "bad_headers" };
  }
  const bodyText = typeof t.body === "string" ? t.body : "";
  if (Buffer.byteLength(bodyText) > MAX_BODY) {
    return { error: "bad_body" };
  }
  const expect = asInt(t.expect ?? 200, 100, 599);
  if (expect === null) {
    return { error: "bad_expect" };
  }

  const f = body?.flags ?? {};
  const randomIp = typeof f.random_ip === "string" ? f.random_ip : "";
  if (randomIp !== "" && IP_POOLS[randomIp] === undefined) {
    return { error: "bad_ip_pool" };
  }
  const unique = f.unique === true;

  /*
   * Обход списка адресов вместо случайных. Кейс приносит настоящие префиксы
   * (страны, ASN, свои списки) и размер пула; генератор идёт по нему подряд,
   * поэтому прогон повторяем. Когда обход задан, random_ip не используется.
   */
  let walk = null;

  if (f.ip_walk !== undefined && f.ip_walk !== null) {
    const cidrs = f.ip_walk.cidrs;
    const count = asInt(f.ip_walk.count, 1, MAX_WALK);

    if (!Array.isArray(cidrs) || cidrs.length === 0 || cidrs.length > MAX_WALK_CIDRS || count === null) {
      return { error: "bad_ip_walk" };
    }

    for (const c of cidrs) {
      if (typeof c !== "string" || !CIDR4.test(c)) {
        return { error: "bad_ip_walk" };
      }
    }

    walk = { cidrs, count };
  }

  const s = body?.sizes ?? {};
  const sizes = {
    body: parseTags(s.body, SIZE_TAGS),
    headers: parseTags(s.headers, META_TAGS),
    args: parseTags(s.args, META_TAGS),
  };
  if (sizes.body === null || sizes.headers === null || sizes.args === null) {
    return { error: "bad_sizes" };
  }

  const rawSteps = body?.steps;
  if (!Array.isArray(rawSteps) || rawSteps.length < 1 || rawSteps.length > MAX_STEPS) {
    return { error: "bad_steps" };
  }
  const steps = [];
  let total = 0;
  for (const row of rawSteps) {
    const rate = asInt(row?.rate, MIN_RATE, MAX_RATE);
    const duration_s = asInt(row?.duration_s, MIN_DUR, MAX_DUR);
    if (rate === null || duration_s === null) {
      return { error: "bad_step" };
    }
    total += duration_s;
    steps.push({ rate, duration_s });
  }
  if (total > MAX_TOTAL_S) {
    return { error: "too_long" };
  }

  const caseId = typeof body?.case === "string" && body.case !== "" ? body.case : null;

  return {
    case: caseId,
    target: { host, method, path, paths, headers, body: bodyText, expect },
    flags: { random_ip: randomIp, unique, ip_walk: walk },
    sizes,
    steps,
  };
}

/* --- суд ступеней ------------------------------------------------------- */

/**
 * Чистая ступень: неожиданных кодов не больше порога, отказов модуля нет,
 * сокет не рвался, p99 в норме. Потолок -- последняя чистая ступень до первой
 * грязной: после неё цифры уже про перегрузку, а не про предел.
 */
function judge(rows, clean) {
  const limit = { ...DEFAULT_CLEAN, ...(clean ?? {}) };
  const out = [];
  let ceiling = null;
  let broken = false;

  for (const row of rows) {
    const why = [];
    const reqs = row.reqs;
    const failCount = Object.values(row.waf?.fails ?? {}).reduce((s, n) => s + n, 0);
    const pct = reqs > 0 ? (row.unexpected / reqs) * 100 : 0;

    if (reqs === 0) {
      why.push("no_requests");
    }
    if (limit.unexpected_pct !== null && pct > limit.unexpected_pct) {
      why.push("unexpected");
    }
    if (limit.fails !== null && failCount > limit.fails) {
      why.push("fails");
    }
    if (limit.sockets !== null && row.sockets + row.timeouts > limit.sockets) {
      why.push("sockets");
    }
    if (limit.p99_ms !== null && row.latency.p99 != null && row.latency.p99 > limit.p99_ms) {
      why.push("p99");
    }
    const isClean = why.length === 0;
    if (isClean && !broken) {
      ceiling = row.step.rate;
    }
    if (!isClean) {
      broken = true;
    }
    out.push({ ...row, clean: isClean, why });
  }

  return { rows: out, ceiling, limit };
}

/* --- NATS --------------------------------------------------------------- */

function num(v) {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

async function natsSnap() {
  try {
    const [varz, connz] = await Promise.all([
      getJson(`${NATS_MONITOR}/varz`),
      getJson(`${NATS_MONITOR}/connz?subs=1`),
    ]);
    const connections = (connz?.connections ?? [])
      .filter((c) => {
        const name = String(c?.name ?? "");
        return name.startsWith("waf-edge") || name.startsWith("waf-inspector");
      })
      .map((c) => ({
        name: c.name,
        pending_bytes: num(c.pending_bytes) ?? 0,
        in_msgs: num(c.in_msgs) ?? 0,
        out_msgs: num(c.out_msgs) ?? 0,
        subscriptions: num(c.subscriptions) ?? 0,
      }))
      .sort((a, b) => b.pending_bytes - a.pending_bytes);
    return {
      slow_consumers: num(varz?.slow_consumers) ?? 0,
      in_msgs: num(varz?.in_msgs) ?? 0,
      out_msgs: num(varz?.out_msgs) ?? 0,
      connections,
    };
  } catch {
    return null;
  }
}

function getJson(url) {
  return fetch(url, { signal: AbortSignal.timeout(2000) }).then((res) => {
    if (!res.ok) {
      throw new Error(String(res.status));
    }
    return res.json();
  });
}

function busDiff(before, after) {
  if (after === null) {
    return null;
  }
  return {
    slow_consumers: after.slow_consumers,
    slow_consumers_delta: before === null ? null : after.slow_consumers - before.slow_consumers,
    in_msgs_delta: before === null ? null : after.in_msgs - before.in_msgs,
    out_msgs_delta: before === null ? null : after.out_msgs - before.out_msgs,
    connections: after.connections,
  };
}

/* --- прогон ------------------------------------------------------------- */

function wrkScale(rate) {
  const rps = Math.max(1, Number(rate));
  const threads = Math.min(16, Math.max(2, Math.ceil(rps / 150)));
  // Соединений хватает на конвейер (≈ rps × латентность), не «по одному на rps».
  // Сам потолок частоты -- delay() в script.lua, иначе wrk жмёт во все.
  const connections = Math.min(2000, Math.max(threads, Math.ceil(rps * WRK_CONN_PER_RPS), 8));
  return { threads, connections, rps };
}

function startRun(plan, clean) {
  run = {
    status: "running",
    runner: RUNNER,
    target: TARGET,
    limits: limits(),
    plan,
    started_at: new Date().toISOString(),
    log: "",
    by_step: [],
  };

  const append = (text) => {
    const prev = typeof run.log === "string" ? run.log : "";
    run.log = (prev + text).slice(-8000);
  };

  const planSec = plan.steps.reduce((s, step) => s + step.duration_s, 0);
  const wallSec = planSec + 8 * plan.steps.length;
  const planFile = join(tmpdir(), `waf-wrk-${process.pid}.lua`);
  const wrkBin = process.env.WRK || "wrk";
  const script = join(HERE, "wrk", "script.lua");
  let current = null;
  let watchdogFired = false;
  const watchdog = setTimeout(() => {
    watchdogFired = true;
    append(`\nwrk watchdog: нет выхода ${wallSec}s, SIGKILL.\n`);
    if (current !== null) {
      current.kill("SIGKILL");
    }
  }, wallSec * 1000);
  watchdog.unref();

  void (async () => {
    const busBefore = await natsSnap();
    try {
      writeFileSync(planFile, writePlanLua(plan));
    } catch (err) {
      clearTimeout(watchdog);
      run = {
        ...run,
        status: "error",
        finished_at: new Date().toISOString(),
        exit_code: 1,
        log: String(err),
      };
      return;
    }

    const parsed = [];
    let lastCode = 0;
    let lastSignal = null;
    let maxConn = 0;
    for (const step of plan.steps) {
      const scale = wrkScale(step.rate);
      maxConn = Math.max(maxConn, scale.connections);
      const args = [
        "-t",
        String(scale.threads),
        "-c",
        String(scale.connections),
        "-d",
        `${step.duration_s}s`,
        "--latency",
        "--timeout",
        WRK_TIMEOUT,
        "-s",
        script,
        TARGET,
        "--",
        planFile,
        String(scale.rps),
        String(scale.threads),
        String(scale.connections),
      ];
      append(
        `\nwrk -t${scale.threads} -c${scale.connections} -d${step.duration_s}s --timeout ${WRK_TIMEOUT} ${TARGET} -- ${scale.rps} rps\n`,
      );
      const result = await new Promise((resolve) => {
        const nice = process.platform !== "win32" && WRK_NICE !== "";
        const child = nice
          ? spawn("nice", ["-n", WRK_NICE, wrkBin, ...args], { stdio: ["ignore", "pipe", "pipe"] })
          : spawn(wrkBin, args, { stdio: ["ignore", "pipe", "pipe"] });
        current = child;
        let out = "";
        const onData = (buf) => {
          const text = buf.toString();
          out += text;
          // Строка сводки длинная и панели не нужна: в журнал -- только wrk.
          append(text.replace(/^waf-summary: .*$/m, "waf-summary: (разобрана)"));
        };
        child.stdout.on("data", onData);
        child.stderr.on("data", onData);
        child.on("error", (err) => {
          resolve({ code: 1, signal: null, out: String(err.message) + "\n" });
        });
        child.on("close", (code, signal) => {
          resolve({ code: code ?? 1, signal, out });
        });
      });
      current = null;
      lastCode = result.code;
      lastSignal = result.signal;
      parsed.push(parseWrk(result.out, step));
      // Ступени видны по ходу прогона, а не только в конце.
      run = { ...run, by_step: judge(parsed, clean).rows };
      if (watchdogFired) {
        break;
      }
    }

    clearTimeout(watchdog);
    try {
      unlinkSync(planFile);
    } catch {
      // план уже не нужен
    }
    const busAfter = await natsSnap();
    const totals = mergeWrk(parsed, planSec, maxConn);
    const verdict = judge(parsed, clean);
    const ok = parsed.some((row) => row.reqs > 0);
    run = {
      status: ok ? "done" : "error",
      runner: RUNNER,
      target: TARGET,
      limits: limits(),
      plan,
      started_at: run.started_at,
      finished_at: new Date().toISOString(),
      exit_code: lastCode,
      signal: lastSignal,
      log: run.log,
      totals,
      by_step: verdict.rows,
      ceiling: verdict.ceiling,
      clean: verdict.limit,
      bus: busDiff(busBefore, busAfter),
    };
  })();
}

/* --- HTTP --------------------------------------------------------------- */

function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(json),
  });
  res.end(json);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      /* План везёт ещё и префиксы пула, поэтому запас крупнее тела. */
      if (size > MAX_BODY + 4 * 1024 * 1024) {
        reject(new Error("too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new Error("bad_json"));
      }
    });
    req.on("error", reject);
  });
}

const server = createServer((req, res) => {
  const url = (req.url ?? "/").replace(/\?.*$/, "");
  if (req.method === "GET" && url === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
    return;
  }
  if (req.method === "GET" && url === "/cases") {
    void loadCases().then((rows) => {
      /*
       * `needs` панели не нужен и бывает крупным (списки адресов): кейс
       * описывает им, что завести на стенде, и это дело раннера, не формы.
       */
      const cases = rows.rows.map(({ needs, ...row }) => row);
      send(res, 200, { cases, error: rows.error, path: CASES_PATH });
    });
    return;
  }
  if (req.method === "GET" && (url === "/run" || url === "/")) {
    send(res, 200, publicState());
    return;
  }
  if (req.method === "POST" && url === "/run") {
    if (run.status === "running") {
      send(res, 409, publicState());
      return;
    }
    readJson(req)
      .then(async (body) => {
        const plan = parsePlan(body);
        if (plan.error !== undefined) {
          send(res, 400, { error: plan.error });
          return;
        }
        let clean = null;
        if (plan.case !== null) {
          const known = (await loadCases()).rows.find((row) => row.id === plan.case);
          if (known === undefined) {
            send(res, 400, { error: "unknown_case" });
            return;
          }
          clean = known.clean ?? null;
        }
        startRun(plan, clean);
        send(res, 202, publicState());
      })
      .catch((err) => {
        const code = err instanceof Error && err.message === "too_large" ? 413 : 400;
        send(res, code, { error: "bad_json" });
      });
    return;
  }
  res.writeHead(404);
  res.end();
});

server.listen(PORT, () => {
  process.stdout.write(`loadgen listening :${PORT} target=${TARGET} cases=${CASES_PATH}\n`);
});
