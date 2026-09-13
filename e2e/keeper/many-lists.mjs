#!/usr/bin/env node
/*
 * Сто активных списков разного размера: как keeper их хранит, как они едут к
 * краям, режет ли модуль записанные адреса, сколько времени проходит от
 * отправки адреса в keeper до блокировки на краю и что происходит на
 * переполнении.
 *
 *     node tests/keeper/many-lists.mjs             # весь прогон со сносом
 *     node tests/keeper/many-lists.mjs --plan      # только расчёт памяти
 *     node tests/keeper/many-lists.mjs --keep      # не сносить (для разбора)
 *     node tests/keeper/many-lists.mjs --clean     # снести остатки e2e-ml- и выйти
 *     --lists 100 --min 10 --max 100000 --short-ttl 2   # число, размеры, срок коротких (мин)
 *     --edge 100                                    # сколько списков объявить на краях
 *     --rounds 60                                   # раундов замера задержки
 *
 * Размеры идут геометрически от min до max: каждый порядок величины
 * представлен одинаково, 25 списков на порядок при ста. Лимит каждого равен
 * его размеру. Каждый десятый список живёт short-ttl минут, остальные -- час.
 *
 * Края: модуль принимает не больше NGX_HTTP_WAF_MAX_DATASETS наборов на
 * конфигурацию (ngx_http_waf.h; 128 с 11.09, раньше 32 -- прогон читает число
 * из исходника), и эти места делят все наборы стенда. Один слот занимает
 * отдельный список замера задержки.
 *
 * Блокировка: сервер прогона берёт адрес клиента из X-Forwarded-For (realip),
 * маршрут режет локальной проверкой по двадцати спискам (каждый десятый и все
 * короткие) и по списку замера. Проверяет и меряет зонд block-probe.mjs,
 * запущенный в контейнере в сети стенда: один процесс пишет в keeper и сам
 * опрашивает три края, так что задержка -- по одним часам.
 *
 * Прогон автономный, как load/logic: всё заводится через API контроллера,
 * конфигурация краёв издаётся, записи идут прямо в keeper пачками `values`
 * по waf.sets.<набор>.event -- контроллер пишет по событию на адрес, миллион
 * так не налить. В конце всё сносится журналом.
 *
 * Переполнения по памяти прогон не добивается нарочно: память считается до
 * старта, и если набор не влезает, прогон не начинается. Проверяется
 * переполнение набора (лимит -> отказ `full`, повтор существующего значения
 * проходит; идёт до проверок блокировки, пока короткие списки полны) и
 * освобождение по сроку (keeper метёт EXPIRED, лимит снова
 * принимает записи, край перестаёт резать истёкшее).
 */

import { execFile } from "node:child_process";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { dockerStats, KEEPER } from "../lib/hot.mjs";
import { apply, connect, converge, publish } from "../lib/stand.mjs";

const run = promisify(execFile);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DEPLOY = join(ROOT, "deploy");
const REPORTS = join(ROOT, "tests", "runner", "reports");
const MODULE_SRC = join(ROOT, "nginx", "module", "src");

/* Клиент NATS -- из node_modules контроллера: у тестов своего нет. */
const require = createRequire(join(ROOT, "controller", "package.json"));
const { connect: natsConnect } = require("nats");

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const num = (name, def) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] !== undefined ? Number(argv[i + 1]) : def;
};

const NATS_URL = process.env.WAF_NATS ?? "nats://127.0.0.1:4222";
const NODE_IMAGE = process.env.WAF_NODE_IMAGE ?? "node:22-alpine";
const NETWORK = process.env.WAF_NETWORK ?? "waf_default";
const PREFIX = "e2e-ml-";
const LISTS = num("--lists", 100);
const MIN = num("--min", 10);
const MAX = num("--max", 100_000);
const SHORT_TTL_MIN = num("--short-ttl", 2);
const ROUNDS = num("--rounds", 60);
const BATCH = 5000;
const PARALLEL = 16;
const SAMPLE = 20;
const EDGES = ["waf-edge-01-1", "waf-edge-02-1", "waf-edge-03-1"];
const EDGE_HOSTS = ["edge-01:8080", "edge-02:8080", "edge-03:8080"];
const ORIGIN = "e2e-many-lists";
const SERVER = "e2e-ml.waf.test";
const PROBE_PATH = "/ml/probe";
const LAT = { name: `${PREFIX}lat`, size: 10_000, ttl: "10m" };
const APP = { name: `${PREFIX}app`, peers: [{ host: "app", port: 8080 }] };

/*
 * Мерки на запись -- прогон горячего списка на миллион, 11.09 (tests/load
 * hot-list, отчёт в tests/load/README.md): redis-internal 187 МиБ, keeper 356
 * МиБ, край 167 МиБ на 1 000 000 записей. Зона края -- формула модуля
 * (ngx_http_waf_shm_fit): 128 Б на запись + 256 КиБ на набор. Провод --
 * wire/pack.go: 15 Б на IPv4-запись в пакете и снапшоте.
 */
const PER = { redis: 196, keeper: 373, edgeRss: 175, zone: 128, zoneSet: 256 * 1024, wire: 15 };
const MiB = 1024 * 1024;

const say = (...p) => console.log("   ", ...p);
const head = (t) => console.log(`\n${t}`);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const fmt = (n) => (n === null || n === undefined ? "--" : String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, " "));
const mb = (bytes) => `${(bytes / MiB).toFixed(1)} МиБ`;
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const dec = (b) => JSON.parse(new TextDecoder().decode(b));

/* --- места на краях ------------------------------------------------------- */

/** Потолок наборов на конфигурацию -- из исходника модуля, а не копией здесь. */
async function moduleDatasetMax() {
  const walk = async (dir) => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) {
        const v = await walk(p);
        if (v !== null) return v;
      } else if (e.name.endsWith(".h")) {
        const m = /#define\s+NGX_HTTP_WAF_MAX_DATASETS\s+(\d+)/.exec(await readFile(p, "utf8"));
        if (m) return Number(m[1]);
      }
    }
    return null;
  };
  return (await walk(MODULE_SRC)) ?? 32;
}

/** Наборы, которые уже объявлены на краях без нас: они делят те же места. */
async function declaredOnEdges(ctx) {
  const res = await ctx.call("GET", `${ctx.base}/config/preview`, undefined, { allow: [422] });
  const text = typeof res.body === "string" ? res.body : res.body?.text ?? "";
  const names = new Set([...text.matchAll(/waf_local_dataset\s+([A-Za-z0-9_-]+)/g)].map((m) => m[1]));
  return [...names].filter((n) => !n.startsWith(PREFIX));
}

/* --- план --------------------------------------------------------------- */

function plan(edgeCount) {
  const rows = [];

  for (let i = 0; i < LISTS; i += 1) {
    const size = Math.max(1, Math.round(MIN * Math.pow(MAX / MIN, LISTS === 1 ? 1 : i / (LISTS - 1))));
    const short = i % 10 === 5;

    rows.push({
      i,
      name: `${PREFIX}${String(i).padStart(3, "0")}`,
      size,
      short,
      ttl: short ? `${SHORT_TTL_MIN}m` : "1h",
      edge: false,
      check: false,
    });
  }

  /*
   * На края -- равномерно по размерам (самый маленький и самый большой
   * обязательно) плюс коротких, чтобы истечение доехало до краёв.
   */
  const pick = new Set();
  const shorts = rows.filter((r) => r.short).map((r) => r.i);
  for (const s of [shorts[Math.floor(shorts.length / 2)], shorts[shorts.length - 1]]) {
    if (s !== undefined && pick.size < edgeCount) pick.add(s);
  }
  const even = Math.max(0, edgeCount - pick.size);
  for (let j = 0; j < even; j += 1) {
    pick.add(even === 1 ? LISTS - 1 : Math.round((j * (LISTS - 1)) / (even - 1)));
  }
  for (let i = LISTS - 1; pick.size < Math.min(edgeCount, LISTS) && i >= 0; i -= 1) pick.add(i);
  for (const i of pick) rows[i].edge = true;

  /* Режет маршрут по каждому десятому и по всем коротким из тех, что на краях. */
  for (const r of rows) r.check = r.edge && (r.short || r.i % 10 === 9);

  return rows;
}

/* --- стенд: Redis, keeper, docker --------------------------------------- */

async function redis(...args) {
  const { stdout } = await run(
    "docker",
    ["compose", "exec", "-T", "redis-internal", "redis-cli", "--raw", ...args],
    { cwd: DEPLOY, windowsHide: true, maxBuffer: 64 * MiB, env: { ...process.env, MSYS_NO_PATHCONV: "1" } },
  );
  return stdout.trim();
}

async function redisMemory() {
  const text = await redis("INFO", "memory");
  const get = (k) => Number((new RegExp(`^${k}:(\\d+)`, "m").exec(text) ?? [])[1] ?? 0);
  return { used: get("used_memory"), rss: get("used_memory_rss"), peak: get("used_memory_peak"), max: get("maxmemory") };
}

/** Ключи прогона в Redis по видам: состав, пакеты журнала, снапшоты. */
async function census() {
  const count = async (pattern) => {
    const out = await redis("--scan", "--pattern", pattern, "--count", "1000");
    return out === "" ? 0 : out.split("\n").length;
  };

  return {
    sets: await count(`waf:set:${PREFIX}*`),
    diffs: await count(`waf:diff:${PREFIX}*`),
    snaps: await count(`waf:snap:${PREFIX}*`),
  };
}

/** Сколько байт Redis держит на набор данного размера: состав, повод, метка. */
async function keyMemory(name) {
  const one = async (key) => Number((await redis("MEMORY", "USAGE", key, "SAMPLES", "0")) || 0);
  const set = await one(`waf:set:${name}`);
  const why = await one(`waf:set:${name}:why`);
  const meta = await one(`waf:set:${name}:meta`);
  return { set, why, meta, total: set + why + meta };
}

async function keeperSets() {
  const res = await fetch(`${KEEPER}/sets`);
  if (!res.ok) throw new Error(`keeper ${res.status} на /sets`);
  const rows = await res.json();
  return new Map((Array.isArray(rows) ? rows : []).filter((r) => r.name.startsWith(PREFIX)).map((r) => [r.name, r]));
}

async function limitOf(container) {
  const { stdout } = await run("docker", ["inspect", "--format", "{{.HostConfig.Memory}}", container], { windowsHide: true });
  return Number(stdout.trim()) || 0;
}

/** Размер "512m" / "1g" / "256k" -> байты. */
function sizeOf(text) {
  const m = /^(\d+)([kKmMgG]?)$/.exec(String(text ?? "").trim());
  if (m === null) return 0;
  const k = { "": 1, k: 1024, m: MiB, g: 1024 * MiB }[m[2].toLowerCase()];
  return Number(m[1]) * k;
}

/**
 * converge кидает на `failed`, а сходимость ещё несколько секунд может
 * показывать отказ прошлого поколения: переспросить, пока края не применят
 * новое.
 */
async function convergeSure(ctx, channels, opts) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await converge(ctx, channels, opts);
    } catch (err) {
      if (attempt >= 4 || !/: failed/.test(err.message)) throw err;
      await wait(5000);
    }
  }
}

/** Зонд в сети стенда: одна строка JSON на выходе. */
async function probe(input) {
  const { stdout } = await run(
    "docker",
    ["run", "--rm", "--network", NETWORK, "-v", `${ROOT.replace(/\\/g, "/")}:/w:ro`, NODE_IMAGE,
      "node", "/w/tests/keeper/block-probe.mjs", JSON.stringify(input)],
    { windowsHide: true, maxBuffer: 64 * MiB, timeout: 900_000, env: { ...process.env, MSYS_NO_PATHCONV: "1" } },
  );
  return JSON.parse(stdout.trim().split("\n").pop());
}

/* --- расчёт памяти ------------------------------------------------------ */

async function budget(ctx, rows) {
  const total = rows.reduce((s, r) => s + r.size, 0);
  const onEdge = rows.filter((r) => r.edge);
  const edgeTotal = onEdge.reduce((s, r) => s + r.size, 0) + LAT.size;
  const mem = await redisMemory();
  const stats = await dockerStats();
  const zone = sizeOf((await ctx.get("/http")).waf_http?.shmZone?.size);
  const keeperLimit = await limitOf("waf-keeper-1");
  const edgeLimit = await limitOf("waf-edge-01-1");
  const redisLimit = await limitOf("waf-redis-internal-1");

  /*
   * Redis: состав постоянно, плюс переходное -- пакеты журнала живут 90 с, и
   * если налить быстрее, в Redis разом лежит весь налив второй раз; снапшоты
   * живут 30 с, по одному на набор.
   */
  const redisSteady = total * PER.redis;
  const redisPeak = mem.used + redisSteady + 2 * total * PER.wire;
  const keeperNeed = (stats["waf-keeper-1"]?.mem ?? 0) * MiB + total * PER.keeper;
  const zoneNeed = edgeTotal * PER.zone + (onEdge.length + 1) * PER.zoneSet;
  const edgeNeed = (stats["waf-edge-01-1"]?.mem ?? 0) * MiB + edgeTotal * PER.edgeRss;

  const lines = [
    ["redis-internal, maxmemory", redisPeak, mem.max, `сейчас ${mb(mem.used)}, состав ${mb(redisSteady)}, пик с пакетами и снапшотами`],
    ["redis-internal, контейнер", redisPeak * 1.2, redisLimit, "RSS с запасом 20% на фрагментацию"],
    ["keeper, контейнер", keeperNeed, keeperLimit, `сейчас ${fmt(stats["waf-keeper-1"]?.mem)} МиБ + ${PER.keeper} Б на запись`],
    ["зона края, waf_shm_zone", zoneNeed, zone, `${onEdge.length + 1} наборов, ${fmt(edgeTotal)} записей: ${PER.zone} Б на запись + 256 КиБ на набор`],
    ["край, контейнер", edgeNeed, edgeLimit, `сейчас ${fmt(stats["waf-edge-01-1"]?.mem)} МиБ + ${PER.edgeRss} Б на запись`],
  ];

  const fits = lines.every(([, need, cap]) => cap === 0 || need <= cap);
  return { total, edgeTotal, lines, fits, mem };
}

function printBudget(b, rows, slots) {
  const sizes = rows.map((r) => r.size);
  const onEdge = rows.filter((r) => r.edge);
  say(`списков ${rows.length}, размеры ${fmt(Math.min(...sizes))}..${fmt(Math.max(...sizes))}, всего записей ${fmt(b.total)}`);
  say(`коротких (срок ${SHORT_TTL_MIN} мин): ${rows.filter((r) => r.short).length}, записей в них ${fmt(rows.filter((r) => r.short).reduce((s, r) => s + r.size, 0))}`);
  say(`на краях: ${onEdge.length} из ${rows.length} + список замера (${fmt(b.edgeTotal)} записей) -- модуль держит до ${slots.max} наборов, занято стендом ${slots.used.length} (${slots.used.join(", ") || "никем"})`);
  say(`режет маршрут по ${rows.filter((r) => r.check).length} спискам: ${rows.filter((r) => r.check).map((r) => fmt(r.size) + (r.short ? "*" : "")).join(", ")}   (* короткий срок)`);
  say("");
  say("что".padEnd(28), "нужно".padStart(12), "есть".padStart(12), "  доля  примечание");

  for (const [what, need, cap, note] of b.lines) {
    const share = cap > 0 ? `${Math.round((100 * need) / cap)}%` : "--";
    say(what.padEnd(28), mb(need).padStart(12), (cap > 0 ? mb(cap) : "без лимита").padStart(12), share.padStart(6), "", note);
  }

  say("");
  say(b.fits ? "всё помещается" : "НЕ ПОМЕЩАЕТСЯ: прогон не начнётся");
}

/* --- наблюдение ----------------------------------------------------------- */

/** Кадры шины по видам: уведомления о пакетах, тики, события писателей, запросы снапшотов. */
function watchWire(nc) {
  const wire = { diff: { n: 0, bytes: 0, count: 0 }, tick: { n: 0, bytes: 0 }, event: { n: 0, bytes: 0 }, snapshot: { n: 0, bytes: 0 } };
  const sub = nc.subscribe("waf.sets.>");

  (async () => {
    for await (const m of sub) {
      if (!m.subject.startsWith(`waf.sets.${PREFIX}`)) continue;
      const len = m.data.length;

      if (m.subject.endsWith(".event")) {
        wire.event.n += 1; wire.event.bytes += len;
      } else if (m.subject.endsWith(".snapshot")) {
        wire.snapshot.n += 1; wire.snapshot.bytes += len;
      } else {
        try {
          const f = dec(m.data);
          if (f.op === "diff") { wire.diff.n += 1; wire.diff.bytes += len; wire.diff.count += f.count ?? 0; }
          else if (f.op === "tick") { wire.tick.n += 1; wire.tick.bytes += len; }
        } catch { /* не JSON -- не наш кадр */ }
      }
    }
  })();

  return { wire, stop: () => sub.unsubscribe() };
}

/** Память redis-internal раз в две секунды: свой пик по фазам. */
function watchMemory() {
  const samples = [];
  let alive = true;
  let phase = "start";

  (async () => {
    while (alive) {
      try {
        const m = await redisMemory();
        samples.push({ t: Date.now(), phase, used: m.used, rss: m.rss });
      } catch { /* redis-cli мог не успеть -- следующая выборка */ }
      await wait(2000);
    }
  })();

  return {
    samples,
    phase: (p) => { phase = p; },
    peak: (p) => Math.max(0, ...samples.filter((s) => p === undefined || s.phase === p).map((s) => s.used)),
    stop: () => { alive = false; },
  };
}

/**
 * Журнал края по наборам прогона с момента since. Отдельные пакеты край на
 * info не пишет -- только запросы и применение снапшотов; доставку пакетов
 * видно по отсутствию расхождений (тик сверяет хеш каждые 2 с).
 */
async function edgeLogs(container, since) {
  const { stdout, stderr } = await run("docker", ["logs", "--since", since, container], { windowsHide: true, maxBuffer: 512 * MiB });
  const per = new Map();
  const at = (name) => {
    if (!per.has(name)) per.set(name, { snapshots: 0, applied: 0, overlay: null, gone: 0, diverged: 0, noRoom: 0 });
    return per.get(name);
  };
  const all = { warns: 0, errors: 0 };

  for (const line of `${stdout}\n${stderr}`.split("\n")) {
    const m = /dataset "(e2e-ml-[a-z0-9]+)"/.exec(line);
    if (m === null) continue;
    const s = at(m[1]);

    if (line.includes("requesting a snapshot")) s.snapshots += 1;
    if (/applied snapshot/.test(line)) {
      s.applied += 1;
      const n = /(\d+) in overlay/.exec(line);
      if (n) s.overlay = Number(n[1]);
    }
    if (line.includes("package gone")) s.gone += 1;
    if (line.includes("diverged")) s.diverged += 1;
    if (line.includes("no room in the zone") || line.includes("did not fit")) s.noRoom += 1;
    if (line.includes("[warn]")) all.warns += 1;
    if (line.includes("[error]") || line.includes("[emerg]") || line.includes("[crit]")) all.errors += 1;
  }

  return { per, all };
}

function sumEdge(logs) {
  const out = { snapshots: 0, applied: 0, gone: 0, diverged: 0, noRoom: 0, warns: logs.all.warns, errors: logs.all.errors, sets: logs.per.size };
  for (const s of logs.per.values()) {
    for (const k of ["snapshots", "applied", "gone", "diverged", "noRoom"]) out[k] += s[k];
  }
  return out;
}

/* --- запись в keeper ------------------------------------------------------ */

/** Адреса без повторов: xorshift32 не повторяется за период, резервные сети пропускаются. */
function addresses(seed) {
  let x = (seed * 2654435761) >>> 0 || 1;

  return () => {
    for (;;) {
      x ^= x << 13; x >>>= 0;
      x ^= x >>> 17;
      x ^= x << 5; x >>>= 0;
      const a = x >>> 24;
      const b = (x >>> 16) & 255;
      if (a === 0 || a === 10 || a === 127 || a >= 224) continue;
      if ((a === 100 && (b & 0xc0) === 64) || (a === 169 && b === 254) || (a === 172 && (b & 0xf0) === 16) || (a === 192 && b === 168)) continue;
      return `${a}.${b}.${(x >>> 8) & 255}.${x & 255}`;
    }
  };
}

const take = (next, n) => Array.from({ length: n }, next);

async function event(nc, set, values, reason) {
  const frame = { v: 3, set, op: "add", values, origin: ORIGIN, reason };
  const until = Date.now() + 60_000;

  /* Свежий набор keeper монтирует не мгновенно после define: not_ready и unknown_set -- повтор. */
  for (;;) {
    try {
      const reply = dec((await nc.request(`waf.sets.${set}.event`, enc(frame), { timeout: 30_000 })).data);
      if (reply.ok || !["not_ready", "unknown_set"].includes(reply.error) || Date.now() > until) return reply;
    } catch (err) {
      if (Date.now() > until) return { ok: false, error: `nats: ${err.message}` };
    }
    await wait(500);
  }
}

async function pool(tasks, width) {
  const results = [];
  let next = 0;
  await Promise.all(Array.from({ length: width }, async () => {
    while (next < tasks.length) {
      const i = next++;
      results[i] = await tasks[i]();
    }
  }));
  return results;
}

/* --- фазы ----------------------------------------------------------------- */

async function fill(nc, rows, gens, samples) {
  const tasks = [];

  for (const r of rows) {
    for (let done = 0; done < r.size; done += BATCH) {
      const n = Math.min(BATCH, r.size - done);
      const first = done === 0;
      tasks.push(async () => {
        const values = take(gens.get(r.name), n);
        /* Первые адреса списка -- выборка для проверки блокировки на краях. */
        if (first) samples.set(r.name, values.slice(0, SAMPLE));
        return { name: r.name, n, reply: await event(nc, r.name, values, "fill") };
      });
    }
  }

  const t0 = Date.now();
  const res = await pool(tasks, PARALLEL);
  const ms = Date.now() - t0;
  const failed = res.filter((x) => !x.reply.ok);
  return { frames: res.length, records: res.reduce((s, x) => s + x.n, 0), ms, failed };
}

async function settle(rows, timeoutMs = 120_000) {
  const t0 = Date.now();
  for (;;) {
    const ks = await keeperSets();
    const short = rows.filter((r) => (ks.get(r.name)?.entries ?? -1) !== r.size);
    if (short.length === 0) return Date.now() - t0;
    if (Date.now() - t0 > timeoutMs) throw new Error(`keeper не дорос до плана: ${short.slice(0, 5).map((r) => r.name).join(", ")}…`);
    await wait(1000);
  }
}

async function overflow(nc, rows, gens, first) {
  const out = { batchFull: 0, batchOther: [], singleFull: 0, singleOther: [], refused: 0 };

  await pool(rows.map((r) => async () => {
    const extra = Math.max(1, Math.ceil(r.size * 0.1));
    const a = await event(nc, r.name, take(gens.get(r.name), extra), "overflow");
    if (!a.ok && a.error === "full") { out.batchFull += 1; out.refused += extra; } else out.batchOther.push({ name: r.name, reply: a });

    const b = await event(nc, r.name, take(gens.get(r.name), 1), "overflow-one");
    if (!b.ok && b.error === "full") { out.singleFull += 1; out.refused += 1; } else out.singleOther.push({ name: r.name, reply: b });
  }), PARALLEL);

  /* Повтор значений, которые уже лежат, лимита не двигает: обновляется срок. */
  const big = rows[rows.length - 1];
  out.refresh = await event(nc, big.name, first.get(big.name), "refresh");
  return out;
}

async function expiry(nc, rows, gens, timeoutMs) {
  const short = rows.filter((r) => r.short);
  const t0 = Date.now();
  let ks;

  for (;;) {
    ks = await keeperSets();
    const left = short.filter((r) => (ks.get(r.name)?.entries ?? 0) > 0);
    if (left.length === 0) break;
    if (Date.now() - t0 > timeoutMs) throw new Error(`не истекли за ${timeoutMs} мс: ${left.map((r) => r.name).join(", ")}`);
    await wait(2000);
  }

  const waited = Date.now() - t0;
  const expired = short.reduce((s, r) => s + (ks.get(r.name)?.expired ?? 0), 0);

  /*
   * Место освободилось: тот же лимит снова принимает, а сверх него -- снова
   * full. Доливается пачками, как налив: одним кадром десятки тысяч адресов
   * не пролезут в потолок сообщения NATS (1 МБ).
   */
  const probeRow = short[short.length - 1];
  let refill = { ok: true, frames: 0 };
  for (let done = 0; done < probeRow.size && refill.ok; done += BATCH) {
    const n = Math.min(BATCH, probeRow.size - done);
    refill = { ...(await event(nc, probeRow.name, take(gens.get(probeRow.name), n), "refill")), frames: refill.frames + 1 };
  }
  const over = await event(nc, probeRow.name, take(gens.get(probeRow.name), 1), "refill-over");

  return { lists: short.length, records: short.reduce((s, r) => s + r.size, 0), expired, waited, probe: probeRow.name, refill, over };
}

/** Сверка на краях: кто обязан резаться и кто обязан проходить. */
function verifyCases(rows, samples, strangers, { expiredShort }) {
  const cases = [];
  for (const r of rows.filter((x) => x.check)) {
    const want = expiredShort && r.short ? "pass" : "block";
    for (const ip of samples.get(r.name) ?? []) cases.push({ ip, want, list: r.name });
  }
  for (const ip of strangers) cases.push({ ip, want: "pass", list: "никакой" });
  return cases;
}

function printVerify(v, label) {
  let ok = true;
  for (const [edge, row] of Object.entries(v.per)) {
    say(`  ${edge}: режется ${row.block}, проходит ${row.pass}, коды ${JSON.stringify(row.statuses ?? {})}, мимо ожидания ${row.wrong.length}${row.wrong.length ? ` -- ${JSON.stringify(row.wrong.slice(0, 3))}` : ""}`);
    if (row.wrong.length > 0) ok = false;
  }
  say(`${label}: ${ok ? "всё как ждали" : "ЕСТЬ РАСХОЖДЕНИЯ"}`);
  return ok;
}

function printLatency(l) {
  const line = (s) => `p50 ${s.p50} мс, p90 ${s.p90}, p99 ${s.p99}, max ${s.max}${s.lost ? `, НЕ ЗАКРЫТО ${s.lost}` : ""}`;
  say(`раундов ${l.rounds} (пропущено ${l.skipped}, отказов keeper ${l.refused}); опрос края каждые ~${l.pollEveryMs} мс`);
  say(`ответ keeper писателю: ${line(l.ack)}`);
  for (const kind of ["addr", "net"]) {
    const k = l[kind];
    say(`${kind === "addr" ? "адрес /32" : "подсеть /24"}: закрыт на всех краях -- ${line(k.slowest)}`);
    for (const [edge, s] of Object.entries(k.per)) say(`  ${edge}: ${line(s)}`);
  }
}

/* --- снос ----------------------------------------------------------------- */

async function clean(ctx) {
  head("снос остатков");
  const del = async (path, kind) => {
    const rows = ((await ctx.get(path))[kind] ?? []).filter((d) => (d.name ?? "").startsWith(PREFIX) || (d.server_names ?? []).includes(SERVER));
    for (const d of rows) await ctx.del(`${path}/${d.uuid}`);
    say(`${kind}: снято ${rows.length}`);
  };
  await del("/servers", "servers");
  await del("/upstreams", "upstreams");
  await del("/datasets", "datasets");
  await publish(ctx, ["nginx"], say);
  await convergeSure(ctx, ["nginx"], { say });
}

/* --- прогон --------------------------------------------------------------- */

async function body(ctx, nc, rows, b, wire, memory, since, statsBefore, report, setLog) {
  const deny = ((await ctx.get("/deny-responses")).deny_responses ?? []).find((d) => d.name === "blocked")?.spec?.status ?? 403;
  const checked = rows.filter((r) => r.check);
  const probeBase = { edges: EDGE_HOSTS, host: SERVER, path: PROBE_PATH, deny };

  head("заведение");
  memory.phase("setup");
  const needs = {
    datasets: [
      ...rows.map((r) => ({
        name: r.name,
        description: `many-lists: ${r.size} записей, срок ${r.ttl}${r.edge ? ", на краях" : ""}`,
        kind: "list",
        type: "ip",
        active: true,
        ttl: r.ttl,
        in_nginx: r.edge,
        limit: r.size,
      })),
      { name: LAT.name, description: "many-lists: замер задержки", kind: "list", type: "ip", active: true, ttl: LAT.ttl, in_nginx: true, limit: LAT.size },
    ],
    upstreams: [APP],
    servers: [
      {
        name: SERVER,
        server_names: [SERVER],
        port: "http-8080",
        /* Адрес клиента -- из X-Forwarded-For: зонд называет его сам. */
        nginx: { realIpFrom: ["0.0.0.0/0", "::/0"], realIpHeader: "X-Forwarded-For" },
        waf: { enabled: true },
      },
    ],
    routes: [
      {
        server: SERVER,
        match: "prefix",
        path: "/ml/",
        position: 100,
        upstream: APP.name,
        waf: {
          /* Только локальный слой: блокирует край по зеркалу, инспекторов нет. */
          localChecks: [...checked, LAT].map((r) => ({ action: "block", dataset: r.name, response: "blocked", variable: "$binary_remote_addr" })),
          requestInspectors: "none",
          responseInspectors: "none",
          capture: ["request none"],
          preview: ["request none"],
          archive: ["request none"],
        },
      },
    ],
  };
  let made = 0;
  const { ledger } = await apply(ctx, needs, (m) => { if (++made % 25 === 0) say(`${m} (${made})`); });
  setLog(ledger);
  say(`наборов заведено: ${rows.length + 1}, на краях ${rows.filter((r) => r.edge).length + 1}; сервер ${SERVER}, маршрут /ml/ с ${checked.length + 1} проверками, отказ ${deny}`);

  head("издание краям");
  await publish(ctx, ["nginx"], say);
  await convergeSure(ctx, ["nginx"], { say, timeoutMs: 180_000 });

  head("налив");
  memory.phase("fill");
  const gens = new Map(rows.map((r) => [r.name, addresses(r.i + 1)]));
  const samples = new Map();
  /* Первые значения самого большого списка -- для проверки повтора на полном наборе. */
  const big = rows[rows.length - 1];
  const bigGen = gens.get(big.name);
  const firstBig = take(bigGen, 1000);
  const replay = firstBig.slice();
  gens.set(big.name, () => (replay.length > 0 ? replay.shift() : bigGen()));
  const filled = await fill(nc, rows, gens, samples);
  const filledAt = Date.now();
  say(`кадров ${fmt(filled.frames)}, записей ${fmt(filled.records)} за ${(filled.ms / 1000).toFixed(1)} с (${fmt(filled.records / (filled.ms / 1000))} в секунду)`);
  if (filled.failed.length > 0) say(`ОТКАЗЫ налива: ${filled.failed.length}, первый ${JSON.stringify(filled.failed[0])}`);
  const settleMs = await settle(rows);
  say(`keeper держит план целиком через ${(settleMs / 1000).toFixed(1)} с после налива`);
  await wait(5000);

  head("хранение");
  const ks = await keeperSets();
  const mem = await redisMemory();
  const keys = await census();
  const sampleRows = [rows[0], rows[25], rows[50], rows[75], rows[rows.length - 1]];
  const perKey = [];
  for (const r of sampleRows) {
    const m = await keyMemory(r.name);
    perKey.push({ name: r.name, size: r.size, ...m, perRecord: m.total / r.size });
  }
  const statsFilled = await dockerStats();
  say(`redis-internal: ${mb(mem.used)} (было ${mb(b.mem.used)}), RSS ${mb(mem.rss)}, пик налива ${mb(memory.peak("fill"))}, потолок ${mb(mem.max)}`);
  say(`ключи прогона: составов ${Math.round(keys.sets / 3)} (по 3 ключа), пакетов журнала ${fmt(keys.diffs)}, снапшотов ${fmt(keys.snaps)}`);
  say("байт на набор в Redis:");
  for (const k of perKey) say(`  ${k.name} ${fmt(k.size).padStart(8)} зап.: состав ${fmt(k.set)}, повод ${fmt(k.why)}, метка ${fmt(k.meta)} -> ${k.perRecord.toFixed(0)} Б/запись`);
  for (const c of ["waf-keeper-1", "waf-redis-internal-1", ...EDGES]) {
    say(`  ${c}: ${fmt(statsBefore[c]?.mem)} -> ${fmt(statsFilled[c]?.mem)} МиБ`);
  }

  head("передача");
  const tot = { writes: 0, diffs: 0, snapshots: 0, packs: 0, storeErr: 0, storeMsMax: 0 };
  for (const s of ks.values()) {
    tot.writes += s.writes ?? 0; tot.diffs += s.diffs ?? 0; tot.snapshots += s.snapshots ?? 0; tot.packs += s.packs ?? 0;
    tot.storeErr += s.store_err ?? 0; tot.storeMsMax = Math.max(tot.storeMsMax, s.store_ms ?? 0);
  }
  const w = wire.wire;
  say(`keeper: записей ${fmt(tot.writes)}, пакетов ${fmt(tot.diffs)}, снапшотов выдано ${fmt(tot.snapshots)}, упаковок ${fmt(tot.packs)}, ошибок склада ${tot.storeErr}, склад до ${tot.storeMsMax} мс`);
  say(`шина waf.sets.e2e-ml-*: события ${fmt(w.event.n)} кадров / ${mb(w.event.bytes)}; уведомления о пакетах ${fmt(w.diff.n)} / ${mb(w.diff.bytes)} на ${fmt(w.diff.count)} изменений; тики ${fmt(w.tick.n)} / ${mb(w.tick.bytes)}; запросы снапшотов ${fmt(w.snapshot.n)}`);
  say(`состав по шине не едет: на ${fmt(w.diff.count)} изменений ушло ${mb(w.diff.bytes)} уведомлений, сами записи -- в Redis, ${PER.wire} Б на адрес (~${mb(w.diff.count * PER.wire)})`);
  const edges = {};
  for (const e of EDGES) {
    edges[e] = sumEdge(await edgeLogs(e, since));
    const x = edges[e];
    say(`  ${e}: наборов в журнале ${x.sets}, снапшотов запрошено ${x.snapshots}, применено ${x.applied}, пакет пропал ${x.gone}, расхождений ${x.diverged}, нет места ${x.noRoom}, warn ${x.warns}, error ${x.errors}`);
  }

  head("переполнение");
  memory.phase("overflow");
  const before = await keeperSets();
  const over = await overflow(nc, rows, gens, new Map([[big.name, firstBig]]));
  const after = await keeperSets();
  const grown = rows.filter((r) => (after.get(r.name)?.entries ?? 0) !== (before.get(r.name)?.entries ?? 0));
  say(`пачка сверх лимита: full у ${over.batchFull} из ${rows.length}; одна запись сверх: full у ${over.singleFull} из ${rows.length}; отвергнуто записей ${fmt(over.refused)}`);
  if (over.batchOther.length + over.singleOther.length > 0) say(`НЕ full: ${JSON.stringify([...over.batchOther, ...over.singleOther].slice(0, 3))}`);
  say(`повтор 1000 уже лежащих значений в полный ${big.name}: ${JSON.stringify(over.refresh)}`);
  say(`размер наборов после попыток: ${grown.length === 0 ? "не изменился ни у одного" : `ИЗМЕНИЛСЯ у ${grown.map((r) => r.name).join(", ")}`}`);
  say(`отказы у keeper: ${fmt([...after.values()].reduce((s, x) => s + (x.rejects ?? 0), 0))}`);

  head("блокировка на краях");
  const sinceFill = Date.now() - filledAt;
  say(`с конца налива ${(sinceFill / 1000).toFixed(0)} с: короткие списки (${SHORT_TTL_MIN} мин) ещё обязаны резаться`);
  const strangers = take(addresses(99_999), SAMPLE);
  const verified = await probe({ ...probeBase, mode: "verify", cases: verifyCases(rows, samples, strangers, { expiredShort: false }) });
  say(`адресов из ${checked.length} списков по ${SAMPLE} -- обязаны резаться; ${SAMPLE} посторонних -- обязаны проходить; ${verified.cases} проверок на каждом крае`);
  const blockOk = printVerify(verified, "блокировка");

  head("задержка: keeper -> блокировка на модуле");
  const lat = await probe({ ...probeBase, mode: "latency", nats: "nats://nats:4222", set: LAT.name, rounds: ROUNDS, ttl: 600, timeoutMs: 5000 });
  printLatency(lat);

  head("истечение");
  memory.phase("expiry");
  const memPre = await redisMemory();
  const exp = await expiry(nc, rows, gens, (SHORT_TTL_MIN * 60 + 180) * 1000);
  await wait(5000);
  const memPost = await redisMemory();
  say(`короткие списки: ${exp.lists}, записей ${fmt(exp.records)}, keeper вымел ${fmt(exp.expired)} (EXPIRED) -- пусты через ${(exp.waited / 1000).toFixed(0)} с ожидания`);
  say(`redis-internal: ${mb(memPre.used)} -> ${mb(memPost.used)}`);
  say(`освободившийся ${exp.probe}: долив до лимита ${JSON.stringify(exp.refill)}, ещё одна сверх -- ${JSON.stringify(exp.over)}`);
  const verifiedExp = await probe({ ...probeBase, mode: "verify", cases: verifyCases(rows, samples, strangers, { expiredShort: true }) });
  say("после истечения: адреса коротких списков обязаны проходить, часовых -- по-прежнему резаться");
  const expOk = printVerify(verifiedExp, "после истечения");
  await wait(5000);
  const edgesExp = {};
  for (const e of EDGES) edgesExp[e] = sumEdge(await edgeLogs(e, since));
  say(`края после истечения: расхождений ${EDGES.map((e) => edgesExp[e].diverged).join("/")}, нет места ${EDGES.map((e) => edgesExp[e].noRoom).join("/")}, пакет пропал ${EDGES.map((e) => edgesExp[e].gone).join("/")}`);

  Object.assign(report, {
    fill: { frames: filled.frames, records: filled.records, ms: filled.ms, failed: filled.failed.length, settleMs },
    storage: { redis: mem, keys, perKey, containers: { before: statsBefore, filled: statsFilled }, peakFill: memory.peak("fill") },
    transport: { keeper: tot, wire: w, edges },
    blocking: { ...verified, sinceFillMs: sinceFill },
    latency: lat,
    overflow: { ...over, grown: grown.map((r) => r.name) },
    expiry: { ...exp, memPre, memPost, edges: edgesExp, verify: verifiedExp },
  });

  const latOk = ["addr", "net"].every((k) => lat[k].slowest.lost === 0) && lat.refused === 0;

  return filled.failed.length === 0 && blockOk && latOk && expOk &&
    over.batchFull === rows.length && over.singleFull === rows.length &&
    over.refresh.ok === true && grown.length === 0 && exp.refill.ok === true && exp.over.error === "full" &&
    EDGES.every((e) => edgesExp[e].diverged === 0 && edgesExp[e].noRoom === 0);
}

async function main() {
  const ctx = await connect();

  if (flag("--clean")) {
    await clean(ctx);
    return 0;
  }

  const slots = { max: await moduleDatasetMax(), used: await declaredOnEdges(ctx) };
  /* Одно место -- списку замера задержки. */
  const free = Math.max(0, slots.max - slots.used.length - 1);
  const edgeCount = Math.min(num("--edge", free), free, LISTS);
  const rows = plan(edgeCount);

  head("память до прогона");
  const b = await budget(ctx, rows);
  printBudget(b, rows, slots);

  if (flag("--plan")) return b.fits ? 0 : 1;
  if (!b.fits && !flag("--force")) return 1;

  const report = {
    started: new Date().toISOString(),
    plan: { lists: rows.length, total: b.total, min: MIN, max: MAX, shortTtlMin: SHORT_TTL_MIN, edge: edgeCount, edgeTotal: b.edgeTotal, moduleMax: slots.max, rounds: ROUNDS },
    budget: b.lines,
  };
  const nc = await natsConnect({ servers: NATS_URL, name: "e2e-many-lists" });
  const wire = watchWire(nc);
  const memory = watchMemory();
  const since = new Date().toISOString();
  const statsBefore = await dockerStats();
  let log = null;
  let ok = false;
  let failure = null;

  try {
    ok = await body(ctx, nc, rows, b, wire, memory, since, statsBefore, report, (l) => { log = l; });
  } catch (err) {
    failure = err;
    head(`ПРОГОН СОРВАЛСЯ: ${err.message}`);
    report.error = err.message;
  }

  wire.stop();

  if (log !== null && !flag("--keep")) {
    try {
      head("снос");
      memory.phase("teardown");
      const left = await log.unwind(() => {});
      say(`снято записей журнала: ${log.rows.length === 0 ? "все" : "не все"}${left.length ? `, НЕ СНЯТО ${left.length}` : ""}`);
      await publish(ctx, ["nginx"], say);
      await convergeSure(ctx, ["nginx"], { say, timeoutMs: 180_000 });
      await wait(3000);
      const keys = await census();
      const mem = await redisMemory();
      say(`ключей прогона в Redis: составов ${keys.sets}, пакетов ${keys.diffs}, снапшотов ${keys.snaps}; redis-internal ${mb(mem.used)}`);
      report.teardown = { keys, redis: mem };
    } catch (err) {
      head(`СНОС СОРВАЛСЯ: ${err.message} -- добить: node tests/keeper/many-lists.mjs --clean`);
      report.teardownError = err.message;
      ok = false;
    }
  }

  memory.stop();
  report.memorySamples = memory.samples;
  report.ok = ok && failure === null;
  await nc.drain();
  await mkdir(REPORTS, { recursive: true });
  const file = join(REPORTS, `many-lists-${report.started.replace(/[:.]/g, "-")}.json`);
  await writeFile(file, JSON.stringify(report, null, 2));
  head(`итог: ${report.ok ? "прошёл" : "НЕ ПРОШЁЛ"}; отчёт ${file}`);

  return report.ok ? 0 : 1;
}

main().then((code) => process.exit(code), (err) => {
  console.error(err);
  process.exit(2);
});
