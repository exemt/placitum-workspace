#!/usr/bin/env node
/*
 * Зонд блокировки изнутри сети стенда: один процесс, одни часы. Пишет запись
 * в keeper и сам опрашивает края, пока модуль не начнёт отказывать, -- так
 * задержка «отправил в keeper -> край режет» меряется без расхождения часов
 * хоста и контейнеров. Запускает его tests/keeper/many-lists.mjs:
 *
 *     docker run --rm --network waf_default -v <repo>:/w node:22-alpine \
 *       node /w/tests/keeper/block-probe.mjs '<json>'
 *
 * Вход -- JSON в argv[2]:
 *
 *   { mode: "verify", edges, host, path, deny,
 *     cases: [{ ip, want: "block" | "pass", list }] }
 *     каждый адрес на каждом крае: отказ `deny` там, где ждали блок, и не
 *     отказ там, где ждали проход;
 *
 *   { mode: "latency", edges, host, path, deny, nats, set, rounds, ttl, timeoutMs }
 *     rounds раз: свежий адрес или его /24 (через раз) пишется в keeper, и все
 *     края опрашиваются вплотную, без пауз, до первого отказа. t0 -- миг перед
 *     отправкой события; ack -- ответ keeper; edge -- первый отказ края.
 *
 * Выход -- одна строка JSON в stdout.
 *
 * Край режет по `$binary_remote_addr`, а сервер прогона берёт адрес из
 * X-Forwarded-For (realip), поэтому адрес клиента задаётся заголовком.
 */

import { createRequire } from "node:module";
import http from "node:http";
import { performance } from "node:perf_hooks";

const require = createRequire("/w/controller/package.json");
const { connect } = require("nats");

const args = JSON.parse(process.argv[2] ?? "{}");
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const dec = (b) => JSON.parse(new TextDecoder().decode(b));

/*
 * Не fetch: undici молча выбрасывает заголовок Host (запрещённый заголовок
 * Fetch), и запрос уходит на сервер по умолчанию -- витрину, которая на любой
 * адрес отвечает 404. node:http Host передаёт; соединения живут, чтобы опрос
 * края шёл без рукопожатий TCP.
 */
const agent = new http.Agent({ keepAlive: true, maxSockets: 64 });

function status(edge, ip) {
  const [hostname, port] = edge.split(":");

  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname, port: Number(port ?? 80), path: args.path, method: "GET", agent, headers: { Host: args.host, "X-Forwarded-For": ip } },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      },
    );
    req.setTimeout(5000, () => req.destroy(new Error(`${edge}: no answer in 5 s`)));
    req.on("error", reject);
    req.end();
  });
}

/* --- сверка --------------------------------------------------------------- */

async function verify() {
  const per = {};

  for (const edge of args.edges) {
    const row = { block: 0, pass: 0, wrong: [], statuses: {} };

    for (const c of args.cases) {
      const s = await status(edge, c.ip);
      const blocked = s === args.deny;
      row.statuses[s] = (row.statuses[s] ?? 0) + 1;

      if (blocked === (c.want === "block")) {
        row[c.want] += 1;
      } else {
        row.wrong.push({ ip: c.ip, list: c.list, want: c.want, status: s });
      }
    }

    row.wrong = row.wrong.slice(0, 10);
    per[edge] = row;
  }

  return { mode: "verify", cases: args.cases.length, per };
}

/* --- задержка ------------------------------------------------------------- */

function fresh(seed) {
  let x = (seed * 2654435761) >>> 0 || 1;

  return () => {
    for (;;) {
      x ^= x << 13; x >>>= 0;
      x ^= x >>> 17;
      x ^= x << 5; x >>>= 0;
      const a = x >>> 24;
      const b = (x >>> 16) & 255;
      if (a < 11 || a === 127 || a >= 224) continue;
      if ((a === 100 && (b & 0xc0) === 64) || (a === 169 && b === 254) || (a === 172 && (b & 0xf0) === 16) || (a === 192 && b === 168)) continue;
      return [a, b, (x >>> 8) & 255, x & 255];
    }
  };
}

/** Опрос края вплотную до отказа: миг первого отказа от t0 и число опросов. */
async function until(edge, ip, t0, timeoutMs) {
  let polls = 0;

  for (;;) {
    const s = await status(edge, ip);
    polls += 1;
    const t = performance.now() - t0;

    if (s === args.deny) return { ms: t, polls };
    if (t > timeoutMs) return { ms: null, polls };
  }
}

const pct = (xs, p) => {
  const v = xs.filter((x) => x !== null).sort((a, b) => a - b);
  if (v.length === 0) return null;
  return Math.round(v[Math.min(v.length - 1, Math.floor((p / 100) * v.length))] * 10) / 10;
};

const summary = (xs) => ({
  n: xs.length,
  lost: xs.filter((x) => x === null).length,
  p50: pct(xs, 50),
  p90: pct(xs, 90),
  p99: pct(xs, 99),
  max: pct(xs, 100),
});

async function latency() {
  const nc = await connect({ servers: args.nats, name: "e2e-block-probe" });
  const next = fresh(args.seed ?? 7);
  const timeoutMs = args.timeoutMs ?? 5000;
  const rows = [];

  /* Прогрев: соединения к краям и к keeper, первый запрос не в зачёт. */
  for (const edge of args.edges) await status(edge, "198.51.100.1");

  for (let r = 0; r < args.rounds; r += 1) {
    const kind = r % 2 === 0 ? "addr" : "net";
    const [a, b, c, d] = next();
    const value = kind === "addr" ? `${a}.${b}.${c}.${d}` : `${a}.${b}.${c}.0/24`;
    const ip = kind === "addr" ? value : `${a}.${b}.${c}.${(d % 250) + 2}`;

    /* Адрес обязан проходить до записи: иначе замер ничего не значит. */
    const before = await Promise.all(args.edges.map((e) => status(e, ip)));
    if (before.some((s) => s === args.deny)) {
      rows.push({ kind, value, skipped: "blocked before write" });
      continue;
    }

    const t0 = performance.now();
    const frame = { v: 3, set: args.set, op: "add", value, ttl: args.ttl, origin: "e2e-block-probe", reason: "latency" };
    const ack = nc.request(`waf.sets.${args.set}.event`, enc(frame), { timeout: 10_000 })
      .then((m) => ({ ms: performance.now() - t0, reply: dec(m.data) }));
    const edges = await Promise.all(args.edges.map((e) => until(e, ip, t0, timeoutMs)));
    const acked = await ack;

    rows.push({ kind, value, ack: acked.ms, ok: acked.reply.ok === true, error: acked.reply.error, edges: edges.map((x) => x.ms), polls: edges.map((x) => x.polls) });
  }

  await nc.drain();

  const done = rows.filter((x) => x.skipped === undefined);
  const out = { mode: "latency", rounds: rows.length, skipped: rows.length - done.length, refused: done.filter((x) => !x.ok).length, ack: summary(done.map((x) => x.ack)) };

  for (const kind of ["addr", "net"]) {
    const k = done.filter((x) => x.kind === kind);
    out[kind] = {
      all: summary(k.flatMap((x) => x.edges)),
      /* Последний край: когда адрес закрыт везде. */
      slowest: summary(k.map((x) => (x.edges.includes(null) ? null : Math.max(...x.edges)))),
      per: Object.fromEntries(args.edges.map((e, i) => [e, summary(k.map((x) => x.edges[i]))])),
    };
  }

  /* Разрешение замера: сколько опросов край выдерживал за миллисекунду. */
  const polls = done.flatMap((x) => x.polls);
  const ms = done.flatMap((x) => x.edges).filter((x) => x !== null);
  out.pollEveryMs = ms.length > 0 ? Math.round((ms.reduce((s, x) => s + x, 0) / polls.reduce((s, x) => s + x, 0)) * 100) / 100 : null;
  out.samples = rows.slice(0, 6);
  return out;
}

const result = args.mode === "latency" ? await latency() : await verify();
agent.destroy();
process.stdout.write(`${JSON.stringify(result)}\n`);
