/*
 * Кейс ip-ban: пробы реакции и наблюдение за активными списками.
 *
 * Здесь то, чего нет у остальных кейсов: измерение «сколько времени проходит
 * от запроса, который поставил бан, до отказа этому же адресу» и взгляд сразу
 * на восемь активных списков -- их размер у keeper, их зеркала у копий
 * инспектора адреса и память тех, кто их держит.
 *
 * Реакция меряется через край, а не по счётчикам: важно не «keeper ответил», а
 * «клиент получил отказ». Первый отказ и отказ устойчивый -- разные величины:
 * копий инспектора три, запрос попадает в любую, и пока запись не доехала до
 * всех, отказ моргает.
 */

import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { probe } from "./stand.mjs";
import { KEEPER, dockerStats } from "./hot.mjs";

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
/* Клиент шины -- из зависимостей контроллера: своего package.json у тестов нет. */
const require = createRequire(join(ROOT, "controller", "package.json"));
const { connect: natsConnect } = require("nats");

const NATS = process.env.WAF_NATS ?? "nats://127.0.0.1:4222";
const ORIGIN = "e2e-ip-ban";

const enc = (o) => new TextEncoder().encode(JSON.stringify(o));
const dec = (b) => JSON.parse(new TextDecoder().decode(b));

/** Молчащие копии в снимке присутствия не ждём: они уже никогда не догонят. */
const ALIVE_MS = 15_000;

/** Контейнеры, за памятью которых смотрит кейс. */
export const BAN_WATCHED = [
  ["keeper", /^waf-keeper-/],
  ["redis-int", /^waf-redis-internal-1$/],
  ["ip", /^waf-inspector-ip-/],
  ["geo", /^waf-geo-/],
  ["край", /^waf-edge-/],
  ["nats", /^waf-nats-1$/],
  ["ctl", /^waf-controller-/],
];

/* --- keeper ------------------------------------------------------------- */

/**
 * Сводка по всем наборам разом: `/sets` отдаёт счётчики, `/sets/<имя>` повёз бы
 * и состав. Кейс смотрит за восемью списками, и восемь запросов на такт
 * наблюдения -- это восемь лишних поводов не успеть.
 */
export async function keeperSets(names) {
  const res = await fetch(`${KEEPER}/sets`);

  if (!res.ok) {
    throw new Error(`keeper ${res.status} на /sets`);
  }

  const rows = await res.json();
  const want = new Set(names);
  const out = {};

  for (const row of Array.isArray(rows) ? rows : []) {
    if (want.has(row.name)) {
      out[row.name] = row;
    }
  }

  return out;
}

/** Сумма поля по всем наблюдаемым спискам. */
const sum = (rows, field) => Object.values(rows).reduce((s, r) => s + (Number(r[field]) || 0), 0);

/* --- синтетические системы для проб ------------------------------------- */

/**
 * Кодеру нужно знать адрес пробы, иначе `net` и `asn` не пишут ничего: анонса
 * нет -- записи нет. Брать настоящий адрес нельзя: под нагрузкой случайный
 * поток сам забанит его систему, и проба будет мерить чужой бан.
 *
 * Поэтому к каталогу кодера на время прогона дописываются свои системы в
 * бенчмарочных 198.18.0.0/15 и 198.19.0.0/16 -- генератор таких адресов не
 * выдаёт (`reserved()` в wrk/script.lua), и попасть в них может только проба:
 *
 *   64501..64505 -- по одному /24: проба `net` банит свой анонс;
 *   64511..64515 -- по одному /24: проба `asn` банит систему из одного анонса;
 *   64599        -- 250 анонсов: та же проба, но пачкой в 250 записей.
 *
 * Формат строки -- как у выгрузки из базы: `asn<TAB>тип<TAB>префикс<TAB>имя`.
 */
export function probeGeo() {
  const rows = [];
  const add = (asn, prefix) => rows.push(`${asn}\tv4\t${prefix}\tE2E ip-ban probe`);

  for (let i = 0; i < 5; i += 1) {
    add(64501 + i, `198.18.${20 + i}.0/24`);
    add(64511 + i, `198.18.${30 + i}.0/24`);
  }

  for (let i = 0; i < 250; i += 1) {
    add(64599, `198.19.${i}.0/24`);
  }

  return `${rows.join("\n")}\n`;
}

/* --- загрузка списков --------------------------------------------------- */

/** Пачка записей в keeper с ответом: свежий набор монтируется не мгновенно. */
async function addMany(nc, set, values) {
  const frame = { v: 3, set, op: "add", values, origin: ORIGIN, reason: "PRELOAD" };
  const until = Date.now() + 60_000;

  for (;;) {
    try {
      const reply = dec((await nc.request(`waf.sets.${set}.event`, enc(frame), { timeout: 30_000 })).data);

      if (reply.ok || !["not_ready", "unknown_set"].includes(reply.error) || Date.now() > until) {
        return reply;
      }
    } catch (err) {
      if (Date.now() > until) {
        return { ok: false, error: `nats: ${err.message}` };
      }
    }

    await wait(500);
  }
}

/**
 * Загрузка активных списков -- прямо в keeper, пачками.
 *
 * Не через контроллер: `POST /datasets/<uuid>/addresses` у активного набора
 * шлёт keeper по одному событию на адрес и ждёт ответа на каждое -- 11-12 мс на
 * запись, восемь списков по двадцать тысяч наливались бы полчаса. Живой
 * писатель так не делает: инспектор шлёт `values[]` одним кадром, и прогон
 * повторяет именно его путь.
 */
export async function fillLive(ban, gen, say) {
  const nc = await natsConnect({ servers: NATS, name: ORIGIN });
  const t0 = Date.now();
  let total = 0;

  try {
    for (const [i, name] of ban.live.entries()) {
      const values = gen(i, ban.loaded);

      for (let off = 0; off < values.length; off += 5000) {
        const part = values.slice(off, off + 5000);
        const reply = await addMany(nc, name, part);

        if (!reply.ok) {
          throw new Error(`налив ${name}: keeper отказал -- ${reply.error}`);
        }

        total += part.length;
      }
    }
  } finally {
    await nc.drain();
  }

  const ms = Date.now() - t0;

  say(`загружено ${total} записей в ${ban.live.length} активных списков за ${ms} мс (${Math.round((total * 1000) / ms)} записей/с)`);

  return { total, ms };
}

/* --- пробы реакции ------------------------------------------------------ */

/** Одна проба через край: код, вердикт и кто отказал. */
async function hit(tr, path, ip) {
  const r = await probe(path, { host: tr.host, headers: { "X-Forwarded-For": ip } });

  return {
    status: r.status,
    verdict: r.verdict,
    fail: r.fail,
    denied: Object.entries(r.inspectors).filter(([, v]) => v.startsWith("deny")).map(([k]) => k),
  };
}

/**
 * Одна проба реакции: запрос, который ставит бан, и опрос до отказа.
 *
 * Первый запрос обязан пройти -- иначе адрес уже забанен (своим прошлым
 * раундом или чужой записью нагрузки), и мерить нечего. Дальше край
 * опрашивается без пауз: разрешение измерения -- это время одного запроса,
 * около миллисекунды на покое и больше под нагрузкой.
 *
 * Опрос до отказа сам продолжает писать: каждый прошедший запрос -- ещё одна
 * запись того же адреса. Это не мешает: первая запись уже в пути, а последующие
 * лишь обновляют срок.
 */
export async function reaction(tr, ep, ip, deny, { timeoutMs, stable }) {
  const first = await hit(tr, ep.path, ip);

  if (first.status !== 200) {
    return { ip, dirty: `${first.status} ${first.verdict}${first.fail ? ` fail=${first.fail}` : ""}` };
  }

  const t0 = Date.now();
  const row = { ip, firstMs: null, stableMs: null, polls: 0, denies: 0, by: null };
  let run = 0;

  while (Date.now() - t0 < timeoutMs) {
    const r = await hit(tr, ep.path, ip);

    row.polls += 1;

    if (r.status === deny) {
      row.denies += 1;
      run += 1;

      if (row.firstMs === null) {
        row.firstMs = Date.now() - t0;
        row.by = r.denied.join(",") || r.verdict;
      }

      if (run >= stable) {
        row.stableMs = Date.now() - t0;
        break;
      }
    } else {
      run = 0;
    }
  }

  return row;
}

/**
 * Раунды проб по всем трём эндпоинтам. Между раундами пауза: записи живут пять
 * секунд, и следующий раунд начинается с чистого адреса, а не с хвоста
 * прошлого. Адрес берётся из своего кольца -- у `addr` они разные, у `net` и
 * `asn` повторяются, поэтому между раундами и нужен разрыв.
 */
export async function reactions(tr, ban, deny, phase, say) {
  const out = [];

  for (let round = 0; round < ban.rounds; round += 1) {
    for (const ep of ban.endpoints) {
      const pool = ban.probes[ep.id];
      let row = null;
      let ip = null;

      /*
       * Адрес обязан быть чистым: под нагрузкой его анонс мог закрыть чужой
       * бан. Перебираем кольцо, начиная со своего места, -- сдаёмся, когда
       * закрыты все.
       */
      for (let k = 0; k < pool.length; k += 1) {
        ip = pool[(round + k) % pool.length];
        row = await reaction(tr, ep, ip, deny, ban);

        if (row.dirty === undefined) {
          break;
        }
      }

      out.push({ phase, endpoint: ep.id, round: round + 1, ...row });

      if (row.dirty !== undefined) {
        say(`${phase} ${ep.id}: все адреса кольца уже закрыты (${row.dirty}) -- проба пропущена`);
      } else {
        say(
          `${phase} ${ep.id} ${ip}: первый отказ ${row.firstMs === null ? "не пришёл" : `${row.firstMs} мс`}` +
          `, устойчиво ${row.stableMs === null ? "нет" : `${row.stableMs} мс`}` +
          ` (проб ${row.polls}, отказов ${row.denies}${row.by ? `, отказал ${row.by}` : ""})`,
        );
      }
    }

    if (round + 1 < ban.rounds) {
      await wait(ban.gapMs);
    }
  }

  return out;
}

/* --- наблюдение --------------------------------------------------------- */

/**
 * Такт наблюдения: счётчики восьми списков у keeper, их зеркала у копий
 * инспектора адреса, темп краёв и -- не на каждом такте -- память.
 */
export async function banSample(ctx, ban, uuids, withStats) {
  const [keeper, fleet, stats] = await Promise.all([
    keeperSets(ban.live).catch((err) => ({ error: err.message })),
    ctx.api("GET", "/api/fleet"),
    withStats ? dockerStats().catch(() => ({})) : Promise.resolve(null),
  ]);
  const mirrors = (fleet.inspectors ?? [])
    .filter((r) => r.name === "ip" && (r.age_ms ?? 0) < ALIVE_MS)
    .map((r) => {
      const live = r.work?.live ?? r.live ?? [];
      let size = 0;
      let seen = 0;

      for (const row of live) {
        if (uuids.has(row.uuid)) {
          size += (row.base ?? 0) + (row.live ?? 0);
          seen += 1;
        }
      }

      return { host: r.hostname, size, lists: seen };
    });
  const agents = (fleet.agents ?? []).filter((a) => (a.age_ms ?? 0) < ALIVE_MS);
  const mem = {};

  if (stats !== null) {
    for (const [label, re] of BAN_WATCHED) {
      const rows = Object.entries(stats).filter(([name]) => re.test(name)).sort(([a], [b]) => a.localeCompare(b));

      if (rows.length > 0) {
        mem[label] = rows.map(([, v]) => v.mem);
      }
    }
  }

  return {
    at: Date.now(),
    keeper,
    mirrors,
    rps: agents.reduce((s, a) => s + (a.rps ?? 0), 0),
    fivexx: agents.reduce((s, a) => s + (a.codes?.["5xx"] ?? 0), 0),
    mem,
  };
}

const fmt = (n) => (n === null || n === undefined ? "--" : String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, " "));

export function banLine(s, t0) {
  const t = Math.round((s.at - t0) / 1000);
  const k = s.keeper;
  const kp = k.error !== undefined
    ? `keeper: ${k.error}`
    : `списки ${fmt(sum(k, "entries"))} зап ${fmt(sum(k, "writes"))} отк ${fmt(sum(k, "rejects"))} ` +
      `истекло ${fmt(sum(k, "expired"))} снап ${fmt(sum(k, "snapshots"))} склад ${Math.max(0, ...Object.values(k).map((r) => r.store_ms ?? 0))} мс`;
  const m = s.mirrors.map((r) => fmt(r.size)).join(" / ");
  const mem = Object.entries(s.mem).map(([l, v]) => `${l} ${v.map((x) => Math.round(x)).join("/")}`).join(" ");

  return (
    `+${String(t).padStart(4)}с  ${kp} | зеркала ip ${m || "--"} | rps ${fmt(s.rps)}` +
    `${s.fivexx ? ` 5xx ${s.fivexx}` : ""}${mem ? ` | МиБ ${mem}` : ""}`
  );
}

/** Наблюдение в соседней задаче: сорвавшийся такт -- строка, а не падение. */
export function banWatch(ctx, ban, uuids, t0, say) {
  const samples = [];
  let stop = false;
  let tick = 0;

  const done = (async () => {
    while (!stop) {
      try {
        const s = await banSample(ctx, ban, uuids, tick % 2 === 0);

        samples.push(s);
        say(banLine(s, t0));
      } catch (err) {
        say(`наблюдение: ${err.message}`);
      }

      tick += 1;
      const until = Date.now() + ban.sampleMs;

      while (!stop && Date.now() < until) {
        await wait(250);
      }
    }

    return samples;
  })();

  return { stop: () => { stop = true; }, done };
}

/* --- отчёт -------------------------------------------------------------- */

function quant(rows, field, q) {
  const vals = rows.map((r) => r[field]).filter((v) => typeof v === "number").sort((a, b) => a - b);

  if (vals.length === 0) {
    return null;
  }

  return vals[Math.min(vals.length - 1, Math.floor(q * vals.length))];
}

export function reportBan(ban, out) {
  const { phases, samples, base, loaded, deny } = out;
  const bad = [];

  console.log("\n  реакция: от запроса, поставившего бан, до отказа тому же адресу");
  console.log("  " + "-".repeat(96));
  console.log("                          первый отказ, мс       устойчиво (подряд " +
    String(ban.stable).padStart(2) + "), мс");
  console.log("  эндпоинт  фаза       проб   p50   p99   макс      p50   p99   макс   пропущено");

  for (const [phase, rows] of Object.entries(phases)) {
    for (const ep of ban.endpoints) {
      const mine = rows.filter((r) => r.endpoint === ep.id);
      const good = mine.filter((r) => r.dirty === undefined);
      const skipped = mine.length - good.length;
      const lost = good.filter((r) => r.firstMs === null).length;

      console.log(
        `  ${ep.id.padEnd(9)} ${phase.padEnd(10)} ${String(good.length).padStart(4)} ` +
        `${String(quant(good, "firstMs", 0.5) ?? "--").padStart(5)} ${String(quant(good, "firstMs", 0.99) ?? "--").padStart(5)} ` +
        `${String(Math.max(0, ...good.map((r) => r.firstMs ?? 0)) || "--").padStart(6)}   ` +
        `${String(quant(good, "stableMs", 0.5) ?? "--").padStart(6)} ${String(quant(good, "stableMs", 0.99) ?? "--").padStart(5)} ` +
        `${String(Math.max(0, ...good.map((r) => r.stableMs ?? 0)) || "--").padStart(6)} ` +
        `${String(skipped).padStart(11)}`,
      );

      if (good.length > 0 && lost === good.length) {
        bad.push(`${phase} ${ep.id}: бан не доехал ни разу за ${Math.round(ban.timeoutMs / 1000)} с`);
      }
    }
  }

  const last = samples.at(-1);
  const k = last?.keeper?.error === undefined ? last.keeper : null;

  console.log("\n  списки");
  console.log("  " + "-".repeat(96));

  if (k !== null) {
    const peakEntries = Math.max(...samples.filter((s) => s.keeper.error === undefined).map((s) => sum(s.keeper, "entries")));

    console.log(
      `  записей всего: загружено ${fmt(loaded)}, на пике ${fmt(peakEntries)}, в конце ${fmt(sum(k, "entries"))}; ` +
      `keeper принял ${fmt(sum(k, "writes"))}, отказал ${fmt(sum(k, "rejects"))}, вымел по сроку ${fmt(sum(k, "expired"))}`,
    );

    for (const name of ban.live) {
      const row = k[name];

      if (row === undefined) {
        console.log(`  ${name}: у keeper такого набора нет`);
        continue;
      }

      const ep = ban.endpoints.find((e) => e.list === name);

      console.log(
        `  ${name.padEnd(16)} записей ${fmt(row.entries).padStart(9)}  принято ${fmt(row.writes).padStart(9)}  ` +
        `отказов ${fmt(row.rejects).padStart(7)}  истекло ${fmt(row.expired).padStart(9)}  снапшотов ${String(row.snapshots).padStart(4)}` +
        `${ep === undefined ? "" : `  <- пишет /${ep.id} (${ep.write})`}`,
      );
    }

    if (sum(k, "rejects") > 0) bad.push(`keeper отказал ${fmt(sum(k, "rejects"))} записям`);
    if (sum(k, "store_err") > 0) bad.push(`keeper: ошибок склада ${fmt(sum(k, "store_err"))}`);
  } else {
    bad.push("keeper не ответил на последнем такте");
  }

  console.log(
    `  зеркала ip в конце: ${last.mirrors.map((m) => `${m.host} ${fmt(m.size)} (списков ${m.lists})`).join(", ") || "ни одного в пульсе"}`,
  );

  console.log("\n  память, МиБ");
  console.log("  " + "-".repeat(96));
  console.log("  контейнер   до кейса   после загрузки   пик под нагрузкой   прирост");

  for (const [label] of BAN_WATCHED) {
    const rows = samples.filter((s) => s.mem[label] !== undefined);

    if (rows.length === 0) {
      continue;
    }

    const at = (s) => s.mem[label].reduce((a, b) => a + b, 0);
    const was = base?.[label] === undefined ? null : base[label];
    const after = at(rows[0]);
    const peak = Math.max(...rows.map(at));

    console.log(
      `  ${label.padEnd(11)} ${String(was === null ? "--" : Math.round(was)).padStart(8)} ` +
      `${String(Math.round(after)).padStart(16)} ${String(Math.round(peak)).padStart(19)} ` +
      `${String(was === null ? "--" : `+${Math.round(peak - was)}`).padStart(9)}`,
    );
  }

  console.log(`\n  отказ в трафике -- код ${deny}: это предмет кейса, а не грязь.`);

  for (const line of bad) {
    console.log(`  ! ${line}`);
  }

  if (bad.length === 0) {
    console.log("  никто не умер: keeper без отказов, бан доезжает, списки на обороте");
  }

  return bad.length === 0;
}

/** Суммарная память наблюдаемых контейнеров из снимка `docker stats`. */
export function memOf(stats) {
  const out = {};

  for (const [label, re] of BAN_WATCHED) {
    const rows = Object.entries(stats ?? {}).filter(([name]) => re.test(name));

    if (rows.length > 0) {
      out[label] = rows.reduce((s, [, v]) => s + v.mem, 0);
    }
  }

  return out;
}
