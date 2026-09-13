/*
 * Нагрузочный прогон целиком: пустой стенд -> сущности через API -> издание ->
 * нагрузка -> суд -> снос. Ничего руками, ничего заранее.
 *
 *     node tests/load/run.mjs                 # все кейсы по очереди
 *     node tests/load/run.mjs ip-lists        # только названные
 *     node tests/load/run.mjs --keep          # не сносить (для разбора)
 *     node tests/load/run.mjs --setup-only    # завести и остановиться
 *     node tests/load/run.mjs --clean        # снести остатки e2e- и выйти
 *     node tests/load/run.mjs --reset-db     # пересоздать базу из controller/schema
 *     node tests/load/run.mjs --no-bootstrap # не сверять стенд с исходниками
 *     node tests/load/run.mjs --steps 200,400 # свои ступени вместо кейсовых
 *     node tests/load/run.mjs --no-swap      # отсчёт: та же нагрузка без смен
 *     node tests/load/run.mjs hot-list --write net --geo full
 *                                            # горячий список: режим записи капчи
 *                                            # и полный каталог у кодера гео
 *     node tests/load/run.mjs hot-list --no-edge --target 200000 --rounds 1
 *                                            # без зеркала на краях, своя цель
 *
 * Контроллер -- WAF_CONTROLLER (умолчание http://127.0.0.1:8080). Генератор
 * дёргается через контроллер (/api/load), поэтому его порт наружу не нужен.
 *
 * Код возврата: 0 -- все кейсы чистые, 1 -- хотя бы один грязный или упал.
 */

import { bootstrap } from "../lib/bootstrap.mjs";
import { lockStand } from "../lib/lock.mjs";
import { denyStatuses, runProbes } from "../lib/check.mjs";
import { CONTROLLER } from "../lib/api.mjs";
import { identities, substOf } from "../lib/identity.mjs";
import { apply, channelsFor, connect, converge, probe, publish, resolvePool, substitute } from "../lib/stand.mjs";
import { dockerStats, edgeLog, geoPulse, installGeoTable, keeperSet, removeGeoTable, waitGeo } from "../lib/hot.mjs";
import { banWatch, fillLive, memOf, probeGeo, reactions, reportBan } from "../lib/ban.mjs";
import { cases, ipbAddrs, swapRules } from "./cases.mjs";

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const opt = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : null;
};

const KEEP = flag("--keep");
const CLEAN = flag("--clean");
const NO_BOOTSTRAP = flag("--no-bootstrap");
const RESET_DB = flag("--reset-db");
const SETUP_ONLY = flag("--setup-only");
/*
 * Отсчёт для кейса со сменами: та же нагрузка на том же стенде, но
 * конфигурацию никто не трогает. Без этого прогона просадку не с чем сравнить
 * -- ступени внутри одного прогона отличаются друг от друга и сами по себе.
 */
const NO_SWAP = flag("--no-swap");
const STEPS = opt("--steps");
/*
 * Горячий список: режим записи капчи, полный каталог у кодера гео на время
 * прогона, зеркало на краях, своя цель и число планов подряд. Кейсу они не
 * вписаны: одна и та же раскладка гоняется в нескольких режимах.
 */
const WRITE = opt("--write") ?? "addr";
const GEO = opt("--geo");
const NO_EDGE = flag("--no-edge");
const TARGET = opt("--target");
const ROUNDS = opt("--rounds");

if (!["addr", "net", "net_all", "asn"].includes(WRITE)) {
  throw new Error(`--write ${WRITE}: бывает addr, net, net_all или asn`);
}

if (GEO !== null && GEO !== "full") {
  throw new Error(`--geo ${GEO}: бывает только full`);
}

const optValues = new Set([STEPS, opt("--write"), GEO, TARGET, ROUNDS].filter((v) => v !== null));
const wanted = argv.filter((a) => !a.startsWith("--") && !optValues.has(a));

const picked = wanted.length === 0 ? cases : cases.filter((c) => wanted.includes(c.id));
const unknown = wanted.filter((id) => !cases.some((c) => c.id === id));

if (unknown.length > 0) {
  throw new Error(`нет таких кейсов: ${unknown.join(", ")}; есть: ${cases.map((c) => c.id).join(", ")}`);
}

const say = (...p) => console.log("   ", ...p);
const head = (t) => console.log(`\n${t}`);

/* --- генератор ---------------------------------------------------------- */

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Ступени прогона: свои (`--steps`) сильнее кейсовых.
 *
 * `400,800` -- по десять секунд на ступень; `1500:120` -- темп и своя
 * длительность. Десять секунд хороши, чтобы нащупать потолок, и бесполезны,
 * чтобы смотреть на поведение под ровным темпом: за них не успевает ни
 * очередь, ни зеркало.
 */
function planSteps(tr) {
  if (!STEPS) {
    return tr.steps;
  }

  return STEPS.split(",").map((s) => {
    const [rate, seconds] = s.trim().split(":");

    return { rate: Number(rate), duration_s: seconds === undefined ? 10 : Number(seconds) };
  });
}

/*
 * `onStart` зовётся ровно тогда, когда генератор принял план: с этого мига
 * идёт отсчёт ступеней, и правки на ходу назначаются от него, а не от начала
 * вызова -- иначе расписание съезжало бы на время старта wrk.
 */
async function loadRun(ctx, kase, tr, extraFlags = {}, steps = planSteps(tr), onStart = null) {
  const plan = {
    case: kase.id,
    target: {
      host: tr.host,
      method: tr.method,
      path: tr.path,
      /* Кейс из нескольких маршрутов: генератор шлёт их по кругу. */
      paths: tr.paths ?? [],
      headers: tr.headers ?? [],
      body: tr.body ?? "",
      expect: tr.expect ?? 200,
    },
    flags: { random_ip: "", unique: false, ...(tr.flags ?? {}), ...extraFlags },
    sizes: tr.sizes ?? { body: ["orig"], headers: ["orig"], args: ["orig"] },
    steps,
  };

  /*
   * Различаем по коду, а не по телу: на удачный старт генератор отвечает 202 и
   * тем же документом состояния, где status уже "running".
   */
  const start = await ctx.call("POST", "/api/load", plan, { allow: [409, 503] });

  if (start.status === 409) {
    throw new Error("генератор уже занят другим прогоном");
  }

  if (start.status === 503) {
    throw new Error(`генератор не подключен: ${JSON.stringify(start.body)}`);
  }

  if (onStart !== null) {
    onStart(Date.now());
  }

  const planned = steps.reduce((s, r) => s + r.duration_s, 0);
  const deadline = Date.now() + (planned + 60) * 1000;

  for (;;) {
    await new Promise((r) => setTimeout(r, 1000));
    const row = await ctx.api("GET", "/api/load");

    if (row.status !== "running") {
      return row;
    }

    if (Date.now() > deadline) {
      throw new Error("генератор не закончил в срок");
    }
  }
}

/* --- правка правил под нагрузкой ---------------------------------------- */

/**
 * Расписание смен: середина каждой ступени, начиная с `from`.
 *
 * Считается по ступеням, а не пишется числами в кейсе: `--steps` двигает и
 * лестницу, и расписание разом, а удар всегда приходится в середину ступени, а
 * не в шов между двумя запусками wrk, где мерить нечего.
 */
function swapSchedule(steps, from) {
  const out = [];
  let at = 0;

  for (let i = 0; i < steps.length; i += 1) {
    if (i + 1 >= from) {
      out.push({ gen: out.length + 1, step: i + 1, atS: at + steps[i].duration_s / 2 });
    }

    at += steps[i].duration_s;
  }

  return out;
}

/**
 * Живые копии инспектора в пульсе: имя процесса, отпечаток поколения,
 * состояние. Молчащие записи отбрасываются: копия, снятая полчаса назад, ещё
 * висит в снимке и никогда не догонит поколение -- ждать её значит ждать
 * таймаута на ровном месте.
 */
const ALIVE_MS = 15_000;

async function replicas(ctx, name) {
  const snap = await ctx.api("GET", "/api/fleet");

  return (snap.inspectors ?? []).filter(
    (row) => row.name === name && (row.age_ms ?? 0) < ALIVE_MS,
  );
}

const swapProbe = (tr, sw, value) =>
  probe(tr.path, { host: tr.host, headers: { [sw.header]: value } });

/**
 * Одна смена: правка файла -> издание -> наблюдение за краем и за флотом.
 *
 * Пока идёт сборка нового набора, край щупается двумя запросами. Сторож стоит
 * во всех поколениях и обязан получать отказ в каждой пробе: пропуск означает
 * дыру между старым и новым набором. Свежее правило до правки обязано
 * пропускать, после применения -- отказывать; расстояние между правкой и
 * устойчивым отказом и есть время горячей замены.
 */
async function oneSwap(ctx, kase, tr, made, plan, denyCode) {
  const sw = kase.swap;
  const file = made.ruleFiles?.[sw.file];

  if (file === undefined) {
    throw new Error(`кейс правит файл «${sw.file}», а он не заведён этим же кейсом`);
  }

  const fresh = `gen-${plan.gen}`;
  const row = { ...plan, samples: 0, guardBad: 0, failed: 0, freshEarly: false, flips: 0 };

  /* До правки свежего правила ещё нет: иначе меряли бы не то, что сменили. */
  const early = await swapProbe(tr, sw, fresh);
  row.freshEarly = early.status === denyCode;

  const t0 = Date.now();

  await ctx.put(`/rule-files/${file.uuid}`, {
    name: sw.file,
    description: file.description ?? "",
    text_raw: swapRules(plan.gen),
  });

  row.saveMs = Date.now() - t0;

  const sent = await ctx.post("/rules/send", {});

  row.rev = sent.rev;
  row.hash = sent.config_hash;
  row.sendMs = Date.now() - t0;

  const deadline = t0 + sw.timeoutMs;
  let denies = 0;
  let tail = null;

  for (;;) {
    const seen = await replicas(ctx, sw.process);
    const applied = seen.filter((i) => i.config_hash === row.hash && i.apply === "ok");

    if (row.firstMs === undefined && applied.length > 0) {
      row.firstMs = Date.now() - t0;
    }

    if (row.allMs === undefined && seen.length > 0 && applied.length === seen.length) {
      row.allMs = Date.now() - t0;
      row.copies = seen.length;
    }

    const guard = await swapProbe(tr, sw, sw.guard);
    const next = await swapProbe(tr, sw, fresh);

    row.samples += 1;

    /*
     * Сторож судится старым набором ровно до подмены и новым после неё, но
     * стоит он в обоих -- поэтому его отказ обязан быть в каждой пробе.
     */
    if (guard.status !== denyCode) {
      row.guardBad += 1;
    }

    if (guard.fail !== "" || next.fail !== "") {
      row.failed += 1;
    }

    if (next.status === denyCode) {
      if (row.flipMs === undefined) {
        row.flipMs = Date.now() - t0;
      }

      denies += 1;
    } else {
      if (denies >= sw.stable) {
        /* Отказ уже был устойчивым и отвалился: замена «моргнула» назад. */
        row.flips += 1;
      }

      denies = 0;
    }

    if (row.stableMs === undefined && denies >= sw.stable) {
      row.stableMs = Date.now() - t0;
    }

    /*
     * Хвост заводится, когда сошлось и по краю, и по пульсу. Само `устойчиво`
     * на пульс не смотрит намеренно: пульс бьёт раз в несколько секунд, и
     * ждать его значило бы выдать такт пульса за время замены.
     */
    if (tail === null && row.stableMs !== undefined && row.allMs !== undefined) {
      tail = Date.now() + sw.tailMs;
    }

    if (tail !== null && Date.now() >= tail) {
      return row;
    }

    if (tail === null && Date.now() > deadline) {
      row.timedOut = true;
      return row;
    }

    await wait(sw.sampleMs);
  }
}

/**
 * Все смены прогона по расписанию. Исключений не бросает: нагрузка идёт в
 * соседней задаче, и сорвавшееся наблюдение не должно ронять её вместе с
 * собой -- оно просто становится грязным результатом.
 */
async function swapWatch(ctx, kase, tr, made, steps, startedAt) {
  const rows = [];

  try {
    const denyCode = (await denyStatuses(ctx))[kase.swap.denyResponse] ?? 403;

    for (const plan of swapSchedule(steps, kase.swap.fromStep)) {
      const due = startedAt + plan.atS * 1000;

      if (Date.now() < due) {
        await wait(due - Date.now());
      }

      rows.push(await oneSwap(ctx, kase, tr, made, plan, denyCode));
    }
  } catch (err) {
    return { rows, error: err.message };
  }

  return { rows, error: null };
}

function reportSwaps(kase, swaps) {
  const rows = swaps.rows;

  console.log("\n  смены набора правил под нагрузкой, мс от правки");
  console.log("  " + "-".repeat(96));
  console.log("                     вызовы API      край            пульс        пробы");
  console.log("  смена  ступень  правка  издание  отказ  устойчиво  первая   все  всего  сторож  сбои");

  const ms = (v) => (v === undefined ? "--" : String(Math.round(v)));

  for (const r of rows) {
    console.log(
      `  ${String(r.gen).padStart(5)} ${String(r.step).padStart(8)} ` +
      `${ms(r.saveMs).padStart(7)} ${ms(r.sendMs).padStart(8)} ` +
      `${ms(r.flipMs).padStart(6)} ${ms(r.stableMs).padStart(10)} ` +
      `${ms(r.firstMs).padStart(7)} ${ms(r.allMs).padStart(5)} ` +
      `${String(r.samples).padStart(6)} ${String(r.guardBad).padStart(7)} ${String(r.failed).padStart(5)}`,
    );
  }

  const bad = [];

  if (swaps.error !== null) {
    bad.push(`наблюдение сорвалось: ${swaps.error}`);
  }

  if (rows.length === 0) {
    bad.push("ни одной смены не состоялось");
  }

  for (const r of rows) {
    if (r.freshEarly) bad.push(`смена ${r.gen}: свежее правило отказывало ещё до правки`);
    if (r.guardBad > 0) bad.push(`смена ${r.gen}: сторож пропустил ${r.guardBad} проб из ${r.samples}`);
    if (r.failed > 0) bad.push(`смена ${r.gen}: отказ модуля в ${r.failed} пробах`);
    if (r.flips > 0) bad.push(`смена ${r.gen}: применённое правило отваливалось ${r.flips} раз`);
    if (r.timedOut) {
      bad.push(`смена ${r.gen}: поколение не применилось за ${Math.round(kase.swap.timeoutMs / 1000)} с`);
    }
  }

  for (const line of bad) {
    console.log(`  ! ${line}`);
  }

  if (bad.length === 0) {
    const worst = Math.max(...rows.map((r) => r.stableMs ?? 0));
    const beat = Math.max(...rows.map((r) => r.allMs ?? 0));

    console.log(
      `  горячая замена: худшая ${Math.round(worst)} мс по краю, копий ${rows[0].copies ?? "?"}; ` +
      `пульс догоняет за ${Math.round(beat)} мс -- это его такт, а не время замены`,
    );
  }

  return bad.length === 0;
}

function report(kase, run) {
  const rows = run.by_step ?? [];

  console.log(`\n  ${kase.id}: ${kase.title}`);
  console.log("  " + "-".repeat(96));
  console.log("  план   факт    p50     p99   не тот код  отказы  ожидание p99  ступень");

  for (const s of rows) {
    const fails = Object.values(s.waf?.fails ?? {}).reduce((a, b) => a + b, 0);
    const why = s.clean ? "чистая" : (s.why ?? []).join(", ");
    console.log(
      `  ${String(s.step.rate).padStart(5)} ${String(Math.round(s.rps ?? 0)).padStart(6)} ` +
      `${String(Math.round(s.latency.p50 ?? 0)).padStart(6)} ${String(Math.round(s.latency.p99 ?? 0)).padStart(7)} ` +
      `${String(s.unexpected).padStart(11)} ${String(fails).padStart(7)} ` +
      `${String(Math.round(s.waf?.wait?.p99 ?? 0)).padStart(13)}  ${why}`,
    );
  }

  const ceiling = run.ceiling ?? null;
  console.log(`  потолок: ${ceiling === null ? "чистых ступеней нет" : ceiling + " rps"}`);
  return ceiling !== null;
}


/* --- горячий список ----------------------------------------------------- */

/** Контейнеры стенда, за памятью которых следит кейс горячего списка. */
const HOT_WATCHED = [
  ["keeper", /^waf-keeper-/],
  ["geo", /^waf-geo-/],
  ["ip", /^waf-inspector-ip-/],
  ["cap", /^waf-inspector-captcha-/],
  ["край", /^waf-edge-/],
  ["nats", /^waf-nats-1$/],
  ["pg", /^waf-postgres-/],
  ["redis", /^waf-redis-1$/],
  ["redis-int", /^waf-redis-internal-1$/],
  ["ctl", /^waf-controller-/],
];
const EDGES = ["waf-edge-01-1", "waf-edge-02-1", "waf-edge-03-1"];

/** 1234567 -> «1 234 567». */
const fmt = (n) => (n === null || n === undefined ? "--" : String(n).replace(/\B(?=(\d{3})+(?!\d))/g, " "));

/** Набор без зеркала на краях: не объявлен в nginx, маршрут без локальной проверки. */
function withoutEdge(needs) {
  return {
    ...needs,
    datasets: (needs.datasets ?? []).map(({ in_nginx, ...d }) => d),
    routes: (needs.routes ?? []).map((r) => ({
      ...r,
      waf: r.waf === undefined ? r.waf : Object.fromEntries(Object.entries(r.waf).filter(([k]) => k !== "localChecks")),
    })),
  };
}

/**
 * Один такт наблюдения: размер списка у контроллера, счётчики keeper, зеркала
 * инспектора адреса из пульса (uuid набора в `work.live`), темп краёв и --
 * не на каждом такте, `docker stats` отвечает секунду-две -- память
 * контейнеров.
 */
async function hotSample(ctx, ds, withStats) {
  const [row, keeper, fleet, stats] = await Promise.all([
    ctx.get(`/datasets/${ds.uuid}`),
    keeperSet(ds.name).catch((err) => ({ error: err.message })),
    ctx.api("GET", "/api/fleet"),
    withStats ? dockerStats().catch(() => ({})) : Promise.resolve(null),
  ]);
  const mirrors = (fleet.inspectors ?? [])
    .filter((r) => r.name === "ip" && (r.age_ms ?? 0) < ALIVE_MS)
    .map((r) => {
      const live = (r.work?.live ?? r.live ?? []).find((l) => l.uuid === ds.uuid);

      return {
        host: r.hostname,
        size: live === undefined ? null : live.base + live.live,
        seq: live?.seq ?? null,
        ready: live?.ready ?? false,
      };
    });
  const agents = (fleet.agents ?? []).filter((a) => (a.age_ms ?? 0) < ALIVE_MS);
  const mem = {};

  if (stats !== null) {
    for (const [label, re] of HOT_WATCHED) {
      const rows = Object.entries(stats).filter(([name]) => re.test(name)).sort(([a], [b]) => a.localeCompare(b));

      if (rows.length > 0) {
        mem[label] = rows.map(([, v]) => v.mem);
      }
    }
  }

  return {
    at: Date.now(),
    size: Number(row.size ?? 0),
    keeper,
    mirrors,
    rps: agents.reduce((s, a) => s + (a.rps ?? 0), 0),
    fivexx: agents.reduce((s, a) => s + (a.codes?.["5xx"] ?? 0), 0),
    mem,
  };
}

function hotLine(s, t0) {
  const t = Math.round((s.at - t0) / 1000);
  const k = s.keeper;
  const kp = k === null
    ? "keeper: набора нет"
    : k.error !== undefined
      ? `keeper: ${k.error}`
      : `keeper ${fmt(k.entries)} зап ${fmt(k.writes)} отк ${k.rejects} дельт ${fmt(k.diffs)} снап ${k.snapshots} ` +
        `склад ${k.store_ms} мс${k.store_err ? ` ОШИБОК ${k.store_err}` : ""}`;
  const m = s.mirrors.map((r) => fmt(r.size)).join(" / ");
  const mem = Object.entries(s.mem).map(([l, v]) => `${l} ${v.map((x) => Math.round(x)).join("/")}`).join(" ");

  return (
    `+${String(t).padStart(4)}с  список ${fmt(s.size)} | ${kp} | зеркала ip ${m || "--"} | ` +
    `rps ${fmt(Math.round(s.rps))}${s.fivexx ? ` 5xx ${s.fivexx}` : ""}${mem ? ` | МиБ ${mem}` : ""}`
  );
}

/** Наблюдение в соседней задаче, пока не остановят; сорвавшийся такт -- строка, не падение. */
function hotWatch(ctx, hot, ds, t0) {
  const samples = [];
  let stop = false;
  let tick = 0;

  const done = (async () => {
    while (!stop) {
      try {
        const s = await hotSample(ctx, ds, tick % 2 === 0);

        samples.push(s);
        say(hotLine(s, t0));
      } catch (err) {
        say(`наблюдение: ${err.message}`);
      }

      tick += 1;
      const until = Date.now() + hot.sampleMs;

      while (!stop && Date.now() < until) {
        await wait(250);
      }
    }

    return samples;
  })();

  return { stop: () => { stop = true; }, done };
}

/** После нагрузки: пока зеркала инспектора адреса не сравняются с keeper, но не дольше settleMs. */
async function hotSettle(ctx, hot, ds) {
  const t0 = Date.now();

  for (;;) {
    const s = await hotSample(ctx, ds, false);
    const truth = s.keeper === null || s.keeper.error !== undefined ? null : s.keeper.entries;
    const lag = s.mirrors.map((m) => (m.size === null || truth === null ? null : truth - m.size));
    const converged = truth !== null && s.mirrors.length > 0 && lag.every((l) => l === 0);

    if (converged || Date.now() - t0 > hot.settleMs) {
      return { ms: converged ? Date.now() - t0 : null, truth, size: s.size, mirrors: s.mirrors, lag };
    }

    await wait(2000);
  }
}

/** Одна проба через край: код, вердикт, кто решил и кто отказал. */
async function hotProbe(tr, ip) {
  const r = await probe(tr.path, { host: tr.host, headers: { "X-Forwarded-For": ip } });

  return {
    status: r.status,
    verdict: r.verdict,
    by: r.by,
    fail: r.fail,
    asked: Object.keys(r.inspectors),
    denied: Object.entries(r.inspectors).filter(([, v]) => v.startsWith("deny")).map(([k, v]) => `${k}=${v}`),
  };
}

/**
 * Затравка до нагрузки: адреса выборки заходят первыми и первыми ложатся в
 * список. Первый визит обязан пройти -- списка ещё нет; второй, после
 * дельты, обязан получить отказ: так до нагрузки видно, что бан вообще
 * работает, а после -- что самые ранние записи дожили до конца.
 */
async function hotSeed(hot, tr, deny) {
  for (const ip of hot.samples) {
    const first = await hotProbe(tr, ip);

    if (first.status !== 200) {
      throw new Error(`затравка ${ip}: первый визит ${first.status} ${first.verdict}${first.fail ? ` fail=${first.fail}` : ""}, ждали 200`);
    }
  }

  /*
   * Второй визит обязан получить отказ, но дельта едет через шину и три
   * зеркала края -- пробуем несколько секунд, а не ровно раз: пропаганда по
   * контуру занимает миллисекунды, но балансировщик кидает второй запрос на
   * любой из трёх краёв, и который-то мог не успеть.
   */
  for (const ip of hot.samples) {
    let second = null;

    for (let i = 0; i < 20; i += 1) {
      await wait(500);
      second = await hotProbe(tr, ip);

      if (second.status === deny) {
        break;
      }
    }

    if (second.status !== deny) {
      throw new Error(`затравка ${ip}: за 10 с бан не доехал до края, последний визит ${second.status} ${second.verdict}, ждали ${deny}`);
    }

    say(`${ip}: первый визит прошёл, второй отказан (${second.by === "local" ? "край" : second.denied.join(",") || second.verdict})`);
  }
}

/**
 * Не забанили лишнего и забанили кого надо: контрольный адрес, которого в
 * трафике не было, проходит; затравка получает отказ -- по три пробы на
 * адрес через балансировщик, чтобы задеть все края, и видно, кто отказал:
 * край локальной проверкой (`by=local`) или инспектор адреса.
 */
async function hotVerify(hot, tr, deny) {
  const control = { ip: hot.control, ...(await hotProbe(tr, hot.control)) };
  const samples = [];

  for (const ip of hot.samples) {
    const got = [];

    for (let i = 0; i < 3; i += 1) {
      got.push(await hotProbe(tr, ip));
    }

    samples.push({ ip, got });
  }

  return { deny, control, samples };
}

function reportHot(hot, out) {
  const { samples, settle, verify, edges, dirty } = out;
  const last = samples.at(-1);
  const k = last?.keeper !== null && last?.keeper?.error === undefined ? last.keeper : null;
  const peak = (label) => Math.max(0, ...samples.map((s) => Math.max(0, ...(s.mem[label] ?? []))));
  const storeMax = Math.max(0, ...samples.map((s) => s.keeper?.store_ms ?? 0));
  const bad = [];

  console.log("\n  горячий список");
  console.log("  " + "-".repeat(96));
  console.log(
    `  записей: список ${fmt(settle.size)}, keeper ${fmt(settle.truth)} из цели ${fmt(hot.target)}` +
    (k === null ? "" : `; keeper принял ${fmt(k.writes)}, отказал ${fmt(k.rejects)}, дельт ${fmt(k.diffs)}, ` +
      `снапшотов ${k.snapshots} (упаковок ${k.packs}), склад до ${storeMax} мс, ошибок склада ${k.store_err}`),
  );
  console.log(
    `  зеркала ip: ${settle.mirrors.map((m) => `${m.host} ${fmt(m.size)}`).join(", ") || "ни одного в пульсе"}; ` +
    (settle.ms === null
      ? `не сошлись с keeper за ${Math.round(hot.settleMs / 1000)} с (отставание ${settle.lag.map(fmt).join(" / ")})`
      : `сошлись с keeper за ${settle.ms} мс после нагрузки`),
  );

  for (const [name, log] of Object.entries(edges)) {
    console.log(
      `  ${name}: снапшотов ${log.snapshots} (применено ${log.applied}, последний ${fmt(log.entries)} записей), ` +
      `пакетов протухло ${log.gone}, diverged ${log.diverged}, нет места ${log.noRoom}, warn ${log.warns}, error ${log.errors}`,
    );
  }

  console.log(
    "  память, пик МиБ: " +
    HOT_WATCHED.filter(([l]) => samples.some((s) => s.mem[l] !== undefined))
      .map(([l]) => `${l} ${Math.round(peak(l))}`).join(", "),
  );

  const c = verify.control;

  console.log(
    `  контроль ${c.ip}: ${c.status} ${c.verdict}${c.by ? ` by=${c.by}` : ""}${c.fail ? ` fail=${c.fail}` : ""}, ` +
    `спрошены ${c.asked.join(",") || "никто"}`,
  );

  for (const s of verify.samples) {
    console.log(
      `  затравка ${s.ip}: ` +
      s.got.map((g) => `${g.status} ${g.by === "local" ? "край" : g.denied.join(",") || g.verdict}`).join(" | "),
    );
  }

  if (dirty > 0) bad.push(`грязных ступеней: ${dirty}`);
  if (k !== null && k.rejects > 0) bad.push(`keeper отказал ${fmt(k.rejects)} записям`);
  if (k !== null && k.store_err > 0) bad.push(`keeper: ошибок склада ${k.store_err}`);
  if (settle.ms === null) bad.push("зеркала инспектора адреса не сошлись с keeper");
  if (settle.truth !== null && settle.size !== settle.truth) {
    /*
     * Не смерть, но видно: размер активного набора контроллер держит в своём
     * состоянии и пересчитывает на своих правках, а пишет сюда keeper -- в
     * панели у горячего списка ноль записей.
     */
    console.log(`  контроллер показывает ${fmt(settle.size)} записей при ${fmt(settle.truth)} у keeper: размер активного набора у него свой, не от keeper`);
  }

  for (const [name, log] of Object.entries(edges)) {
    if (log.noRoom > 0) bad.push(`${name}: нет места в зоне (${log.noRoom} раз) -- зеркало края не вместило список`);
    if (log.errors > 0) bad.push(`${name}: ошибок в журнале по набору ${log.errors}`);
  }

  for (const [l] of HOT_WATCHED) {
    if (peak(l) > 900) bad.push(`${l}: память у предела, пик ${Math.round(peak(l))} МиБ из 1024`);
  }

  if (c.status !== 200 || c.verdict !== "allow") bad.push(`контрольный адрес ${c.ip} не прошёл: ${c.status} ${c.verdict}`);
  if (!c.asked.includes("e2e-ip")) bad.push("контрольный адрес не спросил инспектор адреса");

  for (const s of verify.samples) {
    const passed = s.got.filter((g) => g.status !== verify.deny).length;

    if (passed > 0) bad.push(`затравка ${s.ip} прошла ${passed} раз из ${s.got.length}: ранняя запись не дожила`);
  }

  for (const line of bad) {
    console.log(`  ! ${line}`);
  }

  if (bad.length === 0) {
    console.log("  никто не умер: keeper без отказов, зеркала сошлись, края вместили, контроль прошёл, выборка отказана");
  }

  return bad.length === 0;
}

/**
 * Прогон горячего списка: наблюдение с первого плана до схождения зеркал,
 * планы подряд, пока не набралась цель, потом проверки и журнал краёв.
 */
async function hotRun(ctx, kase, traffic, made, since) {
  const hot = {
    ...kase.hot,
    target: TARGET === null ? kase.hot.target : Number(TARGET),
    rounds: ROUNDS === null ? kase.hot.rounds : Number(ROUNDS),
  };
  const ds = made.datasets?.[hot.list];

  if (ds === undefined) {
    throw new Error(`кейс смотрит за набором «${hot.list}», а он не заведён этим же кейсом`);
  }

  const deny = (await denyStatuses(ctx)).blocked ?? 403;
  const t0 = Date.now();

  head("затравка");
  await hotSeed(hot, traffic, deny);

  head(`нагрузка: запись ${WRITE}, зеркало на краях ${NO_EDGE ? "снято" : "есть"}, цель ${fmt(hot.target)}`);

  const watch = hotWatch(ctx, hot, ds, t0);
  const steps = planSteps(traffic);
  let dirty = 0;

  try {
    for (let round = 1; round <= hot.rounds; round += 1) {
      say(`план ${round} из ${hot.rounds}`);

      const run = await loadRun(ctx, kase, traffic, {}, steps);

      if (run.status !== "done") {
        say(`генератор: ${run.status}, код ${run.exit_code}`);
      }

      report(kase, run);
      dirty += (run.by_step ?? []).filter((s) => !s.clean).length;

      /* Размер -- у keeper: контроллер у активного набора считает только своё, а пишет сюда не он. */
      const size = (await keeperSet(ds.name))?.entries ?? 0;

      if (size >= hot.target) {
        say(`цель набрана: ${fmt(size)} записей`);
        break;
      }

      say(`после плана ${round}: ${fmt(size)} записей из ${fmt(hot.target)}`);
    }

    head("схождение зеркал");
    const settle = await hotSettle(ctx, hot, ds);

    watch.stop();
    const samples = await watch.done;

    head("проверки после нагрузки");
    const verify = await hotVerify(hot, traffic, deny);
    const edges = {};

    for (const name of EDGES) {
      edges[name] = await edgeLog(name, ds.name, since).catch((err) => ({ error: err.message, snapshots: 0, applied: 0, entries: null, gone: 0, diverged: 0, noRoom: 0, warns: 0, errors: 0 }));
    }

    return reportHot(hot, { samples, settle, verify, edges, dirty });
  } finally {
    watch.stop();
  }
}

/* --- бан инспектором адреса --------------------------------------------- */

/**
 * Строки инспекторов из сводки wrk: у кейса из трёх маршрутов общий счёт
 * вердиктов не говорит, который из них отказал, а имя инспектора говорит --
 * оно своё у каждого эндпоинта.
 */
function reportEndpoints(kase, run) {
  const rows = run.by_step ?? [];

  console.log("\n  эндпоинты по ступеням: запросов, отказов инспектора, его время");
  console.log("  " + "-".repeat(96));
  console.log("  ступень  инспектор        запросов   отказов   доля   p50   p99   макс, мс");

  for (const s of rows) {
    for (const i of s.waf?.inspectors ?? []) {
      const deny = Number(i.deny ?? 0);

      console.log(
        `  ${String(s.step.rate).padStart(7)}  ${String(i.name).padEnd(16)} ${String(i.count).padStart(8)} ` +
        `${String(deny).padStart(9)} ${`${Math.round((100 * deny) / Math.max(1, i.count))}%`.padStart(6)} ` +
        `${String(Math.round(i.p50 ?? 0)).padStart(5)} ${String(Math.round(i.p99 ?? 0)).padStart(5)} ${String(Math.round(i.max ?? 0)).padStart(6)}`,
      );
    }
  }
}

/**
 * Кейс ip-ban: реакция на покое, нагрузка с пробами реакции внутри, наблюдение
 * за списками и памятью от заведения до оседания.
 *
 * Пробы под нагрузкой заводятся со второй ступени: на разогреве меряться нечему
 * -- списки ещё пусты, а ответ на вопрос «быстро ли банится адрес, когда стенд
 * занят» нужен именно на рабочем темпе.
 */
async function banRun(ctx, kase, traffic, made, base) {
  const ban = kase.ban;
  const deny = (await denyStatuses(ctx)).blocked ?? 403;
  const uuids = new Set();

  for (const name of ban.live) {
    const ds = made.datasets?.[name];

    if (ds === undefined) {
      throw new Error(`кейс смотрит за набором «${name}», а он не заведён этим же кейсом`);
    }

    uuids.add(ds.uuid);
  }

  head("загрузка активных списков");
  await fillLive(ban, ipbAddrs, say);

  head(`реакция до нагрузки (отказ -- ${deny})`);
  const idle = await reactions(traffic, ban, deny, "покой", say);

  const t0 = Date.now();
  const watch = banWatch(ctx, ban, uuids, t0, say);

  try {
    head("нагрузка");

    const steps = planSteps(traffic);
    /* Пробы стартуют в середине последней ступени -- к этому мигу темп ровный. */
    const atS = steps.slice(0, -1).reduce((s, r) => s + r.duration_s, 0) + 10;
    let probing = null;

    const run = await loadRun(ctx, kase, traffic, {}, steps, (startedAt) => {
      probing = (async () => {
        await wait(Math.max(0, startedAt + atS * 1000 - Date.now()));

        try {
          return await reactions(traffic, ban, deny, "нагрузка", say);
        } catch (err) {
          say(`пробы под нагрузкой: ${err.message}`);
          return [];
        }
      })();
    });

    const loaded = probing === null ? [] : await probing;

    if (run.status !== "done") {
      say(`генератор: ${run.status}, код ${run.exit_code}`);
    }

    report(kase, run);
    reportEndpoints(kase, run);

    head("оседание");
    await wait(ban.settleMs);
    watch.stop();

    const samples = await watch.done;

    return reportBan(ban, {
      phases: { покой: idle, нагрузка: loaded },
      samples,
      base,
      loaded: ban.loaded * ban.live.length,
      deny,
    });
  } finally {
    watch.stop();
  }
}

/* --- один кейс ---------------------------------------------------------- */

async function once(ctx, kase) {
  head(`=== ${kase.id} ===`);

  /*
   * Личности прогона: кейс называет их именами (`"@bearer.alice"`), значения
   * -- своя пара ключей и свои токены -- рождаются здесь. Логин у каждого
   * запуска свой, поэтому корзины прошлого прогона этому не мешают.
   */
  const ident = kase.identity === undefined ? null : identities(kase.identity.logins);
  /* Режим записи горячего списка -- значение прогона, как и личности. */
  const subst = { ...(ident === null ? {} : substOf(ident)), "@hot.write": WRITE };
  const traffic = substitute(kase.traffic, subst);
  const needs = NO_EDGE ? withoutEdge(kase.needs) : kase.needs;

  if (ident !== null) {
    say(`личности прогона: ${Object.values(ident.people).map((p) => p.sub).join(", ")}`);
  }

  /*
   * Полный каталог у кодера гео -- до заведения: капча резолвит анонсы в
   * момент записи, и на учебном наборе `write: net` почти всё пропустит.
   */
  let geo = null;
  /* Кейс сам говорит, что без полного каталога он меряет пустоту. */
  const wantsGeo = (GEO === "full" && kase.hot !== undefined) || kase.ban?.geo === "full";

  if (wantsGeo) {
    head("каталог гео");
    const before = geoPulse(await ctx.api("GET", "/api/fleet"));

    /* Кейс с пробами дописывает к каталогу свои системы -- см. probeGeo. */
    await installGeoTable(say, kase.ban === undefined ? "" : probeGeo());
    geo = await waitGeo(ctx, { gen: before?.gen ?? 0, want: (n) => n >= 50_000 }, say);
  } else if (WRITE !== "addr" && kase.hot !== undefined) {
    say(`запись ${WRITE} на учебном каталоге гео: почти все адреса кодеру неизвестны, записей будет мало (--geo full)`);
  }

  /* Память до заведения: с ней видно, чего стоят сами списки, а не стенд. */
  const base = kase.ban === undefined ? null : memOf(await dockerStats().catch(() => ({})));

  head("заведение");
  /* Журнал краёв по набору читается с этого мига: снапшот они просят при издании, до нагрузки. */
  const since = new Date().toISOString();
  const { ledger: log, made } = await apply(ctx, needs, say, { subst });

  let ok = false;

  try {
    head("издание");
    await publish(ctx, channelsFor(needs), say);
    await converge(ctx, channelsFor(needs), { say });

    if (SETUP_ONLY) {
      say("--setup-only: остановились до нагрузки");
      return true;
    }

    /*
     * Пул адресов: настоящие префиксы стран, ASN и своих списков. Собирается
     * после издания -- к этому моменту наборы кейса уже лежат в контроллере.
     */
    let flags = {};

    if (kase.pool !== undefined) {
      head("пул адресов");
      const pool = await resolvePool(ctx, kase.pool, made);
      flags = { ip_walk: { cidrs: pool.cidrs, count: pool.count } };
      say(`префиксов ${pool.cidrs.length}, адресов в пуле ${pool.count} из ${pool.size} доступных`);
    }

    if (kase.probes?.length) {
      head("проверки до нагрузки");
      await runProbes(ctx, traffic, substitute(kase.probes, subst), say);
    }

    if (kase.ban !== undefined) {
      /* Бан инспектором адреса: пробы реакции и наблюдение за списками -- свои. */
      ok = await banRun(ctx, kase, traffic, made, base);
    } else if (kase.hot !== undefined) {
      /* Горячий список: планы подряд, наблюдение и проверки -- свои. */
      ok = await hotRun(ctx, kase, traffic, made, since);
    } else {
      head("нагрузка");

      /*
       * Кейс со сменами правит конфигурацию прямо под нагрузкой. Наблюдение
       * заводится из колбэка старта -- расписание отсчитывается от мига, когда
       * генератор принял план, а не от начала вызова.
       */
      const steps = planSteps(traffic);
      let watching = null;
      const run = await loadRun(ctx, kase, traffic, flags, steps, (at) => {
        if (kase.swap !== undefined && !NO_SWAP) {
          watching = swapWatch(ctx, kase, traffic, made, steps, at);
        }
      });
      const swaps = watching === null ? null : await watching;

      if (run.status !== "done") {
        say(`генератор: ${run.status}, код ${run.exit_code}`);
      }

      ok = report(kase, run);

      if (swaps !== null) {
        /*
         * У кейса со сменами темп ровный, и потолок ни при чём: просадка ищется
         * сравнением ступеней между собой, поэтому чистыми обязаны быть все.
         */
        const dirty = (run.by_step ?? []).filter((s) => !s.clean);

        if (dirty.length > 0) {
          console.log(`  ! грязных ступеней: ${dirty.length} из ${(run.by_step ?? []).length}`);
        }

        ok = reportSwaps(kase, swaps) && dirty.length === 0;
      }
    }
  } finally {
    if (KEEP) {
      head("снос пропущен (--keep)");
      say(`осталось: ${log.rows.map((r) => `${r.kind} ${r.name}`).join("; ")}`);
    } else {
      head("снос");
      const failed = await log.unwind(say);

      /* Издаём ещё раз: края должны сойтись на конфигурации без наших маршрутов. */
      await publish(ctx, channelsFor(needs), say);
      await converge(ctx, channelsFor(needs), { say });

      if (geo !== null) {
        /* Учебный каталог обратно: кодер перечитает сам, ждём, чтобы стенд остался прежним. */
        await removeGeoTable();
        await waitGeo(ctx, { gen: geo.gen, want: (n) => n < 1000 }, say).catch((err) => say(err.message));
      }

      if (failed.length > 0) {
        throw new Error(`не снято: ${failed.map((f) => `${f.kind} ${f.name} (${f.error})`).join("; ")}`);
      }
    }
  }

  return ok;
}

/* --- уборка остатков ---------------------------------------------------- */

/**
 * Снести всё с префиксом `e2e-`, что осталось от прерванного прогона или от
 * `--keep`. Журнала тут нет, поэтому единственная защита -- префикс: чужое имя
 * под него не попадает.
 */
async function sweep(ctx) {
  const drop = async (kind, path, key, del) => {
    const rows = ((await ctx.get(path))[key] ?? []).filter((r) => (r.name ?? "").startsWith("e2e-"));

    for (const row of rows) {
      await ctx.del(del(row));
      say(`снят ${kind} ${row.name}`);
    }
  };

  for (const srv of ((await ctx.get("/servers")).servers ?? []).filter((s) => s.name.startsWith("e2e-"))) {
    /* Корень сервера поставочный и не удаляется поодиночке: уйдёт вместе с сервером. */
    for (const loc of ((await ctx.get(`/servers/${srv.uuid}/locations`)).locations ?? []).filter((l) => l.builtin !== true)) {
      await ctx.del(`/locations/${loc.uuid}`);
      say(`снят маршрут ${srv.name} ${loc.path}`);
    }
  }

  /* Объявления держат профили, поэтому снимаются раньше них. */
  const http = await ctx.get("/http");
  const insp = { ...(http.waf?.inspectors ?? {}) };
  const mine = Object.keys(insp).filter((n) => n.startsWith("e2e-"));

  for (const n of mine) delete insp[n];

  if (mine.length > 0) {
    await ctx.put("/http", {
      nginx_main: http.nginx_main, nginx: http.nginx, waf_http: http.waf_http,
      waf: { ...(http.waf ?? {}), inspectors: insp }, raw: http.raw, raw_nginx: http.raw_nginx,
    });
    say(`сняты объявления: ${mine.join(", ")}`);
  }

  /* Профиль капчи держит сервер (виджет живёт на нём), поэтому снимается раньше сервера. */
  await drop("профиль капчи", "/captcha/profiles", "profiles", (r) => `/captcha/profiles/${r.uuid}`);
  await drop("сервер", "/servers", "servers", (r) => `/servers/${r.uuid}`);
  await drop("апстрим", "/upstreams", "upstreams", (r) => `/upstreams/${r.uuid}`);
  /* Профиль калитки держит источник, поэтому снимается раньше него. */
  await drop("профиль калитки", "/auth/profiles", "profiles", (r) => `/auth/profiles/${r.uuid}`);
  await drop("источник входа", "/auth/sources", "sources", (r) => `/auth/sources/${r.uuid}`);
  await drop("профиль модификатора", "/rewrite/profiles", "profiles", (r) => `/rewrite/profiles/${r.uuid}`);
  await drop("профиль счётчика", "/counter/profiles", "profiles", (r) => `/counter/profiles/${r.uuid}`);
  await drop("профиль действий", "/action/profiles", "profiles", (r) => `/action/profiles/${r.uuid}`);
  await drop("профиль адреса", "/ip-profiles", "ip_profiles", (r) => `/ip-profiles/${r.uuid}`);
  await drop("набор адресов", "/ip-sets", "ip_sets", (r) => `/ip-sets/${r.uuid}`);
  /* Набор правил держит свои файлы, поэтому снимается раньше них. */
  await drop("набор правил", "/rule-sets", "rule_sets", (r) => `/rule-sets/${r.uuid}`);
  await drop("файл правил", "/rule-files", "rule_files", (r) => `/rule-files/${r.uuid}`);
  await drop("набор", "/datasets", "datasets", (r) => `/datasets/${r.uuid}`);

  /* Объявления счётчиков -- один документ на пространство: правка, а не запись. */
  const shared = (await ctx.get("/counter/shared")).shared ?? { counters: {} };
  const counters = { ...(shared.counters ?? {}) };
  const mineCounters = Object.keys(counters).filter((n) => n.startsWith("e2e-"));

  for (const n of mineCounters) delete counters[n];

  if (mineCounters.length > 0) {
    await ctx.put("/counter/shared", { shared: { ...shared, counters } });
    say(`сняты счётчики: ${mineCounters.join(", ")}`);
  }

  /* Полный каталог гео от прерванного прогона: кодер перечитает сам. */
  await removeGeoTable();

  const channels = ["ip", "action", "counter", "rewrite", "auth", "captcha", "rules", "nginx"];

  await publish(ctx, channels, say);
  await converge(ctx, channels, { say });
}

/* --- прогон ------------------------------------------------------------- */

/* Стенд один: два прогона разом теряют правки общих документов. */
lockStand();

/*
 * Предполёт раньше всего: прогон против промежуточной сборки ничего не
 * доказывает. Пропускается только явно, `--no-bootstrap`, и только когда
 * оператор точно знает, что стенд уже соответствует исходникам.
 */
if (!NO_BOOTSTRAP) {
  head("предполёт");
  await bootstrap({ ctrl: CONTROLLER, reset: RESET_DB, say });
}

const ctx = await connect();
console.log(`контроллер ${ctx.ctrl}, пространство ${ctx.scope}`);

if (CLEAN) {
  head("уборка остатков");
  await sweep(ctx);
  head("готово");
  process.exit(0);
}

const results = [];

for (const kase of picked) {
  try {
    results.push({ id: kase.id, ok: await once(ctx, kase) });
  } catch (err) {
    console.error(`\n  ${kase.id}: СОРВАЛСЯ -- ${err.message}`);
    results.push({ id: kase.id, ok: false, error: err.message });
  }
}

head("итог");

for (const r of results) {
  console.log(`    ${r.ok ? "чисто " : "ГРЯЗНО"}  ${r.id}${r.error ? "  " + r.error : ""}`);
}

process.exitCode = results.every((r) => r.ok) ? 0 : 1;
