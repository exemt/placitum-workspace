/*
 * Логический прогон: пустой стенд -> сущности через API -> издание -> проверки
 * одиночными запросами -> снос. Нагрузки здесь нет, предмет проверки -- что
 * контур решает на конкретном запросе.
 *
 *     node tests/logic/run.mjs                # все кейсы по очереди
 *     node tests/logic/run.mjs off-saves      # только названные
 *     node tests/logic/run.mjs --keep         # не сносить (для разбора)
 *     node tests/logic/run.mjs --clean        # снести остатки e2e- и выйти
 *     node tests/logic/run.mjs --reset-db     # пересоздать базу из controller/schema
 *     node tests/logic/run.mjs --no-bootstrap # не сверять стенд с исходниками
 *
 * Контроллер -- WAF_CONTROLLER, край -- WAF_E2E_EDGE. Код возврата 0, если все
 * кейсы прошли; пропущенный по неподдержке кейс код не роняет.
 */

import { bootstrap } from "../lib/bootstrap.mjs";
import { lockStand } from "../lib/lock.mjs";
import { runProbes } from "../lib/check.mjs";
import { solveCaptcha } from "../lib/captcha.mjs";
import { CONTROLLER } from "../lib/api.mjs";
import { identities, substOf } from "../lib/identity.mjs";
import { runSocket } from "../lib/socket.mjs";
import { apply, channelsFor, connect, converge, publish, substitute } from "../lib/stand.mjs";
import { cases } from "./cases.mjs";

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);

const KEEP = flag("--keep");
const CLEAN = flag("--clean");
const NO_BOOTSTRAP = flag("--no-bootstrap");
const RESET_DB = flag("--reset-db");
const wanted = argv.filter((a) => !a.startsWith("--"));

const picked = wanted.length === 0 ? cases : cases.filter((c) => wanted.includes(c.id));
const unknown = wanted.filter((id) => !cases.some((c) => c.id === id));

if (unknown.length > 0) {
  throw new Error(`нет таких кейсов: ${unknown.join(", ")}; есть: ${cases.map((c) => c.id).join(", ")}`);
}

const say = (...p) => console.log("   ", ...p);
const head = (t) => console.log(`\n${t}`);

/**
 * Свежий адрес на запуск -- то же, зачем логин каждого запуска свой: корзины
 * по оси `ip` живут в Redis и переживают прогон, а доступа к Redis у
 * автономного прогона нет. Вчерашняя корзина сегодняшнему прогону не мешает
 * ровно потому, что адрес другой.
 *
 * Без указаний -- случайный хост в 198.18/15, диапазоне под стендовые
 * измерения, которого в живом трафике не бывает. Кейс, которому нужен адрес,
 * известный гео (подсеть, AS), называет префикс: `address: { within:
 * "8.8.8.0/24" }` -- и получает случайный хост внутри него.
 */
function runAddress(within = "198.18.0.0/15") {
  const [net, bitsRaw] = within.split("/");
  const bits = Number(bitsRaw);
  const base = net.split(".").reduce((n, o) => n * 256 + Number(o), 0);
  const hosts = 2 ** (32 - bits);
  /* Без сетевого и широковещательного адреса: у /24 это .1 .. .254. */
  const host = base + 1 + Math.floor(Math.random() * Math.max(1, hosts - 2));

  return [24, 16, 8, 0].map((s) => (host >>> s) & 255).join(".");
}

/**
 * Несколько клиентов на один запуск. Кейс называет их ролями (`actors: {
 * buyer: {}, carder: { within: "1.1.1.0/24" } }`), пробы -- именами
 * `@ip.<роль>`, и у каждой роли свой свежий адрес по тем же правилам, что у
 * `@run.ip`. Адреса различны: две роли на одном адресе делили бы корзины и
 * записи в наборах, и кейс проверял бы не то, что в нём написано.
 */
function actorAddresses(actors = {}, taken = new Set()) {
  const out = {};

  for (const [role, spec] of Object.entries(actors)) {
    let ip = runAddress(spec?.within);

    while (taken.has(ip)) {
      ip = runAddress(spec?.within);
    }

    taken.add(ip);
    out[`@ip.${role}`] = ip;
  }

  return out;
}

/* --- поддержка контроллером --------------------------------------------- */

/**
 * Умеет ли поднятый контроллер названный глагол канала действий.
 *
 * Спрашиваем делом, а не версией: заводим временный профиль с этим глаголом и
 * смотрим ответ. Реестр глаголов меняется чаще, чем пересобирают контроллер, и
 * кейс, опередивший стенд, должен быть пропущен с внятной причиной, а не
 * покрашен в красный.
 */
async function supportsVerb(ctx, verb) {
  const doc = {
    mode: "enforce",
    rules: [
      {
        name: "e2e-probe",
        match: { path_prefix: "/e2e-probe/", suffixes: [], static: false, methods: [] },
        actions: [{ do: verb, apply: "request", value: 1, code: "E2E_PROBE" }],
      },
    ],
  };
  const res = await ctx.call(
    "POST",
    `${ctx.base}/action/profiles`,
    { name: `e2e-verb-probe-${Date.now()}`, description: "проба поддержки глагола", doc },
    { allow: [400, 422] },
  );

  if (res.status >= 300) {
    return { ok: false, why: String(res.body?.detail ?? res.body?.error ?? res.status) };
  }

  await ctx.del(`/action/profiles/${res.body.uuid ?? res.body.profile?.uuid}`);
  return { ok: true };
}

/* --- уборка остатков ---------------------------------------------------- */

async function sweep(ctx) {
  const drop = async (kind, path, key, del) => {
    const rows = ((await ctx.get(path))[key] ?? []).filter((r) => (r.name ?? "").startsWith("e2e-"));

    for (const row of rows) {
      await ctx.del(del(row));
      say(`снят ${kind} ${row.name}`);
    }
  };

  /*
   * Объявления держат профили, поэтому снимаются первыми -- раньше и профилей,
   * и серверов. Порядок здесь важнее, чем кажется: профиль капчи зажат с двух
   * сторон -- его держит объявление, а сам он держит сервер и локацию виджета,
   * -- и снять его можно только в этой щели.
   */
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

  await drop("профиль капчи", "/captcha/profiles", "profiles", (r) => `/captcha/profiles/${r.uuid}`);

  for (const srv of ((await ctx.get("/servers")).servers ?? []).filter((s) => s.name.startsWith("e2e-"))) {
    /* Корень сервера поставочный: уйдёт вместе с сервером. */
    for (const loc of ((await ctx.get(`/servers/${srv.uuid}/locations`)).locations ?? []).filter((l) => l.builtin !== true)) {
      await ctx.del(`/locations/${loc.uuid}`);
      say(`снят маршрут ${srv.name} ${loc.path}`);
    }
  }

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
  await drop("набор", "/datasets", "datasets", (r) => `/datasets/${r.uuid}`);

  /*
   * Объявления счётчиков живут одним документом на пространство: снимаются не
   * записью, а правкой -- и только свои, по тому же префиксу.
   */
  const shared = (await ctx.get("/counter/shared")).shared ?? { counters: {} };
  const counters = { ...(shared.counters ?? {}) };
  const mineCounters = Object.keys(counters).filter((n) => n.startsWith("e2e-"));

  for (const n of mineCounters) delete counters[n];

  if (mineCounters.length > 0) {
    await ctx.put("/counter/shared", { shared: { ...shared, counters } });
    say(`сняты счётчики: ${mineCounters.join(", ")}`);
  }

  const channels = ["ip", "action", "counter", "rewrite", "auth", "captcha", "nginx"];

  await publish(ctx, channels, say);
  await converge(ctx, channels, { say });
}

/* --- один кейс ---------------------------------------------------------- */

async function once(ctx, kase) {
  head(`=== ${kase.id} ===`);

  if (kase.requires?.verb !== undefined) {
    const can = await supportsVerb(ctx, kase.requires.verb);

    if (!can.ok) {
      say(`пропущен: контроллер не принимает глагол «${kase.requires.verb}» -- ${can.why}`);
      return "skip";
    }
  }

  /*
   * Личности прогона: своя пара ключей и свои токены. Кейс называет их
   * именами (`"@bearer.alice"`, `"@jwt.public"`), значения подставляются
   * здесь -- и в описание сущностей, и в проверки. Логин каждого запуска свой,
   * поэтому вчерашние корзины в Redis сегодняшнему прогону не мешают.
   */
  const ident = kase.identity === undefined ? null : identities(kase.identity.logins);
  /*
   * Свежий адрес на запуск -- то же, зачем логин каждого запуска свой: корзины
   * по оси `ip` живут в Redis и переживают прогон, а доступа к Redis у
   * автономного прогона нет. Вчерашняя корзина сегодняшнему прогону не мешает
   * ровно потому, что адрес другой. Диапазон -- 198.18/15, отведённый под
   * стендовые измерения и в живом трафике не встречающийся.
   */
  const runIp = runAddress(kase.address?.within);
  const actors = actorAddresses(kase.actors, new Set([runIp]));
  const subst = {
    "@run.ip": runIp,
    ...actors,
    ...(ident === null ? {} : substOf(ident)),
  };

  if (ident !== null) {
    say(`личности прогона: ${Object.values(ident.people).map((p) => p.sub).join(", ")}`);
  }

  if (Object.keys(actors).length > 0) {
    say(`клиенты прогона: ${Object.entries(actors).map(([k, ip]) => `${k.slice(4)} ${ip}`).join(", ")}`);
  }

  head("заведение");
  const { ledger: log, made } = await apply(ctx, kase.needs, say, { subst });
  const channels = channelsFor(kase.needs);

  /*
   * Что уже летит наружу. Нужно затем, чтобы снос не подменял собой причину
   * падения: `throw` из `finally` затирает исходное исключение, и «проверка не
   * сошлась» превращалась в «не снят профиль» -- жалобу на последствие вместо
   * причины.
   */
  let failure = null;

  try {
    head("издание");
    await publish(ctx, channels, say);
    await converge(ctx, channels, { say });

    head("проверки");
    const target = substitute(kase.target, subst);

    /*
     * Прохождение виджета -- действие, а не проверка, и живёт оно снаружи
     * `check.mjs`: там только HTTP через край, а здесь нужен ещё и взгляд в
     * Redis за ответом картинки (см. `../lib/captcha.mjs`).
     */
    await runProbes(ctx, target, substitute(kase.probes ?? [], subst), say, {
      solve: async (p, tell) => {
        const cookies = await solveCaptcha({
          host: target.host,
          from: p.from ?? target.path,
          ip: p.ip ?? null,
          say: (...m) => tell("   ", ...m),
        });

        return { Cookie: cookies.header() };
      },
      /*
       * Взгляд в набор: записи с их сроком. Запись едет через секвенсор, и
       * появляется не мгновенно, поэтому взгляд повторяется до срока пробы --
       * как проверка через край повторяется до сходимости.
       *
       * Ожидания: `has` -- значение есть (адрес сравнивается по началу: в базе
       * он лежит как прислало правило, а край видит его как /32), `lacks` --
       * значения нет, `ttlMax` -- срок записи не больше названного.
       */
      list: async (p, tell) => {
        const ds = made.datasets?.[p.list];

        if (ds === undefined) {
          throw new Error(`проба «${p.name}» смотрит в набор «${p.list}», а он не заведён этим же кейсом`);
        }

        const until = Date.now() + (p.settleMs ?? 15_000);
        let bad = [];

        for (;;) {
          const rows = (await ctx.get(`/datasets/${ds.uuid}/addresses?page_size=200`)).addresses ?? [];
          const found = (v) => rows.find((r) => String(r.address ?? r.value ?? "").startsWith(v));

          bad = [];

          for (const v of [].concat(p.expect?.has ?? [])) {
            const row = found(v);

            if (row === undefined) {
              bad.push(`в наборе нет «${v}» (есть: ${rows.map((r) => r.address ?? r.value).join(", ") || "пусто"})`);
            } else if (p.expect?.ttlMax !== undefined && (row.ttl_s ?? 0) > p.expect.ttlMax) {
              bad.push(`у «${v}» срок ${row.ttl_s} с, ждали не больше ${p.expect.ttlMax}`);
            } else {
              tell(`   ${v}: срок ${row.ttl_s ?? "?"} с, до ${row.expires_at ?? "?"}`);
            }
          }

          for (const v of [].concat(p.expect?.lacks ?? [])) {
            if (found(v) !== undefined) {
              bad.push(`в наборе осталось «${v}», а его должны были убрать`);
            }
          }

          if (bad.length === 0 || Date.now() > until) {
            break;
          }

          await new Promise((r) => setTimeout(r, 1000));
        }

        if (bad.length > 0) {
          throw new Error(`проба «${p.name}»: ${bad.join("; ")}`);
        }
      },
    });

    /* Кадры: своё соединение и свои шаги, по одному кадру на шаг. */
    if (kase.socket !== undefined) {
      head("кадры");
      await runSocket(target, substitute(kase.socket, subst), say);
    }

    return "ok";
  } catch (err) {
    failure = err;
    throw err;
  } finally {
    if (KEEP) {
      head("снос пропущен (--keep)");
      say(`осталось: ${log.rows.map((r) => `${r.kind} ${r.name}`).join("; ")}`);
    } else {
      head("снос");
      const failed = await log.unwind(say);

      await publish(ctx, channels, say);
      await converge(ctx, channels, { say });

      if (failed.length > 0) {
        const text = `не снято: ${failed.map((f) => `${f.kind} ${f.name} (${f.error})`).join("; ")}`;

        if (failure === null) {
          throw new Error(text);
        }

        /* Причина уже летит: про остатки жалуемся громко, но её не подменяем. */
        say(`ВНИМАНИЕ, ${text}`);
      }
    }
  }
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
    results.push({ id: kase.id, state: await once(ctx, kase) });
  } catch (err) {
    console.error(`\n  ${kase.id}: СОРВАЛСЯ -- ${err.message}`);
    results.push({ id: kase.id, state: "fail", error: err.message });
  }
}

head("итог");

for (const r of results) {
  const mark = r.state === "ok" ? "прошёл  " : r.state === "skip" ? "пропущен" : "УПАЛ    ";
  console.log(`    ${mark}  ${r.id}${r.error ? "  " + r.error : ""}`);
}

process.exitCode = results.every((r) => r.state !== "fail") ? 0 : 1;
