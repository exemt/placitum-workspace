/*
 * Предполётная подготовка стенда: привести поднятое в соответствие с
 * исходниками и только потом пускать прогон.
 *
 * Зачем. Прогон против промежуточной сборки ничего не доказывает: зелёный
 * результат может значить «код исправен», а может — «стенд не знает о правке».
 * Ровно так и вышло 10.09.2026: контроллер, поднятый сутками раньше, отдавал
 * реестр из двенадцати глаголов вместо четырнадцати, и кейс на `score` падал
 * не потому, что сломан, а потому, что стенд отстал.
 *
 * Что делает.
 *
 * 1. Собирает образы тех сервисов, у которых исходники новее образа.
 * 2. Раскатывает в обязательном порядке: инспекторы, потом контроллер, потом
 *    края. Обратный порядок ломает рассылку: новый контроллер считает хеш
 *    по-новому, старый инспектор его отвергает, и до пересборки перестают
 *    доезжать не только новые поля, но и правки профилей.
 * 3. Сверяет, что каждый контейнер поднят на текущем образе, а не на прошлом.
 * 4. Сверяет реестр глаголов контроллера с исходниками -- это дешёвая проверка
 *    того, что раскатка действительно дошла до кода, а не только до образа.
 *
 * Чего НЕ делает сам. Не пересоздаёт базу: поставка `controller/schema`
 * применяется postgres только на пустом томе. Миграции, выпущенные после
 * поставки, предполёт докатывает по журналу `waf_schema_log`; всё остальное --
 * отдельный, явно запрошенный `--reset-db`, который сносит том и поднимает его
 * заново поставкой, гео-сидом и стендовым деревом `schema/stand/stand.sql`.
 */

import { execFile } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");
const DEPLOY = join(ROOT, "deploy");

const NL = String.fromCharCode(10);

/* Каталоги, которые не считаются исходниками: их правка образ не меняет. */
/* Сколько образов собирать за раз: больше -- срывается сеть сборщика. */
const BUILD_BATCH = 3;

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "target", "__pycache__", ".venv", "seed"]);

/**
 * Порядок раскатки. Внутри группы порядок безразличен, между группами -- нет.
 * Инспекторы раньше контроллера, контроллер раньше краёв.
 */
const WAVES = [
  {
    name: "инспекторы",
    services: [
      "inspector-modsec", "inspector-ip", "inspector-auth", "auth-http",
      "inspector-json", "inspector-action", "inspector-counter",
      "inspector-rewrite", "inspector-captcha", "captcha-http", "inspector-vlai",
    ],
  },
  { name: "служебные", services: ["keeper", "crypto", "geo", "logger", "search", "redis-agent", "redis-internal-agent", "s3-agent", "app", "loadgen"] },
  { name: "контроллер", services: ["controller"] },
  { name: "края", services: ["edge-01", "edge-02", "edge-03", "haproxy"] },
];

/** Контекст сборки на сервис: чем определяется свежесть образа. */
const CONTEXT = {
  "inspector-modsec": "inspectors/modsec",
  "inspector-ip": "inspectors/ip",
  "inspector-auth": "inspectors/auth",
  "auth-http": "inspectors/auth",
  "inspector-json": "inspectors/json",
  "inspector-action": "inspectors/action",
  "inspector-counter": "inspectors/counter",
  "inspector-rewrite": "inspectors/rewrite",
  "inspector-captcha": "inspectors/captcha",
  "captcha-http": "inspectors/captcha",
  "inspector-vlai": "inspectors/vlai",
  keeper: "keeper",
  crypto: "crypto",
  geo: "geo",
  logger: "logger",
  search: "logger",
  "redis-agent": "agents/redis",
  "redis-internal-agent": "agents/redis",
  "s3-agent": "agents/s3",
  app: "testapp",
  loadgen: "deploy/loadgen",
  controller: "controller",
  "edge-01": "nginx",
  "edge-02": "nginx",
  "edge-03": "nginx",
  haproxy: "agents/haproxy",
};

function docker(args, { timeoutMs = 900_000 } = {}) {
  return new Promise((ok, no) => {
    execFile(
      "docker",
      args,
      { cwd: DEPLOY, env: { ...process.env, MSYS_NO_PATHCONV: "1" }, maxBuffer: 64 * 1024 * 1024, timeout: timeoutMs },
      (err, stdout, stderr) => {
        if (err) {
          /*
           * compose пишет прогресс в stderr, поэтому в сообщение идут код
           * возврата и ХВОСТ вывода: начало -- это перечисление контейнеров, а
           * причина, если она есть, всегда в конце.
           */
          const tail = String(stderr || "").trimEnd().split(NL).slice(-12).join(" | ");
          const code = err.code ?? (err.killed ? "убит по таймауту" : "?");

          no(new Error(`docker ${args.slice(0, 3).join(" ")} -> ${code}: ${tail.slice(-900) || err.message}`));
          return;
        }
        ok(String(stdout));
      },
    );
  });
}

const compose = (args, opts) => docker(["compose", ...args], opts);

/** Самая свежая правка в дереве, без служебных каталогов. */
function newestMtime(dir, best = 0) {
  let rows;

  try {
    rows = readdirSync(dir, { withFileTypes: true });
  } catch {
    return best;
  }

  for (const row of rows) {
    if (row.name.startsWith(".") && row.name !== ".dockerignore") continue;
    if (row.isDirectory()) {
      if (SKIP_DIRS.has(row.name)) continue;
      best = newestMtime(join(dir, row.name), best);
      continue;
    }
    try {
      best = Math.max(best, statSync(join(dir, row.name)).mtimeMs);
    } catch {
      /* исчез между чтением каталога и stat -- не наш случай */
    }
  }

  return best;
}

/** Что поднято: сервис -> {image, imageId, running}. */
async function running() {
  const out = await compose(["ps", "--all", "--format", "{{.Service}}\\t{{.Image}}\\t{{.ID}}\\t{{.State}}"]);
  const rows = new Map();

  for (const line of out.split("\n")) {
    const [service, image, id, state] = line.trim().split("\t");
    if (!service) continue;
    if (!rows.has(service)) rows.set(service, []);
    rows.get(service).push({ image, id, state });
  }

  return rows;
}

async function imageId(name) {
  try {
    const out = await docker(["image", "inspect", name, "--format", "{{.Id}}"], { timeoutMs: 60_000 });
    return out.trim();
  } catch {
    return null;
  }
}

async function containerImageId(id) {
  try {
    const out = await docker(["inspect", id, "--format", "{{.Image}}"], { timeoutMs: 60_000 });
    return out.trim();
  } catch {
    return null;
  }
}

/** Сервисы, у которых исходники новее образа либо контейнер поднят не на нём. */
async function stale(say) {
  const live = await running();
  const build = [];
  const roll = [];

  for (const [service, rel] of Object.entries(CONTEXT)) {
    const rows = live.get(service) ?? [];
    const image = rows[0]?.image;

    if (image === undefined) {
      build.push(service);
      roll.push(service);
      continue;
    }

    const current = await imageId(image);
    const built = current === null ? 0 : Date.parse(
      (await docker(["image", "inspect", image, "--format", "{{.Created}}"], { timeoutMs: 60_000 })).trim(),
    );
    const src = newestMtime(join(ROOT, rel));

    if (src > built) {
      say(`${service}: исходники новее образа`);
      build.push(service);
      roll.push(service);
      continue;
    }

    for (const row of rows) {
      const onImage = await containerImageId(row.id);

      if (row.state !== "running" || (current !== null && onImage !== current)) {
        say(`${service}: контейнер не на текущем образе`);
        roll.push(service);
        break;
      }
    }
  }

  return { build: [...new Set(build)], roll: [...new Set(roll)] };
}

async function waitHealthy(services, { timeoutMs = 180_000, say }) {
  const until = Date.now() + timeoutMs;

  for (;;) {
    const live = await running();
    const bad = [];

    /*
     * Сервис в порядке, если у него есть работающий контейнер и ни один не
     * перезапускается. Остановленные реплики не считаются бедой: они остаются
     * от смены масштаба, и compose их не убирает.
     */
    for (const s of services) {
      const rows = live.get(s) ?? [];
      const up = rows.filter((r) => r.state === "running").length;
      const looping = rows.filter((r) => r.state === "restarting").length;

      if (rows.length === 0) bad.push(`${s}=нет контейнера`);
      else if (up === 0) bad.push(`${s}=${rows.map((r) => r.state).join(",")}`);
      else if (looping > 0) bad.push(`${s}=перезапускается`);
    }

    if (bad.length === 0) return;

    if (Date.now() > until) {
      throw new Error(`не поднялись за ${Math.round(timeoutMs / 1000)} с: ${bad.join(", ")}`);
    }

    say?.(`ждём: ${bad.join(", ")}`);
    await new Promise((r) => setTimeout(r, 3000));
  }
}

/** Реестр глаголов у поднятого контроллера против исходников. */
async function verbsMatch(ctrl) {
  const src = (await import("node:fs")).readFileSync(join(ROOT, "controller", "src", "model", "actions.ts"), "utf8");
  const want = new Set([...src.matchAll(/do: "([a-z_]+)"/g)].map((m) => m[1]));
  const res = await fetch(`${ctrl}/api/actions`, { signal: AbortSignal.timeout(15_000) });
  const body = await res.json();
  const have = new Set((body.verbs ?? []).map((v) => v.do));
  const missing = [...want].filter((v) => !have.has(v));

  return { want: want.size, have: have.size, missing };
}

/* --- миграции ------------------------------------------------------------ */

/*
 * Пустой том поднимается поставкой 1.0 (`controller/schema/01-baseline.sql` и
 * `02-shipped.sql`), и журнал применённого приезжает вместе с ней -- в нём
 * отмечен весь архив `schema/migrations`. Здесь применяется то, чего в журнале
 * нет: миграции, выпущенные после 1.0.
 *
 * Журнал может оказаться пустым только на базе старше поставки -- такую подняли
 * до того, как появился baseline. Там основание называется один раз, переменной
 * WAF_SCHEMA_BASE (номер последней уже применённой миграции).
 *
 * Файл скармливается psql изнутри контейнера (`-f`), а не пайпом с хоста:
 * PowerShell читает UTF-8 без BOM как ANSI и удваивает кириллицу в INSERT-ах.
 */
const SCHEMA_DIR = join(ROOT, "controller", "schema", "migrations");
const SCHEMA_IN_PG = "/docker-entrypoint-initdb.d/migrations";
const STAND_IN_PG = "/docker-entrypoint-initdb.d/stand";

const psql = (sql) =>
  compose(["exec", "-T", "postgres", "psql", "-U", "waf", "-d", "waf", "-tAc", sql], { timeoutMs: 120_000 });

export async function applySchema(say) {
  await psql(
    "create table if not exists waf_schema_log (file text primary key, applied_at timestamptz not null default now())",
  );

  const files = readdirSync(SCHEMA_DIR)
    .filter((f) => /^\d{3}_.*\.(sql|sh)$/.test(f))
    .sort();
  const done = new Set(
    (await psql("select file from waf_schema_log")).split("\n").map((r) => r.trim()).filter(Boolean),
  );

  if (done.size === 0) {
    const base = process.env.WAF_SCHEMA_BASE;

    if (base === undefined) {
      throw new Error(
        "журнал миграций пуст: база поднята раньше поставки 1.0, и по ней не видно, где она " +
          "остановилась. Один раз укажите номер последней уже применённой миграции: " +
          "WAF_SCHEMA_BASE=099. Всё, что новее, предполёт накатит сам. Пересозданный том " +
          "(--reset-db) приходит с заполненным журналом и вопроса не задаёт.",
      );
    }

    const seeded = files.filter((f) => f.slice(0, 3) <= String(base).padStart(3, "0"));

    for (const f of seeded) {
      await psql(`insert into waf_schema_log(file) values ('${f}') on conflict do nothing`);
    }

    say(`журнал миграций заведён, основание ${base}: отмечено применёнными ${seeded.length}`);
    seeded.forEach((f) => done.add(f));
  }

  const pending = files.filter((f) => !done.has(f) && f.endsWith(".sql"));

  if (pending.length === 0) {
    say("миграции: применять нечего");
    return;
  }

  for (const f of pending) {
    say(`накатываю ${f}`);
    await compose(
      ["exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "waf", "-d", "waf", "-f", `${SCHEMA_IN_PG}/${f}`],
      { timeoutMs: 600_000 },
    );
    await psql(`insert into waf_schema_log(file) values ('${f}') on conflict do nothing`);
  }

  say(`миграции применены: ${pending.length}`);
}

/* --- пересоздание базы --------------------------------------------------- */

/**
 * Схема применяется только на пустом томе, поэтому «накатить недостающее» =
 * пересоздать том. С пустого тома приезжает поставка (структура, страницы,
 * CRS, default-профили) и гео-сид `03-geo.sh`, то есть страны и ASN на месте.
 *
 * Стендового дерева в поставке нет: серверы, пути, апстримы и списки стенда
 * кладёт `schema/stand/stand.sql` -- здесь, отдельным шагом. Раньше они
 * приезжали сидом 024 из initdb и уезжали бы клиенту вместе со схемой.
 *
 * Данные стенда, заведённые прогонами, при этом теряются целиком. Для e2e это
 * не потеря: прогон заводит всё сам. Витрину возвращает `deploy/stand-shop.mjs`.
 */
async function resetDb(say) {
  say("останавливаю контроллер и базу");
  await compose(["stop", "controller", "postgres"]);
  await compose(["rm", "-sf", "postgres"]);

  const project = (await compose(["ls", "--format", "{{.Name}}"])).split("\n")[0]?.trim() || "deploy";
  const volume = `${project}_postgres-data`;

  say(`удаляю том ${volume}`);
  await docker(["volume", "rm", "-f", volume], { timeoutMs: 120_000 });

  say("поднимаю базу: поставка и гео-сид накатываются на пустой том, это небыстро");
  await compose(["up", "-d", "postgres"]);
  await waitHealthy(["postgres"], { timeoutMs: 600_000, say });

  /*
   * Healthy у postgres наступает до конца initdb-скриптов: ждём саму таблицу.
   * Гео ждём только там, где есть что ждать: выгрузки MaxMind не в git
   * (`schema/seed/.gitignore`), и на чистом клоне их нет.
   */
  const geo = existsSync(join(ROOT, "controller", "schema", "seed", "ip_asns.sql"));
  const until = Date.now() + 900_000;

  for (;;) {
    try {
      const out = await compose([
        "exec", "-T", "postgres", "psql", "-U", "waf", "-d", "waf", "-tAc",
        geo ? "select count(*) from ip_asns" : "select count(*) from waf_schema_log",
      ], { timeoutMs: 60_000 });

      if (Number(out.trim()) > 0) {
        say(geo ? `гео-сид применён: ASN ${out.trim()}` : `поставка применена: миграций в журнале ${out.trim()}`);
        break;
      }
    } catch {
      /* ещё катится */
    }

    if (Date.now() > until) {
      throw new Error("поставка и сид не применились за 15 минут");
    }

    await new Promise((r) => setTimeout(r, 5000));
  }

  say("накатываю стендовое дерево");
  await compose([
    "exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-q",
    "-U", "waf", "-d", "waf", "-f", `${STAND_IN_PG}/stand.sql`,
  ], { timeoutMs: 300_000 });

  /* Без выгрузки MaxMind стенду достаются три тестовые страны из фикстуры. */
  if (!geo) {
    await compose([
      "exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-q",
      "-U", "waf", "-d", "waf", "-f", `${STAND_IN_PG}/geo-test.sql`,
    ], { timeoutMs: 120_000 });

    say("гео: выгрузки MaxMind нет, положена тестовая фикстура");
  }
}

/* --- предполёт ----------------------------------------------------------- */

export async function bootstrap({ ctrl, reset = false, say = () => {} } = {}) {
  if (reset) {
    await resetDb(say);
    /* Журнал применённого приезжает заполненным вместе с поставкой. */
  }

  /* Схема раньше сборки: новый контроллер не встанет на отставшей базе. */
  await applySchema(say);

  const { build, roll } = await stale(say);

  if (build.length > 0) {
    say(`собираю: ${build.join(", ")}`);
    /*
     * Пачками и с повтором. Двадцать образов разом тянут модули Go
     * одновременно, и виртуальная сеть Docker Desktop на этом срывается:
     * `go mod tidy` падает, хотя следующая же попытка проходит.
     */
    for (let i = 0; i < build.length; i += BUILD_BATCH) {
      const batch = build.slice(i, i + BUILD_BATCH);

      try {
        await compose(["build", ...batch]);
      } catch (err) {
        /*
         * Повтор поштучно, а не той же пачкой. Сборки тяжёлые (модуль nginx
         * компилируется с -Werror, инспекторы тянут модули Go), и параллельно
         * они срываются то на памяти, то на DNS сборщика; по одной проходят.
         */
        say(`пачка сорвалась, собираю по одному: ${err.message.slice(0, 160)}`);

        for (const one of batch) {
          /*
           * Несколько попыток: сборка модуля nginx и модулей Go срывается
           * под нагрузкой машины (память сборщика, DNS), а следующая попытка
           * тех же слоёв проходит. Три -- эмпирический запас.
           */
          let last;

          for (let attempt = 1; attempt <= 3; attempt += 1) {
            try {
              await compose(["build", one]);
              last = null;
              break;
            } catch (e) {
              last = e;
              say(`    ${one}: попытка ${attempt} не удалась`);
              await new Promise((r) => setTimeout(r, 5000));
            }
          }

          if (last) throw last;

          say(`    собрано: ${one}`);
        }
      }

      say(`  собрано: ${batch.join(", ")}`);
    }
  } else {
    say("образы свежие, сборка не нужна");
  }

  if (roll.length === 0 && !reset) {
    say("всё поднято на текущих образах");
  } else {
    for (const wave of WAVES) {
      const mine = wave.services.filter((s) => roll.includes(s) || reset);

      if (mine.length === 0) continue;

      say(`${wave.name}: поднимаю ${mine.join(", ")}`);
      /* Повтор: compose иногда возвращает ненулевой код на предупреждении о томе. */
      try {
        await compose(["up", "-d", "--remove-orphans", ...mine]);
      } catch (err) {
        say(`  повтор подъёма: ${err.message.slice(0, 160)}`);
        await compose(["up", "-d", ...mine]);
      }
      await waitHealthy(mine, { say });
    }
  }

  /* Контроллер обязан отвечать: иначе дальше проверять нечего. */
  const until = Date.now() + 120_000;

  for (;;) {
    try {
      const res = await fetch(`${ctrl}/api/spaces`, { signal: AbortSignal.timeout(10_000) });
      if (res.ok) break;
    } catch {
      /* ещё поднимается */
    }

    if (Date.now() > until) {
      const log = await compose(["logs", "--tail", "25", "controller"]).catch(() => "");
      const stale = /column .* does not exist|relation .* does not exist|postgres unavailable/i.test(log);

      throw new Error(
        stale
          ? "контроллер не поднялся: схема базы отстала от controller/schema. " +
            "Миграции применяются только на пустом томе, поэтому нужен прогон с --reset-db " +
            "(том пересоздаётся, схема и гео-сид накатываются заново, данные стенда теряются).\n" +
            log.split("\n").slice(-8).join("\n")
          : `контроллер не отвечает на /api/spaces:\n${log.split("\n").slice(-8).join("\n")}`,
      );
    }

    await new Promise((r) => setTimeout(r, 3000));
  }

  const verbs = await verbsMatch(ctrl);

  if (verbs.missing.length > 0) {
    throw new Error(
      `контроллер отдаёт ${verbs.have} глаголов канала действий, в исходниках ${verbs.want}; ` +
        `нет: ${verbs.missing.join(", ")}. Раскатка не дошла до кода -- прогон остановлен, ` +
        "чтобы не мерить промежуточную сборку.",
    );
  }

  say(`соответствие: глаголов ${verbs.have}, как в исходниках`);
}
