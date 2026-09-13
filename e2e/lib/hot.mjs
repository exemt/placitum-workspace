/*
 * Наблюдение за горячим списком: кейс `hot-list` в tests/load.
 *
 * Здесь всё, что смотрит мимо API контроллера: счётчики keeper по его
 * собственному HTTP, память контейнеров через `docker stats`, журнал краёв
 * через `docker logs` и полный каталог для кодера гео -- выгрузка из базы
 * контроллера в каталог кодера на время прогона. Сам кейс, как и остальные,
 * заводится и сносится через API; сюда вынесено только то, что через API
 * не видно.
 *
 * Keeper -- WAF_KEEPER (умолчание http://127.0.0.1:8098, порт из compose).
 */

import { execFile } from "node:child_process";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DEPLOY = join(ROOT, "deploy");

export const KEEPER = process.env.WAF_KEEPER ?? "http://127.0.0.1:8098";

/** Каталог ASN кодера на стенде: compose монтирует его в /app/data/asn. */
const GEO_ASN_DIR = join(ROOT, "geo", "testdata", "asn");
const GEO_FULL = "e2e-full.tsv";

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

/* --- keeper ------------------------------------------------------------- */

/**
 * Счётчики набора у keeper: записи, отказы, дельты, снапшоты, склад. Из
 * сводки `/sets`: `/sets/<имя>` отдаёт и сам состав, на миллионе записей это
 * десятки мегабайт на каждый такт.
 */
export async function keeperSet(name) {
  const res = await fetch(`${KEEPER}/sets`);

  if (!res.ok) {
    throw new Error(`keeper ${res.status} на /sets`);
  }

  const rows = await res.json();

  return (Array.isArray(rows) ? rows : []).find((r) => r.name === name) ?? null;
}

/* --- docker ------------------------------------------------------------- */

/**
 * Память и процессор контейнеров стенда, МиБ и проценты. Одна команда на все
 * контейнеры: `docker stats` без потока отвечает секунду-две, поэтому зовётся
 * не на каждый такт наблюдения.
 */
export async function dockerStats() {
  const { stdout } = await run(
    "docker",
    ["stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}"],
    { windowsHide: true },
  );
  const out = {};

  for (const line of stdout.split("\n")) {
    const [name, mem, cpu] = line.trim().split("\t");

    if (!name) {
      continue;
    }

    out[name] = { mem: mib(mem.split("/")[0]), cpu: Number((cpu ?? "0").replace("%", "")) };
  }

  return out;
}

/** «123.4MiB», «1.2GiB», «900kB» -> МиБ. */
function mib(text) {
  const m = /([\d.]+)\s*([kKMG]i?B)/.exec(text ?? "");

  if (m === null) {
    return 0;
  }

  const n = Number(m[1]);

  switch (m[2].toUpperCase()) {
    case "GIB": case "GB": return n * 1024;
    case "KIB": case "KB": return n / 1024;
    default: return n;
  }
}

/**
 * Журнал края по одному набору с момента `since`: сколько раз просил снапшот,
 * сколько применил, сколько хвостов и изменений в них, сколько раз не хватило
 * места в зоне, сколько предупреждений и ошибок. Последний применённый снапшот
 * -- взгляд края на размер набора.
 */
export async function edgeLog(container, dataset, since) {
  const { stdout, stderr } = await run(
    "docker",
    ["logs", "--since", since, container],
    { windowsHide: true, maxBuffer: 256 * 1024 * 1024 },
  );
  const out = { snapshots: 0, applied: 0, entries: null, gone: 0, diverged: 0, noRoom: 0, warns: 0, errors: 0 };
  const needle = `"${dataset}"`;

  for (const line of `${stdout}\n${stderr}`.split("\n")) {
    if (!line.includes(needle)) {
      continue;
    }

    if (line.includes("requesting a snapshot")) out.snapshots += 1;

    /*
     * Снапшот ложится пометкой и выметанием; "in overlay" -- сколько записей
     * край держит после него, это и есть его взгляд на размер набора.
     */
    const applied = /applied snapshot .*?: (\d+) records, (\d+) swept, (\d+) in overlay/.exec(line);

    if (applied !== null) {
      out.applied += 1;
      out.entries = Number(applied[3]);
    }

    /* Пакет протух в Redis раньше, чем край его прочитал: отставание дольше журнала. */
    if (line.includes("package gone")) out.gone += 1;
    if (line.includes("diverged")) out.diverged += 1;

    if (line.includes("no room in the zone") || line.includes("did not fit")) out.noRoom += 1;
    if (line.includes("[warn]")) out.warns += 1;
    if (line.includes("[error]") || line.includes("[emerg]") || line.includes("[crit]")) out.errors += 1;
  }

  return out;
}

/* --- полный каталог для кодера гео ------------------------------------- */

/**
 * Выгрузка каталога ASN из базы контроллера в TSV кодера: `code type address
 * name`, только IPv4 -- генератор других адресов не выдаёт. Файл ложится в
 * каталог, который compose монтирует кодеру; кодер читает `.tsv` рядом с
 * учебными файлами и перезагружается сам по отпечатку каталога. Пишется под
 * именем с точкой (такие кодер пропускает) и переименовывается целиком:
 * полуписаный файл он бы прочитал как усечённую таблицу.
 */
export async function installGeoTable(say, extra = "") {
  const sql =
    "copy (select s.asn, s.type, a.address, coalesce(s.description, '') " +
    "from ip_asn_addresses a join ip_asns s on s.id = a.asn_id " +
    "where s.type = 'v4' order by s.asn) to stdout";
  const { stdout } = await run(
    "docker",
    ["compose", "exec", "-T", "postgres", "psql", "-U", "waf", "-d", "waf", "-Atc", sql],
    { cwd: DEPLOY, windowsHide: true, maxBuffer: 1024 * 1024 * 1024 },
  );
  const lines = stdout.split("\n").filter((l) => l.length > 0).length;

  if (lines < 1000) {
    throw new Error(`каталог ASN в базе контроллера пуст (${lines} строк): полную таблицу взять неоткуда`);
  }

  await mkdir(GEO_ASN_DIR, { recursive: true });
  const part = join(GEO_ASN_DIR, `.${GEO_FULL}.part`);

  await writeFile(
    part,
    `# Полный каталог ASN из базы контроллера: положен нагрузочным прогоном, снимается им же.\n${stdout}${extra}`,
  );
  await rename(part, join(GEO_ASN_DIR, GEO_FULL));
  say(`каталог ASN: ${lines} префиксов IPv4 выгружено в ${join("geo", "testdata", "asn", GEO_FULL)}`);

  return lines;
}

export async function removeGeoTable() {
  await rm(join(GEO_ASN_DIR, GEO_FULL), { force: true });
  await rm(join(GEO_ASN_DIR, `.${GEO_FULL}.part`), { force: true });
}

/** Пульс кодера из снимка присутствия: сколько систем в памяти и поколение. */
export function geoPulse(fleet) {
  const row = (fleet.services ?? []).find((s) => s.name === "geo");

  return row === undefined ? null : { asns: row.work?.asns ?? 0, gen: row.work?.gen ?? 0, age: row.age_ms ?? 0 };
}

/**
 * Дождаться, пока кодер перечитает каталог: поколение сменилось и число систем
 * прошло порог. Кодер опрашивает отпечаток раз в секунду, но полная таблица
 * собирается дольше -- ждём до `timeoutMs`.
 */
export async function waitGeo(ctx, { gen, want }, say, timeoutMs = 300_000) {
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    const p = geoPulse(await ctx.api("GET", "/api/fleet"));

    if (p !== null && p.gen !== gen && want(p.asns)) {
      say(`кодер гео: поколение ${p.gen}, систем в памяти ${p.asns}`);
      return p;
    }

    if (Date.now() > deadline) {
      throw new Error(`кодер гео не перечитал каталог за ${Math.round(timeoutMs / 1000)} с (поколение ${p?.gen}, систем ${p?.asns})`);
    }

    await wait(2000);
  }
}
