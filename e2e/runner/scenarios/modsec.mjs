#!/usr/bin/env node
/**
 * E2E modsec: 1) сброс/заливка конфига через API, 2) проверка через API, что
 * залилось, 3) трафик — вариации с телом и без тела, 4) проверка записей в
 * ClickHouse/Redis. Подробности и обоснование устройства — план
 * .cursor/plans/e2e_test_runner_modsec_733badde.plan.md и tests/runner/README.md.
 *
 *     cd tests/runner
 *     npm install
 *     npm run test:modsec
 *
 * Требует поднятый deploy/ (docker compose up -d --wait) и опубликованные
 * порты controller/haproxy/redis/clickhouse на хосте.
 */

import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { loadEnv } from "../lib/env.mjs";
import { controllerClient } from "../lib/controller.mjs";
import { auditClient } from "../lib/audit.mjs";
import { rawRequest } from "../lib/http.mjs";
import { pollUntil, sleep } from "../lib/wait.mjs";
import { Report } from "../lib/report.mjs";
import { withRedis, moduleKeys, bodyKeys } from "../lib/redis.mjs";
import { countByUriPrefixes } from "../lib/clickhouse.mjs";

// Маркер стабилен между прогонами: это позволяет фазе 1 быть no-op ("unchanged"),
// когда конфиг не менялся, и не ждать заново сходимость флота на каждый запуск.
// Уникальность конкретного прогона даёт runId в пути (/modsec-e2e/<runId>/<case>),
// не сам маркер.
const CANARY = "e2e-modsec-canary-x7q9";

// Имя записи реестра инспекторов, не имя сервиса. Маршруты /modsec-e2e*/
// объявлены как `waf_inspector modsec-e2e subject=waf.req.modsec profile=e2e`
// (deploy/nginx/nginx.conf), и в аудит едет именно оно: инспектор берёт имя из
// пришедшего сообщения, а не из своей конфигурации, потому что под каким именем
// процесс объявлен в nginx, знает только само сообщение
// (inspectors/modsec/internal/protocol/protocol.go, NewReply). Записью реестра
// маршрут отличает профили одного сервиса -- в аудите это имя и нужно.
const INSPECTOR = "modsec-e2e";

const ENGINE_TEXT = `SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine Off
SecAuditLog /dev/null
SecDebugLogLevel 0
`;

const CANARY_TEXT = `SecRule ARGS "@contains ${CANARY}" \\
    "id:9100001,phase:2,deny,status:403,msg:'e2e canary in args'"
SecRule REQUEST_HEADERS:X-E2E-Canary "@contains ${CANARY}" \\
    "id:9100002,phase:1,deny,status:403,msg:'e2e canary in header'"
`;

/*
 * expectClientStatus -- то, что реально получает клиент на проводе.
 * expectAuditStatus -- то, что модуль записывает как решение WAF в аудит.
 * Это не всегда одно и то же число:
 *
 * - На allow модуль пишет status=0: апстрим на фазе запроса ещё не ответил
 *   (docs/audit.md, "На allow фазы запроса апстрим ещё не ответил, поле 0").
 *   Реальный код клиенту при этом всё равно 200 -- echo ничего не меняет.
 * - На deny числа совпадают и на POST: страница отказа отдаётся через
 *   error_page с URI, и на этой форме nginx меняет метод на GET. Через
 *   именованный location POST доезжал до статики как есть и получал от неё
 *   405 при 403 в аудите.
 */
function locatorOf(ev, kind) {
  const raw = ev?.store?.[kind];
  if (raw === undefined || raw === null) {
    return null;
  }

  return typeof raw === "string" ? JSON.parse(raw) : raw;
}

function isArchived(loc) {
  return (
    loc?.store === "archive" &&
    loc?.driver === "s3" &&
    Boolean(loc?.key) &&
    !loc?.unavailable
  );
}

function headerValue(pairs, name) {
  const want = name.toLowerCase();
  const row = (pairs ?? []).find((p) => String(p.name ?? "").toLowerCase() === want);
  return row?.value;
}

/*
 * archived -- уехал ли набор архива в S3 на этом исходе. Флаг один на кейс, а
 * не на объект: исход смотрится один на маршрут, и `when=` решает судьбу всего
 * набора сразу (docs/directives/list/archive.md). У /modsec-e2e/ стоит
 * `when=deny`, у /modsec-e2e-body/ -- `when=` нет, то есть любой исход. Отсюда
 * единственный кейс с archived: false -- allow на when=deny: "при allow в S3
 * ничего", в записи остаётся описание объекта без адреса, а сам объект модуль
 * удаляет вместе с вердиктом (docs/audit.md, "Архив полезной нагрузки").
 */
function buildCases() {
  return [
    {
      id: "clean-no-body",
      path: "/modsec-e2e",
      method: "GET",
      expectVerdict: "allow",
      expectClientStatus: 200,
      expectAuditStatus: 0,
      expectBody: false,
      expectArgs: false,
      archiveBody: false,
      archived: false,
    },
    {
      id: "clean-with-body",
      path: "/modsec-e2e-body",
      method: "POST",
      contentType: "application/x-www-form-urlencoded",
      body: `q=hello&pad=${"a".repeat(200)}`,
      expectVerdict: "allow",
      expectClientStatus: 200,
      expectAuditStatus: 0,
      expectBody: true,
      expectArgs: false,
      archiveBody: true,
      archived: true,
    },
    {
      id: "canary-query",
      path: "/modsec-e2e",
      method: "GET",
      query: `?q=${encodeURIComponent(CANARY)}`,
      expectVerdict: "deny",
      expectClientStatus: 403,
      expectAuditStatus: 403,
      expectBody: false,
      expectArgs: true,
      archiveBody: false,
      archived: true,
    },
    {
      id: "canary-header",
      path: "/modsec-e2e",
      method: "GET",
      headers: { "X-E2E-Canary": CANARY },
      expectVerdict: "deny",
      expectClientStatus: 403,
      expectAuditStatus: 403,
      expectBody: false,
      expectArgs: false,
      archiveBody: false,
      archived: true,
    },
    {
      id: "canary-body",
      path: "/modsec-e2e-body",
      method: "POST",
      contentType: "application/x-www-form-urlencoded",
      body: `q=${encodeURIComponent(CANARY)}`,
      expectVerdict: "deny",
      expectClientStatus: 403,
      expectAuditStatus: 403,
      expectBody: true,
      expectArgs: false,
      archiveBody: true,
      archived: true,
    },
    {
      id: "canary-body-large",
      path: "/modsec-e2e-body",
      method: "POST",
      contentType: "application/x-www-form-urlencoded",
      body: `q=${encodeURIComponent(CANARY)}&pad=${"a".repeat(40_000)}`,
      expectVerdict: "deny",
      expectClientStatus: 403,
      expectAuditStatus: 403,
      expectBody: true,
      expectArgs: false,
      archiveBody: true,
      archived: true,
    },
  ];
}

async function main() {
  const env = loadEnv();
  const ctrl = controllerClient(env.controller);
  const audit = auditClient(env.controller);
  const runId = randomUUID().slice(0, 8);
  const report = new Report("modsec", runId);

  let scope = null;
  let sent = null;

  // --- Фаза 1: сброс + заливка конфига -------------------------------------
  await report.run("Фаза 1 — сброс и заливка конфига", async ({ check, note }) => {
    scope = await ctrl.scopeByName(env.spaceName);
    check(`пространство "${env.spaceName}" найдено`, typeof scope === "string", scope);

    if (typeof scope !== "string") {
      throw new Error(`нет пространства "${env.spaceName}" — контроллер не поднят или не засеян`);
    }

    const engine = await ctrl.ruleFiles.upsert(scope, {
      name: "e2e-engine",
      description: "Движок Coraza для e2e-modsec (tests/runner)",
      textRaw: ENGINE_TEXT,
    });
    check(`rule-file e2e-engine (${engine.action})`, true);

    const canary = await ctrl.ruleFiles.upsert(scope, {
      name: "e2e-canary",
      description: "Канареечные правила e2e-modsec (tests/runner)",
      textRaw: CANARY_TEXT,
    });
    check(`rule-file e2e-canary (${canary.action})`, true);

    const ruleSet = await ctrl.ruleSets.upsert(scope, {
      name: "e2e",
      description: "Профиль под /modsec-e2e/ (tests/runner)",
      fileIds: [engine.row.uuid, canary.row.uuid],
    });
    check(
      `rule-set "e2e" (${ruleSet.action}), файлов: ${ruleSet.row.files.length}`,
      ruleSet.row.files.length === 2,
    );

    sent = await ctrl.rulesSend(scope);
    check(
      'POST /rules/send вернул профиль "e2e"',
      Array.isArray(sent.profiles) && sent.profiles.includes("e2e"),
      sent.profiles,
    );
    note(`rev=${sent.rev} config_hash=${sent.config_hash}`);
  });

  if (sent === null || scope === null) {
    report.finish();
    report.printText();
    process.exitCode = report.summary().failed || 1;
    return;
  }

  // --- Фаза 2: проверка через API, что залилось ----------------------------
  await report.run("Фаза 2 — сходимость флота по API", async ({ check }) => {
    const outcome = await pollUntil(
      async () => {
        const snap = await ctrl.fleet();
        const modsecs = (snap.inspectors ?? []).filter((i) => i.name === "modsec");
        const converged =
          modsecs.length > 0 &&
          modsecs.every(
            (i) =>
              i.apply === "ok" &&
              i.config_hash === sent.config_hash &&
              (i.rev ?? 0) >= sent.rev &&
              Array.isArray(i.profiles) &&
              i.profiles.includes("e2e"),
          );
        return { ok: converged, modsecs };
      },
      { timeoutMs: 15_000, intervalMs: 500 },
    );

    const modsecs = outcome.modsecs ?? [];
    check(`во флоте есть инстансы modsec`, modsecs.length > 0, `найдено ${modsecs.length}`);

    for (const i of modsecs) {
      const good =
        i.apply === "ok" &&
        i.config_hash === sent.config_hash &&
        (i.rev ?? 0) >= sent.rev &&
        (i.profiles ?? []).includes("e2e");

      check(
        `${i.hostname ?? i.uuid} apply=${i.apply} rev=${i.rev} hash=${(i.config_hash ?? "").slice(0, 12)}`,
        good,
      );
    }

    check("флот сошёлся на присланной конфигурации до таймаута", outcome.ok);
  });

  // --- Фаза 3: трафик -------------------------------------------------------
  const cases = buildCases();
  const ua = `waf-e2e-modsec/${runId}`;

  function uriOf(c) {
    return `${c.path}/${runId}/${c.id}`;
  }

  function urlOf(c) {
    return `${env.edge}${uriOf(c)}${c.query ?? ""}`;
  }

  let redisBefore = null;

  await report.run("Фаза 3 — трафик: с телом и без тела", async ({ check, note }) => {
    redisBefore = await withRedis(env.redis, (client) => moduleKeys(client, env.nodes));

    if (redisBefore.ok) {
      note(`Redis: ключей модуля до трафика — ${redisBefore.value.length}`);
    } else {
      note(`Redis недоступен, housekeeping-проверка в фазе 4 будет пропущена (${redisBefore.error})`);
    }

    for (const c of cases) {
      const headers = { "user-agent": ua, ...(c.headers ?? {}) };

      if (c.contentType !== undefined) {
        headers["content-type"] = c.contentType;
      }

      const res = await rawRequest(urlOf(c), { method: c.method, headers, body: c.body });
      c.gotStatus = res.status;

      check(
        `${c.id}: ${c.method} ${urlOf(c).replace(env.edge, "")} -> ${res.status}`,
        res.status === c.expectClientStatus,
        res.status === c.expectClientStatus ? undefined : `ожидался ${c.expectClientStatus}`,
      );
    }
  });

  // --- Фаза 4: записи в хранилищах ------------------------------------------
  await sleep(1_500);

  await report.run("Фаза 4 — записи в хранилищах", async ({ check, note }) => {
    // /api/search/audit фильтрует uri через "contains", а не точное
    // совпадение (logger/internal/query/query.go). Тянем записи прогона
    // по runId и сверяем uri на точное совпадение сами.
    const found = await pollUntil(
      async () => {
        const { items } = await audit.list({ uri: runId, limit: "50" });
        const byUri = new Map(
          items.filter((ev) => ev.uri.includes(`/${runId}/`)).map((ev) => [ev.uri, ev]),
        );
        return { ok: byUri.size >= cases.length, byUri };
      },
      { timeoutMs: 10_000, intervalMs: 500 },
    );

    check(
      `аудит: найдено ${found.byUri.size}/${cases.length} записей прогона ${runId}`,
      found.ok,
    );

    for (const c of cases) {
      const uriPath = uriOf(c);
      const ev = found.byUri.get(uriPath);

      if (!check(`${c.id}: запись аудита найдена (uri=${uriPath})`, ev !== undefined)) {
        continue;
      }

      check(
        `${c.id}: verdict в аудите — ${c.expectVerdict}`,
        ev.verdict === c.expectVerdict,
        { got: ev.verdict, want: c.expectVerdict },
      );

      check(
        `${c.id}: status в аудите — решение модуля, а не ответ клиенту`,
        ev.status === c.expectAuditStatus,
        { got: ev.status, want: c.expectAuditStatus },
      );

      const hasBody = (ev.body_size ?? 0) > 0;
      check(
        `${c.id}: body_size ${c.expectBody ? "> 0" : "== 0"} (получено ${ev.body_size ?? 0})`,
        hasBody === c.expectBody,
      );

      check(
        `${c.id}: модуль опрашивал ${INSPECTOR}`,
        Array.isArray(ev.inspectors) && ev.inspectors.includes(INSPECTOR),
        ev.inspectors,
      );

      const kinds = ["headers"];
      if (c.expectArgs) {
        kinds.push("args");
      }
      if (c.archiveBody) {
        kinds.push("body");
      }

      // Локаторы едут не сразу: адрес в записи подменяет агент, уже после
      // публикации. Ждём ожидаемого состояния, а не первого ответа поиска.
      const archived = await pollUntil(
        async () => {
          const { items } = await audit.list({ uri: uriPath, limit: "5" });
          const row = items.find((item) => item.uri === uriPath);
          const locs = Object.fromEntries(kinds.map((kind) => [kind, locatorOf(row, kind)]));
          const ok = c.archived
            ? kinds.every((kind) => isArchived(locs[kind]))
            : kinds.every((kind) => locs[kind] !== null && !isArchived(locs[kind]));
          return { ok, row, locs };
        },
        { timeoutMs: 8_000, intervalMs: 400 },
      );

      for (const kind of kinds) {
        const loc = archived.locs?.[kind];

        if (c.archived) {
          check(`${c.id}: ${kind} в архиве S3 (ttl=1h, без archive_error)`, isArchived(loc), loc);
        } else {
          // when=deny при allow: объект удалён вместе с вердиктом, в записи
          // осталось описание без адреса -- size есть, store/driver/key нет.
          check(
            `${c.id}: ${kind} не в архиве, но описан (when=deny при allow)`,
            loc !== null && !isArchived(loc),
            loc,
          );
        }
      }

      // Содержимое читается только из архива: не уехавший объект модуль уже
      // удалил, и поиск на него отвечает недоступностью, а не байтами.
      if (c.archived && archived.ok) {
        const hdr = await audit.content(archived.row.node, archived.row.ray, "headers");
        const uaGot = headerValue(hdr.headers, "user-agent");
        check(
          `${c.id}: заголовки читаются и содержат User-Agent прогона`,
          hdr.available === true && uaGot === ua,
          { available: hdr.available, reason: hdr.reason, count: hdr.count, ua: uaGot },
        );

        if (c.id === "canary-header") {
          check(
            `${c.id}: в заголовках есть X-E2E-Canary=${CANARY}`,
            headerValue(hdr.headers, "x-e2e-canary") === CANARY,
            headerValue(hdr.headers, "x-e2e-canary"),
          );
        }

        if (c.expectArgs) {
          const qs = await audit.content(archived.row.node, archived.row.ray, "args");
          const raw = qs.raw ?? "";
          check(
            `${c.id}: query читается и содержит маркер`,
            qs.available === true && raw.includes(CANARY),
            { available: qs.available, reason: qs.reason, raw },
          );
        }

        if (c.archiveBody) {
          const payload = await audit.content(archived.row.node, archived.row.ray, "body");
          check(
            `${c.id}: тело читается и совпадает с отправленным`,
            payload.available === true && payload.text === c.body,
            {
              available: payload.available,
              reason: payload.reason,
              size: payload.size,
              text: (payload.text ?? "").slice(0, 80),
            },
          );
        }
      }

      // "clean": true -- инспектор отчитался, что смотрел и не нашёл; это не
      // находка, а рабочая строка advisory-отчёта, code/rule у неё нет.
      const { items: finds } = await audit.findings(ev.node, ev.ray);
      const modsecFinding = finds.find(
        (f) => f.inspector === INSPECTOR && f.code !== undefined && f.code !== "",
      );

      if (c.id.startsWith("canary-")) {
        check(`${c.id}: есть находка ${INSPECTOR} с правилом`, modsecFinding !== undefined, {
          rule: modsecFinding?.rule,
          code: modsecFinding?.code,
        });
      } else {
        check(`${c.id}: находок ${INSPECTOR} нет (чистый запрос)`, modsecFinding === undefined);
      }
    }

    try {
      const chCount = await countByUriPrefixes(env, [
        `/modsec-e2e/${runId}/`,
        `/modsec-e2e-body/${runId}/`,
      ]);
      check(
        `ClickHouse напрямую: записей по прогону ${runId}`,
        chCount >= cases.length,
        `получено ${chCount}, ожидалось >= ${cases.length}`,
      );
    } catch (err) {
      note(`ClickHouse недоступен напрямую, проверка пропущена: ${err.message}`);
    }

    if (redisBefore?.ok) {
      const redisAfter = await withRedis(env.redis, (client) => moduleKeys(client, env.nodes));

      if (redisAfter.ok) {
        check(
          `Redis: ключи модуля сняты после архива (было ${redisBefore.value.length}, стало ${redisAfter.value.length})`,
          redisAfter.value.length <= redisBefore.value.length,
        );

        const leftoverBody = bodyKeys(redisAfter.value).length - bodyKeys(redisBefore.value).length;
        check(`Redis: ключей тела не осталось (дельта ${leftoverBody})`, leftoverBody <= 0);
      } else {
        note(`Redis недоступен на повторном опросе: ${redisAfter.error}`);
      }
    }
  });

  report.finish();
  report.printText();

  const written = await report.writeFiles(fileURLToPath(new URL("../reports/", import.meta.url)));
  process.stdout.write(`\nотчёт: ${written.json}\n       ${written.txt}\n`);

  process.exitCode = report.summary().failed;
}

main().catch((err) => {
  process.stderr.write(`modsec: непойманная ошибка: ${err instanceof Error ? err.stack : err}\n`);
  process.exitCode = 1;
});
