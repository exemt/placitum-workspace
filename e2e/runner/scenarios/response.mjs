#!/usr/bin/env node
/**
 * E2E фазы ответа: тело ответа снимается, инспектируется, уезжает в превью
 * записи и в архив -- и всё это видно по записи фазы `response`.
 *
 *     cd tests/runner
 *     npm run test:response
 *
 * Маршруты -- deploy/nginx/nginx.conf, /modsec-e2e-rsp/ и
 * /modsec-e2e-rsp-always/: echo печатает заголовки запроса в теле ответа
 * открытым текстом (тело запроса -- base64, поэтому маркер едет заголовком),
 * и маркер в X-E2E-Canary оказывается маркером в теле ответа. Правило
 * профиля e2e-rsp -- phase:4 по RESPONSE_BODY: в запросе оно его не найдёт,
 * и это ровно то, что отличает отказ фазы ответа от отказа фазы запроса.
 *
 * Что проверяется, по записи каждой фазы отдельно (общий ray, две записи):
 *
 * - запись `response` есть, verdict и status -- решение модуля (на allow
 *   status=0, как и у фазы запроса: модуль ничего не подменял);
 * - body_size > 0 и body_preview несёт маркер (waf_preview response body=2k);
 * - архив ответа: when=deny -- только у отказа, без when -- у обоих исходов;
 * - when=deny у запроса срабатывает и на отказ фазы ответа (archive.md);
 * - содержимое тела ответа читается по фазе и совпадает с тем, что отдал echo;
 * - находка modsec лежит в записи фазы ответа, а у запроса находок нет.
 */

import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { loadEnv } from "../lib/env.mjs";
import { controllerClient } from "../lib/controller.mjs";
import { auditClient } from "../lib/audit.mjs";
import { pollUntil, sleep } from "../lib/wait.mjs";
import { Report } from "../lib/report.mjs";

const CANARY = "e2e-response-canary-r4v7";

const ENGINE_TEXT = `SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html application/json
SecResponseBodyLimit 1048576
SecAuditEngine Off
SecAuditLog /dev/null
SecDebugLogLevel 0
`;

// deny прямо в правиле, а не через score: исход фазы ответа должен зависеть
// от одного правила, а не от порога маршрута.
const CANARY_TEXT = `SecRule RESPONSE_BODY "@contains ${CANARY}" \\
    "id:9200001,phase:4,deny,status:403,msg:'e2e canary leaked in the response body'"
`;

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

function buildCases() {
  return [
    {
      id: "rsp-clean-deny-only",
      path: "/modsec-e2e-rsp",
      body: `q=hello&pad=${"a".repeat(120)}`,
      expectVerdict: "allow",
      expectClientStatus: 200,
      expectAuditStatus: 0,
      archiveResponse: false,
      archiveRequest: false,
    },
    {
      id: "rsp-canary-deny-only",
      path: "/modsec-e2e-rsp",
      body: `q=hello&pad=${"b".repeat(120)}`,
      canary: true,
      expectVerdict: "deny",
      expectClientStatus: 403,
      expectAuditStatus: 403,
      archiveResponse: true,
      archiveRequest: true,
    },
    {
      id: "rsp-clean-always",
      path: "/modsec-e2e-rsp-always",
      body: `q=hello&pad=${"c".repeat(120)}`,
      expectVerdict: "allow",
      expectClientStatus: 200,
      expectAuditStatus: 0,
      archiveResponse: true,
      archiveRequest: true,
    },
    {
      id: "rsp-canary-always",
      path: "/modsec-e2e-rsp-always",
      body: `q=hello&pad=${"d".repeat(120)}`,
      canary: true,
      expectVerdict: "deny",
      expectClientStatus: 403,
      expectAuditStatus: 403,
      archiveResponse: true,
      archiveRequest: true,
    },
  ];
}

async function main() {
  const env = loadEnv();
  const ctrl = controllerClient(env.controller);
  const audit = auditClient(env.controller);
  const runId = randomUUID().slice(0, 8);
  const report = new Report("response", runId);

  let scope = null;
  let sent = null;

  await report.run("Фаза 1 — заливка профиля e2e-rsp", async ({ check, note }) => {
    scope = await ctrl.scopeByName(env.spaceName);
    check(`пространство "${env.spaceName}" найдено`, typeof scope === "string", scope);
    if (typeof scope !== "string") {
      throw new Error(`нет пространства "${env.spaceName}"`);
    }

    const engine = await ctrl.ruleFiles.upsert(scope, {
      name: "e2e-rsp-engine",
      description: "Движок Coraza с телом ответа для e2e-response (tests/runner)",
      textRaw: ENGINE_TEXT,
    });
    check(`rule-file e2e-rsp-engine (${engine.action})`, true);

    const canary = await ctrl.ruleFiles.upsert(scope, {
      name: "e2e-rsp-canary",
      description: "Канарейка phase:4 по RESPONSE_BODY (tests/runner)",
      textRaw: CANARY_TEXT,
    });
    check(`rule-file e2e-rsp-canary (${canary.action})`, true);

    const ruleSet = await ctrl.ruleSets.upsert(scope, {
      name: "e2e-rsp",
      description: "Профиль под /modsec-e2e-rsp/ (tests/runner)",
      fileIds: [engine.row.uuid, canary.row.uuid],
    });
    check(`rule-set "e2e-rsp" (${ruleSet.action})`, ruleSet.row.files.length === 2);

    sent = await ctrl.rulesSend(scope);
    check(
      'POST /rules/send вернул профиль "e2e-rsp"',
      Array.isArray(sent.profiles) && sent.profiles.includes("e2e-rsp"),
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

  await report.run("Фаза 2 — сходимость флота", async ({ check }) => {
    const outcome = await pollUntil(
      async () => {
        const snap = await ctrl.fleet();
        const modsecs = (snap.inspectors ?? []).filter((i) => i.name === "modsec");
        const ok =
          modsecs.length > 0 &&
          modsecs.every(
            (i) =>
              i.apply === "ok" &&
              i.config_hash === sent.config_hash &&
              (i.profiles ?? []).includes("e2e-rsp"),
          );
        return { ok, modsecs };
      },
      { timeoutMs: 15_000, intervalMs: 500 },
    );
    check(`инстансов modsec: ${outcome.modsecs?.length ?? 0}`, (outcome.modsecs?.length ?? 0) > 0);
    check("флот сошёлся на e2e-rsp", outcome.ok);
  });

  const cases = buildCases();
  const ua = `waf-e2e-response/${runId}`;
  const uriOf = (c) => `${c.path}/${runId}/${c.id}`;

  await report.run("Фаза 3 — трафик: маркер в теле ответа", async ({ check, note }) => {
    for (const c of cases) {
      // Не rawRequest: тело ответа здесь нужно -- по нему видно, дошёл ли
      // маркер до клиента и совпадает ли архив с тем, что отдал echo.
      const headers = { "user-agent": ua, "content-type": "application/x-www-form-urlencoded" };
      if (c.canary) {
        headers["x-e2e-canary"] = CANARY;
      }
      const raw = await fetch(`${env.edge}${uriOf(c)}`, {
        method: "POST",
        headers,
        body: c.body,
        signal: AbortSignal.timeout(10_000),
      });
      c.gotStatus = raw.status;
      c.gotText = await raw.text();

      check(
        `${c.id}: POST ${uriOf(c)} -> ${raw.status}`,
        raw.status === c.expectClientStatus,
        raw.status === c.expectClientStatus ? undefined : `ожидался ${c.expectClientStatus}`,
      );

      if (c.expectVerdict === "deny") {
        check(
          `${c.id}: маркер не дошёл до клиента`,
          !c.gotText.includes(CANARY),
          c.gotText.slice(0, 120),
        );
      } else {
        note(`${c.id}: echo отдал ${c.gotText.length} байт`);
      }
    }
  });

  await sleep(1_500);

  await report.run("Фаза 4 — записи фазы ответа", async ({ check }) => {
    const found = await pollUntil(
      async () => {
        const { items } = await audit.list({ uri: runId, phase: "response", limit: "50" });
        const byUri = new Map(
          items.filter((ev) => ev.uri.includes(`/${runId}/`)).map((ev) => [ev.uri, ev]),
        );
        return { ok: byUri.size >= cases.length, byUri };
      },
      { timeoutMs: 10_000, intervalMs: 500 },
    );
    check(`аудит: записей фазы response ${found.byUri.size}/${cases.length}`, found.ok);

    const { items: reqItems } = await audit.list({ uri: runId, phase: "request", limit: "50" });
    const reqByUri = new Map(reqItems.map((ev) => [ev.uri, ev]));

    for (const c of cases) {
      const uri = uriOf(c);
      const ev = found.byUri.get(uri);
      if (!check(`${c.id}: запись response найдена`, ev !== undefined)) {
        continue;
      }

      check(`${c.id}: phase=response`, ev.phase === "response", ev.phase);
      check(`${c.id}: verdict ${c.expectVerdict}`, ev.verdict === c.expectVerdict, ev.verdict);
      check(`${c.id}: status ${c.expectAuditStatus}`, ev.status === c.expectAuditStatus, ev.status);
      check(`${c.id}: body_size > 0 (${ev.body_size ?? 0})`, (ev.body_size ?? 0) > 0);
      check(
        `${c.id}: модуль опрашивал modsec-e2e-rsp на фазе ответа`,
        Array.isArray(ev.inspectors) && ev.inspectors.includes("modsec-e2e-rsp"),
        ev.inspectors,
      );

      // Превью -- у одиночной записи, список его не несёт.
      const full = await audit.get(ev.node, ev.ray, "response");
      const preview = full?.body_preview ?? "";
      check(
        `${c.id}: body_preview ${c.expectVerdict === "deny" ? "несёт" : "без"} маркер(а)`,
        preview.length > 0 && preview.includes(CANARY) === (c.expectVerdict === "deny"),
        preview.slice(0, 120),
      );

      const req = reqByUri.get(uri);
      check(`${c.id}: парная запись request с тем же ray`, req !== undefined && req.ray === ev.ray);

      // Архив: локаторы подменяет агент, ждём.
      const archived = await pollUntil(
        async () => {
          const { items } = await audit.list({ uri, phase: "response", limit: "5" });
          const row = items.find((item) => item.uri === uri);
          const body = locatorOf(row, "body");
          const headers = locatorOf(row, "headers");
          const ok = c.archiveResponse
            ? isArchived(body) && isArchived(headers)
            : body !== null && !isArchived(body);
          return { ok, row, body, headers };
        },
        { timeoutMs: 8_000, intervalMs: 400 },
      );

      if (c.archiveResponse) {
        check(`${c.id}: тело ответа в архиве S3`, isArchived(archived.body), archived.body);
        check(`${c.id}: заголовки ответа в архиве S3`, isArchived(archived.headers), archived.headers);

        const payload = await audit.content(ev.node, ev.ray, "body", "response");
        const text = payload.text ?? "";
        if (c.expectVerdict === "deny") {
          // Клиент получил страницу отказа; в архиве -- то, что отдал апстрим,
          // и сравнить его можно только с тем, что в него положили: маркером
          // и путём echo.
          check(
            `${c.id}: тело ответа читается по фазе и несёт ответ апстрима с маркером`,
            payload.available === true &&
              text.includes(CANARY) &&
              text.includes(uriOf(c).replace(c.path, "/echo")),
            { available: payload.available, reason: payload.reason, size: payload.size },
          );
        } else {
          check(
            `${c.id}: тело ответа читается по фазе и совпадает с ответом echo`,
            payload.available === true && text.length > 0 && c.gotText === text,
            { available: payload.available, reason: payload.reason, size: payload.size },
          );
        }

        const hdr = await audit.content(ev.node, ev.ray, "headers", "response");
        const names = (hdr.headers ?? []).map((p) => String(p.name).toLowerCase());
        check(
          `${c.id}: заголовки ответа читаются (content-type апстрима)`,
          hdr.available === true && names.includes("content-type"),
          { available: hdr.available, reason: hdr.reason, names },
        );
      } else {
        check(
          `${c.id}: тело ответа не архивировано (when=deny при allow)`,
          archived.body !== null && !isArchived(archived.body),
          archived.body,
        );
      }

      if (req !== undefined) {
        const reqArchived = await pollUntil(
          async () => {
            const { items } = await audit.list({ uri, phase: "request", limit: "5" });
            const row = items.find((item) => item.uri === uri);
            const headers = locatorOf(row, "headers");
            return { ok: isArchived(headers) === c.archiveRequest, headers };
          },
          { timeoutMs: 8_000, intervalMs: 400 },
        );
        check(
          `${c.id}: запрос ${c.archiveRequest ? "в архиве" : "не в архиве"} (when=deny смотрится по последней фазе)`,
          reqArchived.ok,
          reqArchived.headers,
        );
      }

      // Находки по ray -- одной плоскостью, обе фазы; фазу отделяем сами.
      const { items: allFinds } = await audit.findings(ev.node, ev.ray);
      const finding = allFinds.find(
        (f) => f.phase === "response" && f.profile === "e2e-rsp" && f.code,
      );
      if (c.expectVerdict === "deny") {
        check(`${c.id}: находка modsec в записи фазы ответа`, finding !== undefined, {
          rule: finding?.rule,
          code: finding?.code,
        });
      } else {
        check(`${c.id}: находок на фазе ответа нет`, finding === undefined);
      }

      if (req !== undefined) {
        const reqFinding = allFinds.find(
          (f) => f.phase === "request" && f.profile === "e2e-rsp" && f.code,
        );
        check(`${c.id}: на фазе запроса находок нет (правило phase:4)`, reqFinding === undefined);
      }
    }
  });

  report.finish();
  report.printText();

  const written = await report.writeFiles(fileURLToPath(new URL("../reports/", import.meta.url)));
  process.stdout.write(`\nотчёт: ${written.json}\n       ${written.txt}\n`);
  process.exitCode = report.summary().failed ? 1 : 0;
}

main().catch((err) => {
  process.stderr.write(`${err?.stack ?? err}\n`);
  process.exitCode = 1;
});
