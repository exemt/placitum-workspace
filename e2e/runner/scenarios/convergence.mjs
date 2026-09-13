#!/usr/bin/env node
/**
 * E2E сходимости: механизм поиска расхождений проверяется на живом контуре.
 *
 * Проверяется не «хеши совпали», а четыре утверждения, каждое из которых
 * ломается по-своему:
 *
 *   1. Правка одного канала делает грязным ровно его. Изоляция каналов --
 *      единственное, что отличает работающий индикатор от того, который через
 *      неделю отключают: индикатор, кричащий на всё сразу, не читают.
 *   2. `send` двигает изданное, а хеш плана совпадает с опубликованным. Если
 *      план и рассылка считают по-разному, панель врёт в одну сторону, а флот
 *      работает в другую.
 *   3. Флот сходится, и это видно тем же документом. «Приехало».
 *   4. Правила действительно применились -- канареечным трафиком. Без этого
 *      пункт 3 доказывает только то, что все повторили одно число.
 *
 * Плюс отрицательные проверки: битое поколение не встаёт и не роняет боевую
 * конфигурацию; инспектор без канала не считается расхождением.
 *
 *     cd tests/runner
 *     npm install
 *     npm run test:convergence
 *
 * Требует поднятый deploy/ (docker compose up -d --wait).
 */

import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { loadEnv } from "../lib/env.mjs";
import { controllerClient } from "../lib/controller.mjs";
import { rawRequest } from "../lib/http.mjs";
import { pollUntil } from "../lib/wait.mjs";
import { Report } from "../lib/report.mjs";

/*
 * Маркер стабилен между прогонами: фаза заливки тогда бывает no-op, и флоту
 * не приходится сходиться заново на каждый запуск. Уникальность прогона даёт
 * runId в пути, не маркер.
 */
const CANARY = "e2e-convergence-canary-p4w2";

const ENGINE_TEXT = `SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine Off
SecAuditLog /dev/null
SecDebugLogLevel 0
`;

function canaryText(marker) {
  return `SecRule ARGS "@contains ${marker}" \\
    "id:9200001,phase:2,deny,status:403,msg:'e2e convergence canary'"
`;
}

/** Поколение, которое обязано не собраться: у SecLang нет такой директивы. */
const BROKEN_TEXT = `SecRuleEngine On
SecRule ARGS "@contains x" "id:9200002,phase:2,deny,chain,skipAfter:NOWHERE"
SecNoSuchDirectiveHere on
`;

const CHANNELS = ["nginx", "agent", "rules", "ip", "auth", "captcha"];

/*
 * Маршрут /modsec-e2e/ ходит к инспектору `modsec-e2e`, у которого в реестре
 * стоит `profile=e2e`. Свой набор здесь заводить бесполезно: профиль, на
 * который не ссылается ни один маршрут, доедет до реплик и не встретит ни
 * одного запроса, а фаза трафика окажется проверкой пустоты.
 */
const PROFILE = "e2e";
const ROUTE = "/modsec-e2e";

/**
 * Дописать файлы в набор, не выкинув чужие. `ruleSets.upsert` заменяет состав
 * целиком, а этот набор делят несколько сценариев.
 */
async function attachToProfile(ctrl, scope, fileIds) {
  const rows = await ctrl.ruleSets.list(scope);
  const found = rows.find((row) => row.name === PROFILE);

  if (found === undefined) {
    return ctrl.ruleSets.create(scope, {
      name: PROFILE,
      description: "Профиль под /modsec-e2e/ (tests/runner)",
      files: fileIds,
    });
  }

  const full = await ctrl.ruleSets.get(scope, found.uuid);
  const current = full.files.map((row) => row.uuid);
  const missing = fileIds.filter((id) => !current.includes(id));

  if (missing.length === 0) {
    return full;
  }

  return ctrl.ruleSets.update(scope, found.uuid, {
    name: full.name,
    description: full.description,
    files: [...current, ...missing],
  });
}

function channelOf(snap, id) {
  return (snap.channels ?? []).find((row) => row.id === id) ?? null;
}

function states(snap) {
  return Object.fromEntries(
    (snap.channels ?? []).map((row) => [row.id, row.state]),
  );
}

async function main() {
  const env = loadEnv();
  const ctrl = controllerClient(env.controller);
  const runId = randomUUID().slice(0, 8);
  const report = new Report("convergence", runId);

  let scope = null;
  let engineId = null;
  let canaryId = null;

  /* --- Фаза 1: снимок отвечает и описывает все каналы -------------------- */

  await report.run("Фаза 1 — снимок сходимости", async ({ check, note }) => {
    scope = await ctrl.scopeByName(env.spaceName);
    check(`пространство "${env.spaceName}" найдено`, scope !== null, scope);

    if (scope === null) {
      return;
    }

    const snap = await ctrl.convergence.refresh(scope);

    check(
      "в снимке ровно шесть каналов",
      (snap.channels ?? []).length === CHANNELS.length,
      (snap.channels ?? []).map((row) => row.id),
    );

    for (const id of CHANNELS) {
      const row = channelOf(snap, id);
      check(`канал ${id} есть и знает свой ключ KV`, row?.key?.startsWith("policy/") === true, row?.key);
    }

    // Инспектор адреса профили с шины не забирает: его отпечаток каталога
    // контроллер повторить не может, и сверять их нельзя ни при каких условиях.
    const ip = channelOf(snap, "ip");
    check("канал адреса помечен как недоставляемый", ip?.delivered === false);
    check(
      "и потому не показывает расхождения",
      ip?.state !== "failed" && ip?.state !== "foreign",
      ip?.state,
    );

    note(`лампа ${snap.lamp}, худшее ${snap.worst}: ${JSON.stringify(states(snap))}`);
  });

  if (scope === null) {
    report.finish();
    report.printText();
    process.exitCode = 1;
    return;
  }

  /* --- Фаза 2: правка канала делает грязным ровно его --------------------- */

  await report.run("Фаза 2 — изоляция каналов", async ({ check, note }) => {
    const before = states(await ctrl.convergence.refresh(scope));

    const engine = await ctrl.ruleFiles.upsert(scope, {
      name: "e2e-conv-engine",
      description: "Движок Coraza для e2e-convergence (tests/runner)",
      textRaw: ENGINE_TEXT,
    });
    engineId = engine.row.uuid;

    // Текст канарейки уникален для прогона: иначе повторный запуск не создаёт
    // расхождения вовсе и фаза проверяет пустоту.
    const canary = await ctrl.ruleFiles.upsert(scope, {
      name: "e2e-conv-canary",
      description: "Канареечное правило e2e-convergence (tests/runner)",
      textRaw: `${canaryText(CANARY)}# run ${runId}\n`,
    });
    canaryId = canary.row.uuid;

    const set = await attachToProfile(ctrl, scope, [engineId, canaryId]);
    const inSet = set.files.map((row) => row.uuid);
    check(
      `канареечный файл в профиле ${PROFILE}`,
      inSet.includes(engineId) && inSet.includes(canaryId),
      inSet.length,
    );

    const after = states(await ctrl.convergence.refresh(scope));

    check("канал правил стал грязным", after.rules === "dirty", after.rules);

    // Вот это и есть главная проверка фазы: правка правил не должна попасть в
    // канон соседних каналов.
    for (const id of CHANNELS.filter((row) => row !== "rules")) {
      check(
        `канал ${id} не тронут правкой правил`,
        after[id] === before[id],
        `${before[id]} -> ${after[id]}`,
      );
    }

    note(JSON.stringify(after));
  });

  /* --- Фаза 3: send двигает изданное, план совпадает с опубликованным ----- */

  let sentHash = null;

  await report.run("Фаза 3 — рассылка", async ({ check, note }) => {
    const planned = await ctrl.convergence.channel(scope, "rules");
    const draftHash = planned.draft?.hash ?? null;
    check("план канала правил посчитан", draftHash !== null, draftHash);

    const sent = await ctrl.convergence.send(scope, "rules");
    sentHash = sent.config_hash ?? null;

    check(
      "опубликован ровно тот хеш, который показывал план",
      sentHash === draftHash,
      { plan: draftHash, sent: sentHash },
    );

    const after = await ctrl.convergence.channel(scope, "rules");

    check(
      "изданное поколение сдвинулось на присланное",
      after.desired?.hash === sentHash,
      after.desired,
    );
    check("канал перестал быть грязным", after.dirty === false, after.state);

    note(`rev=${sent.rev} hash=${sentHash}`);
  });

  /* --- Фаза 4: флот сошёлся, и это видно тем же документом ---------------- */

  await report.run("Фаза 4 — сходимость флота", async ({ check, note }) => {
    const outcome = await pollUntil(
      async () => {
        const row = await ctrl.convergence.channel(scope, "rules");
        return { ok: row.state === "ok", row };
      },
      { timeoutMs: 20_000, intervalMs: 500 },
    );

    const row = outcome.row;

    check("канал правил сошёлся до таймаута", outcome.ok, row?.state);
    check(
      "у всех реплик поколение с шины",
      (row?.counts?.ok ?? 0) > 0 &&
        (row?.counts?.stale ?? 0) === 0 &&
        (row?.counts?.pending ?? 0) === 0,
      row?.counts,
    );
    check(
      "чужих поколений на репликах нет",
      (row?.counts?.foreign ?? 0) === 0,
      row?.consumers?.filter((c) => c.state === "foreign"),
    );

    for (const c of row?.consumers ?? []) {
      note(`${c.label}: ${c.state} rev=${c.rev ?? "—"}`);
    }
  });

  /* --- Фаза 5: правила реально работают ----------------------------------- */

  await report.run("Фаза 5 — трафик подтверждает применение", async ({ check }) => {
    // Совпавшие хеши доказывают только то, что все повторили одно число.
    // Работает поколение или нет, знает единственный источник -- трафик.
    const clean = await rawRequest(`${env.edge}${ROUTE}/${runId}/clean`, {
      headers: { "User-Agent": `waf-e2e-convergence/${runId}` },
    });
    check("чистый запрос проходит", clean.status === 200, clean.status);

    const dirty = await rawRequest(
      `${env.edge}${ROUTE}/${runId}/canary?q=${encodeURIComponent(CANARY)}`,
      { headers: { "User-Agent": `waf-e2e-convergence/${runId}` } },
    );
    check(
      "канареечный запрос заблокирован присланным правилом",
      dirty.status === 403,
      dirty.status,
    );
  });

  /* --- Фаза 6: битое поколение не встаёт и не роняет боевое --------------- */

  await report.run("Фаза 6 — отказ применения", async ({ check, note }) => {
    const good = await ctrl.convergence.channel(scope, "rules");
    const goodHash = good.desired?.hash ?? null;

    await ctrl.ruleFiles.upsert(scope, {
      name: "e2e-conv-canary",
      description: "Заведомо битый профиль e2e-convergence (tests/runner)",
      textRaw: BROKEN_TEXT,
    });

    const sent = await ctrl.convergence.send(scope, "rules");
    note(`битое поколение издано: rev=${sent.rev}`);

    const outcome = await pollUntil(
      async () => {
        const row = await ctrl.convergence.channel(scope, "rules");
        return { ok: row.state === "failed", row };
      },
      { timeoutMs: 20_000, intervalMs: 500 },
    );

    check(
      "поколение не встало и канал это показывает",
      outcome.ok,
      outcome.row?.state,
    );
    check(
      "реплики докладывают отказ, а не тишину",
      (outcome.row?.counts?.failed ?? 0) > 0,
      outcome.row?.counts,
    );

    // Главное в этой фазе: отказ применения не должен пропускать трафик.
    // Реплика обязана продолжать работать по прежнему набору.
    const still = await rawRequest(
      `${env.edge}${ROUTE}/${runId}/after-broken?q=${encodeURIComponent(CANARY)}`,
      { headers: { "User-Agent": `waf-e2e-convergence/${runId}` } },
    );
    check(
      "боевая конфигурация осталась прежней: канарейка всё ещё блокируется",
      still.status === 403,
      still.status,
    );

    /* --- откат: вернуть рабочий состав ---------------------------------- */

    await ctrl.ruleFiles.upsert(scope, {
      name: "e2e-conv-canary",
      description: "Канареечное правило e2e-convergence (tests/runner)",
      textRaw: `${canaryText(CANARY)}# run ${runId}\n`,
    });

    const back = await ctrl.convergence.send(scope, "rules");

    check(
      "откат вернул прежнее поколение тем же хешем",
      back.config_hash === goodHash,
      { before: goodHash, after: back.config_hash },
    );

    const recovered = await pollUntil(
      async () => {
        const row = await ctrl.convergence.channel(scope, "rules");
        return { ok: row.state === "ok", row };
      },
      { timeoutMs: 20_000, intervalMs: 500 },
    );

    check("флот вернулся в сошедшееся состояние", recovered.ok, recovered.row?.state);
  });

  /* --- Фаза 7: инспекторы без своего канала не считаются расхождением ----- */

  await report.run("Фаза 7 — чужие инспекторы", async ({ check, note }) => {
    const snap = await ctrl.fleet();
    const rows = snap.inspectors ?? [];

    check("во флоте есть инспекторы", rows.length > 0, rows.length);

    const managed = new Set(["modsec", "auth", "captcha"]);
    const bogus = rows.filter(
      (row) => !managed.has(row.name) && row.name !== "ip" && row.drift !== "unknown",
    );

    check(
      "инспектор без канала помечен unknown, а не расхождением",
      bogus.length === 0,
      bogus.map((row) => `${row.name}=${row.drift}`),
    );

    const ip = rows.filter((row) => row.name === "ip");
    check(
      "инспектор адреса помечен unmanaged, а не drift",
      ip.every((row) => row.drift === "unmanaged"),
      ip.map((row) => `${row.hostname}=${row.drift}`),
    );

    note(rows.map((row) => `${row.name}:${row.drift}`).join(" "));
  });

  report.finish();
  report.printText();
  await report.writeFiles(fileURLToPath(new URL("../reports", import.meta.url)));

  process.exitCode = report.summary().failed === 0 ? 0 : 1;
}

await main();
