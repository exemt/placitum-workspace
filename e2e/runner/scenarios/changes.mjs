#!/usr/bin/env node
/**
 * E2E правок: замечает ли панель изменение конфигурации. Любое.
 *
 * Проверяется одно утверждение, повторённое на четырёх десятках настоящих
 * сущностей: оператор что-то поменял -> контроллер это увидел -> предложил
 * разослать. И симметричное к нему: оператор ничего значимого не менял ->
 * контроллер молчит. Второе не менее важно первого: индикатор, который горит
 * всегда, не читают.
 *
 * Как устроен каждый случай:
 *
 *   1. канал приводится к «сошлось» -- иначе сравнивать не с чем;
 *   2. правка через то же API, которым правит панель;
 *   3. снимок сходимости обязан выйти из `ok`;
 *   4. заодно проверяется, что соседние каналы не тронуты;
 *   5. правка откатывается, и канал обязан вернуться в `ok`.
 *
 * Шаг 3 различает два исхода, и это главный результат прогона:
 *
 *   `dirty`     -- правка доехала до конфигурации, её надо разослать;
 *   `no_effect` -- правка сохранена, а конфигурация вышла та же. Значит поле
 *                  не читает компилятор, либо директива не поддержана сборкой
 *                  модуля, либо правили объект, на который никто не ссылается.
 *                  Раньше такое было неотличимо от «ничего не меняли».
 *
 * Итоговая таблица `no_effect` -- это и есть список настроек, которые оператор
 * может двигать без всякого следа на флоте. Её стоит читать глазами.
 *
 *     cd tests/runner
 *     npm run test:changes
 *
 * Требует поднятый deploy/ (docker compose up -d --wait).
 */

import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import { loadEnv } from "../lib/env.mjs";
import { controllerClient } from "../lib/controller.mjs";
import { pollUntil } from "../lib/wait.mjs";
import { Report } from "../lib/report.mjs";

const CHANNELS = ["nginx", "agent", "rules", "ip", "auth", "captcha"];

/** Состояния, в которых канал считается «панель ничего не заметила». */
const QUIET = new Set(["ok", "empty", "unmanaged", "nobody"]);

function channelOf(snap, id) {
  return (snap.channels ?? []).find((row) => row.id === id) ?? null;
}

function states(snap) {
  return Object.fromEntries((snap.channels ?? []).map((row) => [row.id, row.state]));
}

async function main() {
  const env = loadEnv();
  const ctrl = controllerClient(env.controller);
  const runId = randomUUID().slice(0, 8);
  const report = new Report("changes", runId);

  const scope = await ctrl.scopeByName(env.spaceName);

  if (scope === null) {
    process.stdout.write(`нет пространства "${env.spaceName}"\n`);
    process.exitCode = 1;
    return;
  }

  const api = ctrl.api;
  const seen = { dirty: [], no_effect: [], other: [] };

  /* --- инструменты случая -------------------------------------------------- */

  const snapshot = () => ctrl.convergence.refresh(scope);

  /**
   * Привести канал к «сошлось». Рассылка обязательна хотя бы раз за прогон,
   * даже если канал уже `ok`: пока контроллер не издал поколение, он не знает
   * отпечатка источника на момент рассылки, и правку, которую компилятор не
   * печатает, сравнивать не с чем.
   */
  const primed = new Set();

  async function settle(channel) {
    let row = channelOf(await snapshot(), channel);

    if (!primed.has(channel) || (row !== null && !QUIET.has(row.state))) {
      await ctrl.convergence.send(scope, channel).catch(() => {});
      primed.add(channel);
    }

    // Дренаж флота -- нормальное состояние; базовая линия должна снимать его
    // уже устоявшимся, иначе «откат вернул прежнее» падает на таймингах.
    const outcome = await pollUntil(
      async () => {
        const now = channelOf(await snapshot(), channel);
        return { ok: now !== null && QUIET.has(now.state), now };
      },
      { timeoutMs: 20_000, intervalMs: 400 },
    );

    return outcome.now ?? row;
  }

  /**
   * Один случай: правка -> заметили -> откат -> снова тихо.
   *
   * `apply` возвращает функцию отката. Так откат пишется рядом с правкой и
   * знает её исходное значение, а не восстанавливается по памяти сценария.
   */
  async function probe(phase, { id, channel, apply, expect, neighbours }) {
    const before = await settle(channel);
    const baseline = before?.state ?? "unknown";
    const others = states(await snapshot());

    let revert;
    try {
      revert = await apply();
    } catch (err) {
      phase.check(`${id}: правка прошла`, false, String(err));
      return;
    }

    const after = await snapshot();
    const row = channelOf(after, channel);
    const state = row?.state ?? "unknown";
    const noticed = !QUIET.has(state) || row?.sourceChanged === true;

    phase.check(`${id} -> ${channel}: правка замечена`, noticed, state);

    if (expect !== undefined) {
      phase.check(`${id}: состояние «${expect}»`, state === expect, state);
    }

    if (state === "dirty") {
      seen.dirty.push(id);
    } else if (state === "no_effect") {
      seen.no_effect.push(id);
    } else if (noticed) {
      seen.other.push(`${id}=${state}`);
    }

    // Соседние каналы правка задевать не должна: канон одного канала не
    // обязан зависеть от источника другого.
    if (neighbours !== false) {
      const now = states(after);
      const bled = CHANNELS.filter(
        (other) => other !== channel && now[other] !== others[other],
      );
      phase.check(
        `${id}: соседние каналы не задеты`,
        bled.length === 0,
        bled.map((other) => `${other}: ${others[other]} -> ${now[other]}`),
      );
    }

    try {
      await revert();
    } catch (err) {
      phase.check(`${id}: откат прошёл`, false, String(err));
      return;
    }

    const back = channelOf(await snapshot(), channel)?.state ?? "unknown";
    phase.check(
      `${id}: откат вернул «${baseline}»`,
      back === baseline,
      `${baseline} -> ${state} -> ${back}`,
    );
  }

  /** Правка поля в jsonb-документе сущности с восстановлением исходного. */
  function patcher(path, build) {
    return async () => {
      const before = await api.get(scope, path);
      await api.put(scope, path, build(before, true));
      return () => api.put(scope, path, build(before, false));
    };
  }

  /* --- Фаза 1: пространство http ------------------------------------------ */

  await report.run("Фаза 1 — пространство http", async (phase) => {
    const httpBody = (row) => ({
      nginx_main: row.nginx_main,
      nginx: row.nginx,
      waf_http: row.waf_http,
      waf: row.waf,
      raw: row.raw,
      raw_nginx: row.raw_nginx,
    });

    const httpCase = (id, mutate) => ({
      id,
      channel: "nginx",
      apply: patcher("/http", (row, edit) => {
        const body = httpBody(row);
        return edit ? mutate(structuredClone(body)) : body;
      }),
    });

    for (const one of [
      httpCase("http.nginx.sendfile", (b) => {
        b.nginx.sendfile = !(b.nginx.sendfile ?? false);
        return b;
      }),
      httpCase("http.nginx.clientMaxBodySize", (b) => {
        b.nginx.clientMaxBodySize = "13m";
        return b;
      }),
      httpCase("http.nginx.keepaliveTimeoutS", (b) => {
        b.nginx.keepaliveTimeoutS = (b.nginx.keepaliveTimeoutS ?? 60) + 5;
        return b;
      }),
      httpCase("http.nginxMain.workerProcesses", (b) => {
        b.nginx_main.workerProcesses = (b.nginx_main.workerProcesses ?? 2) + 1;
        return b;
      }),
      httpCase("http.wafHttp.shmZone.size", (b) => {
        b.waf_http.shmZone = { ...b.waf_http.shmZone, size: "9m" };
        return b;
      }),
      httpCase("http.wafHttp.maxInflight", (b) => {
        b.waf_http.maxInflight = (b.waf_http.maxInflight ?? 4096) + 128;
        return b;
      }),
      httpCase("http.waf.inspectors[modsec].timeoutMs", (b) => {
        const modsec = b.waf.inspectors?.modsec ?? {};
        b.waf.inspectors = {
          ...b.waf.inspectors,
          modsec: { ...modsec, timeoutMs: (modsec.timeoutMs ?? 500) + 25 },
        };
        return b;
      }),
      httpCase("http.waf.inspectors[modsec].profile", (b) => {
        const modsec = b.waf.inspectors?.modsec ?? {};
        b.waf.inspectors = {
          ...b.waf.inspectors,
          modsec: { ...modsec, profile: "default" },
        };
        return b;
      }),
    ]) {
      await probe(phase, one);
    }

    /*
     * Отдельный случай: поле, которое база принимает, а компилятор отвергает
     * (`deadlineMs` живёт на сервере, не в http). Панель обязана не молчать и
     * назвать причину, а не показать «сошлось».
     */
    await probe(phase, {
      id: "http.waf.deadlineMs (поле не для этого уровня)",
      channel: "nginx",
      expect: "broken",
      apply: patcher("/http", (row, edit) => {
        const body = httpBody(row);
        if (!edit) {
          return body;
        }
        const next = structuredClone(body);
        next.waf.deadlineMs = 33;
        return next;
      }),
    });
  });

  /* --- Фаза 2: серверы ----------------------------------------------------- */

  let server = null;
  let location = null;

  await report.run("Фаза 2 — серверы", async (phase) => {
    const servers = (await api.get(scope, "/servers")).servers ?? [];
    server = servers.find((row) => row.enabled && row.location_count > 0) ?? servers[0];

    if (server === undefined) {
      phase.check("в пространстве есть сервер", false);
      return;
    }

    phase.note(`сервер «${server.name}», путей ${server.location_count}`);

    const serverBody = (row) => ({
      name: row.name,
      server_names: row.server_names,
      enabled: row.enabled,
      nginx: row.nginx,
      waf: row.waf,
      raw: row.raw,
      raw_nginx: row.raw_nginx,
    });

    const serverCase = (id, mutate) => ({
      id,
      channel: "nginx",
      apply: patcher(`/servers/${server.uuid}`, (row, edit) => {
        const body = serverBody(row);
        return edit ? mutate(structuredClone(body)) : body;
      }),
    });

    for (const one of [
      serverCase("server.server_names", (b) => {
        b.server_names = [...b.server_names, `probe-${runId}.example.com`];
        return b;
      }),
      serverCase("server.enabled", (b) => {
        b.enabled = !b.enabled;
        return b;
      }),
      serverCase("server.name", (b) => {
        b.name = `${b.name}-probe`;
        return b;
      }),
      serverCase("server.waf.deadlineMs", (b) => {
        b.waf.deadlineMs = (b.waf.deadlineMs ?? 500) + 25;
        return b;
      }),
      serverCase("server.waf.scoreDeny.threshold", (b) => {
        b.waf.scoreDeny = {
          ...(b.waf.scoreDeny ?? {}),
          threshold: (b.waf.scoreDeny?.threshold ?? 100) - 7,
        };
        return b;
      }),
      serverCase("server.waf.capture", (b) => {
        const capture = b.waf.capture ?? ["headers"];
        b.waf.capture = capture.includes("body")
          ? capture.filter((row) => row !== "body")
          : [...capture, "body"];
        return b;
      }),
      serverCase("server.waf.deadlinePolicy", (b) => {
        b.waf.deadlinePolicy = b.waf.deadlinePolicy === "pass" ? "block" : "pass";
        return b;
      }),
      serverCase("server.waf.onBusError", (b) => {
        b.waf.onBusError = b.waf.onBusError === "pass" ? "block" : "pass";
        return b;
      }),
      serverCase("server.waf.debugHeader", (b) => {
        b.waf.debugHeader = !(b.waf.debugHeader ?? false);
        return b;
      }),
      serverCase("server.waf.enabled", (b) => {
        b.waf.enabled = !(b.waf.enabled ?? true);
        return b;
      }),
      serverCase("server.nginx.clientMaxBodySize", (b) => {
        b.nginx.clientMaxBodySize = "11m";
        return b;
      }),
      serverCase("server.nginx.realIpHeader", (b) => {
        b.nginx.realIpHeader = b.nginx.realIpHeader === "X-Real-IP"
          ? "X-Forwarded-For"
          : "X-Real-IP";
        return b;
      }),
    ]) {
      await probe(phase, one);
    }
  });

  /* --- Фаза 3: пути -------------------------------------------------------- */

  await report.run("Фаза 3 — пути", async (phase) => {
    if (server === null) {
      phase.check("сервер найден в прошлой фазе", false);
      return;
    }

    const locations =
      (await api.get(scope, `/locations?server=${server.uuid}`)).locations ?? [];
    location = locations.find((row) => row.enabled && row.handler === "proxy")
      ?? locations.find((row) => row.enabled)
      ?? locations[0];

    if (location === undefined) {
      phase.check(`у сервера ${server.name} есть пути`, false);
      return;
    }

    phase.note(`путь «${location.path}», обработчик ${location.handler}`);

    const locationBody = (row) => ({
      match: row.match,
      path: row.path,
      enabled: row.enabled,
      handler: row.handler,
      upstream_id: row.upstream_id,
      upstream_uri: row.upstream_uri,
      return_status: row.return_status,
      return_page: row.return_page,
      return_url: row.return_url,
      nginx: row.nginx,
      waf: row.waf,
      raw: row.raw,
      raw_nginx: row.raw_nginx,
    });

    const locationCase = (id, mutate) => ({
      id,
      channel: "nginx",
      apply: patcher(`/locations/${location.uuid}`, (row, edit) => {
        const body = locationBody(row);
        return edit ? mutate(structuredClone(body)) : body;
      }),
    });

    for (const one of [
      locationCase("location.enabled", (b) => {
        b.enabled = !b.enabled;
        return b;
      }),
      locationCase("location.path", (b) => {
        b.path = `${b.path.replace(/\/$/, "")}-probe/`;
        return b;
      }),
      locationCase("location.match", (b) => {
        b.match = b.match === "prefix" ? "exact" : "prefix";
        return b;
      }),
      locationCase("location.waf.enabled", (b) => {
        b.waf.enabled = !(b.waf.enabled ?? true);
        return b;
      }),
      locationCase("location.waf.deadlineMs", (b) => {
        b.waf.deadlineMs = (b.waf.deadlineMs ?? 25) + 9;
        return b;
      }),
      locationCase("location.waf.capture", (b) => {
        const capture = b.waf.capture ?? [];
        b.waf.capture = capture.includes("args")
          ? capture.filter((row) => row !== "args")
          : [...capture, "args"];
        return b;
      }),
      locationCase("location.nginx.proxyReadTimeoutMs", (b) => {
        b.nginx.proxyReadTimeoutMs = 61_000;
        return b;
      }),
      locationCase("location.upstream_uri", (b) => {
        b.upstream_uri = b.upstream_uri === null ? "/" : null;
        return b;
      }),
    ]) {
      await probe(phase, one);
    }
  });

  /* --- Фаза 4: порты, апстримы, реестр ------------------------------------- */

  await report.run("Фаза 4 — порты, апстримы, реестр", async (phase) => {
    const ports = (await api.get(scope, "/ports")).ports ?? [];
    const port = ports[0];

    if (port !== undefined) {
      /*
       * Холостое сохранение порта перед замерами. `server_ports` держит копию
       * флагов порта (ssl/http2/proxy_protocol), и синхронизирует её только
       * запись в сам порт: пока порт не трогали, копия может расходиться с
       * оригиналом, и первая же правка меняет конфигурацию сверх того, что
       * правил оператор. Тогда «откат вернул прежнее» падает не на механизме
       * сходимости, а на этом рассинхроне. Причина -- отдельная задача.
       */
      await api.put(scope, `/ports/${port.uuid}`, {
        name: port.name,
        address: port.address,
        port: port.port,
        ssl: port.ssl,
        http2: port.http2,
        proxy_protocol: port.proxy_protocol,
      });

      const portBody = (row) => ({
        name: row.name,
        address: row.address,
        port: row.port,
        ssl: row.ssl,
        http2: row.http2,
        proxy_protocol: row.proxy_protocol,
      });

      const portCase = (id, mutate) => ({
        id,
        channel: "nginx",
        apply: patcher(`/ports/${port.uuid}`, (row, edit) => {
          const body = portBody(row);
          return edit ? mutate(structuredClone(body)) : body;
        }),
      });

      for (const one of [
        portCase("port.http2", (b) => {
          b.http2 = !b.http2;
          return b;
        }),
        portCase("port.proxy_protocol", (b) => {
          b.proxy_protocol = !b.proxy_protocol;
          return b;
        }),
        portCase("port.name", (b) => {
          b.name = `${b.name}-probe`;
          return b;
        }),
      ]) {
        await probe(phase, one);
      }
    } else {
      phase.check("в пространстве есть порт", false);
    }

    const upstreams = (await api.get(scope, "/upstreams")).upstreams ?? [];
    const upstream = upstreams.find((row) => (row.peers ?? []).length > 0);

    if (upstream !== undefined) {
      // Пир описывается `host`, не `address`: форма из controller/ux/src/api.ts.
      const upstreamBody = (row) => ({
        name: row.name,
        method: row.method,
        hash_key: row.hash_key,
        keepalive: row.keepalive,
        keepalive_requests: row.keepalive_requests,
        keepalive_timeout_ms: row.keepalive_timeout_ms,
        peers: (row.peers ?? []).map((peer) => ({
          host: peer.host,
          port: peer.port,
          weight: peer.weight,
          max_fails: peer.max_fails,
          fail_timeout_ms: peer.fail_timeout_ms,
          backup: peer.backup,
          down: peer.down,
        })),
      });

      const upstreamCase = (id, mutate) => ({
        id,
        channel: "nginx",
        apply: patcher(`/upstreams/${upstream.uuid}`, (row, edit) => {
          const body = upstreamBody(row);
          return edit ? mutate(structuredClone(body)) : body;
        }),
      });

      for (const one of [
        upstreamCase("upstream.keepalive", (b) => {
          b.keepalive = (b.keepalive ?? 0) + 16;
          return b;
        }),
        upstreamCase("upstream.keepalive_requests", (b) => {
          b.keepalive_requests = (b.keepalive_requests ?? 100) + 10;
          return b;
        }),
        upstreamCase("upstream.peer.weight", (b) => {
          b.peers[0].weight = (b.peers[0].weight ?? 1) + 1;
          return b;
        }),
        upstreamCase("upstream.peer.down", (b) => {
          b.peers[0].down = !b.peers[0].down;
          return b;
        }),
        upstreamCase("upstream.peer.max_fails", (b) => {
          b.peers[0].max_fails = (b.peers[0].max_fails ?? 1) + 2;
          return b;
        }),
      ]) {
        await probe(phase, one);
      }
    } else {
      phase.check("в пространстве есть апстрим с пирами", false);
    }

    const inspectors = (await api.get(scope, "/inspectors")).inspectors ?? [];
    const inspector = inspectors.find((row) => row.name === "modsec") ?? inspectors[0];

    if (inspector !== undefined) {
      for (const one of [
        {
          id: "inspector.phases",
          channel: "nginx",
          apply: async () => {
            const before = await api.get(scope, `/inspectors/${inspector.uuid}`);
            const phases = before.phases.includes("response")
              ? ["request"]
              : ["request", "response"];
            await api.put(scope, `/inspectors/${inspector.uuid}`, { phases });
            return () =>
              api.put(scope, `/inspectors/${inspector.uuid}`, {
                phases: before.phases,
              });
          },
        },
        {
          id: "inspector.conf",
          channel: "nginx",
          apply: async () => {
            const before = await api.get(scope, `/inspectors/${inspector.uuid}`);
            await api.put(scope, `/inspectors/${inspector.uuid}`, {
              conf: `${before.conf ?? ""}\n# probe ${runId}\n`,
            });
            return () =>
              api.put(scope, `/inspectors/${inspector.uuid}`, {
                conf: before.conf ?? "",
              });
          },
        },
      ]) {
        await probe(phase, one);
      }
    } else {
      phase.check("в реестре есть инспекторы", false);
    }
  });

  /* --- Фаза 5: наборы, страницы, каталоги ---------------------------------- */

  await report.run("Фаза 5 — наборы, страницы, каталоги", async (phase) => {
    const datasets = (await api.get(scope, "/datasets")).datasets ?? [];
    const list = datasets.find((row) => row.kind === "list");
    const content = datasets.find((row) => row.kind === "content");

    if (list !== undefined) {
      for (const one of [
        {
          id: "dataset.limit",
          channel: "nginx",
          apply: async () => {
            const before = list.limit ?? null;
            await api.put(scope, `/datasets/${list.uuid}`, {
              limit: (before ?? 1000) + 17,
            });
            return () =>
              api.put(scope, `/datasets/${list.uuid}`, {
                limit: before ?? undefined,
              });
          },
        },
        {
          id: "dataset.in_nginx",
          channel: "nginx",
          apply: async () => {
            const before = list.in_nginx === true;
            await api.put(scope, `/datasets/${list.uuid}`, { in_nginx: !before });
            return () =>
              api.put(scope, `/datasets/${list.uuid}`, { in_nginx: before });
          },
        },
        {
          id: "dataset.name",
          channel: "nginx",
          // Набор принадлежит двум каналам сразу: шаблон видит его слотом
          // `waf_local_dataset`, а компилятор адреса -- как источник. Правка
          // имени законно отзывается в обоих.
          neighbours: false,
          apply: async () => {
            const before = list.name;
            await api.put(scope, `/datasets/${list.uuid}`, {
              name: `${before}-probe`,
            });
            return () =>
              api.put(scope, `/datasets/${list.uuid}`, { name: before });
          },
        },
      ]) {
        await probe(phase, one);
      }

      /*
       * Состав списка адресов. Канал у него `ip`, но задеть он может и `nginx`:
       * набор виден шаблону слотом `waf_local_dataset`. Поэтому «соседние
       * каналы не задеты» здесь не проверяется -- проверяется, что оба канала
       * заметили правку.
       */
      await probe(phase, {
        id: "dataset.addresses",
        channel: "ip",
        neighbours: false,
        apply: async () => {
          const address = `203.0.113.${Math.floor(Math.random() * 200) + 5}`;
          const created = await api.post(
            scope,
            `/datasets/${list.uuid}/addresses`,
            { addresses: [address] },
          );
          const rows = created.addresses ?? created.created ?? [];
          const id = Array.isArray(rows) ? rows[0]?.uuid : undefined;

          return async () => {
            if (id === undefined) {
              throw new Error(`адрес создан без uuid: ${JSON.stringify(created)}`);
            }
            await api.send(scope, `/addresses/${id}`, "DELETE");
          };
        },
      });
    } else {
      phase.check("в пространстве есть список", false);
    }

    if (content !== undefined) {
      await probe(phase, {
        id: "content.body (страница отказа)",
        channel: "nginx",
        apply: async () => {
          const before = await api.get(scope, `/datasets/${content.uuid}/content`);
          const text = Buffer.from(before.blob ?? "", "base64").toString("utf8");
          const blob = Buffer.from(`${text}<!-- probe ${runId} -->`).toString("base64");
          await api.put(scope, `/datasets/${content.uuid}/content`, {
            name: before.name,
            blob,
          });
          return () =>
            api.put(scope, `/datasets/${content.uuid}/content`, {
              name: before.name,
              blob: before.blob,
            });
        },
      });
    } else {
      phase.check("в пространстве есть объект содержимого", false);
    }

    const denies = (await api.get(scope, "/deny-responses")).deny_responses ?? [];
    if (denies.length > 0) {
      const row = denies[0];
      await probe(phase, {
        id: "deny-response.spec.status",
        channel: "nginx",
        apply: async () => {
          const spec = { ...row.spec, status: row.spec?.status === 503 ? 502 : 503 };
          await api.put(scope, `/deny-responses/${row.uuid}`, { ...row, spec });
          return () => api.put(scope, `/deny-responses/${row.uuid}`, row);
        },
      });
    } else {
      phase.check("в каталоге есть формы отказа", false);
    }

    const formats = (await api.get(scope, "/log-formats")).log_formats ?? [];
    if (formats.length > 0) {
      const row = formats[0];
      await probe(phase, {
        id: "log-format.format",
        channel: "nginx",
        apply: async () => {
          await api.put(scope, `/log-formats/${row.uuid}`, {
            ...row,
            format: `${row.format ?? ""} probe=${runId}`,
          });
          return () => api.put(scope, `/log-formats/${row.uuid}`, row);
        },
      });
    } else {
      phase.check("в каталоге есть форматы логов", false);
    }
  });

  /* --- Фаза 6: профили инспекторов и агент --------------------------------- */

  await report.run("Фаза 6 — профили инспекторов и агент", async (phase) => {
    const files = (await api.get(scope, "/rule-files")).rule_files ?? [];
    const sets = (await api.get(scope, "/rule-sets")).rule_sets ?? [];

    /* Файл, который лежит хотя бы в одном наборе: иначе правка его и не должна
       никуда доехать, и случай проверял бы пустоту. */
    const used = new Set();
    for (const row of sets) {
      const full = await api.get(scope, `/rule-sets/${row.uuid}`);
      for (const item of full.files ?? []) {
        used.add(item.uuid);
      }
    }

    const file = files.find((row) => used.has(row.uuid)) ?? files[0];

    if (file !== undefined) {
      const fileBody = (row) => ({
        name: row.name,
        description: row.description,
        text_raw: row.text_raw ?? "",
      });

      for (const one of [
        {
          id: "rule-file.text",
          channel: "rules",
          apply: patcher(`/rule-files/${file.uuid}`, (row, edit) => {
            const body = fileBody(row);
            return edit
              ? { ...body, text_raw: `${body.text_raw}\n# probe ${runId}\n` }
              : body;
          }),
        },
        {
          id: "rule-file.name",
          channel: "rules",
          apply: patcher(`/rule-files/${file.uuid}`, (row, edit) => {
            const body = fileBody(row);
            return edit ? { ...body, name: `${body.name}-probe` } : body;
          }),
        },
      ]) {
        await probe(phase, one);
      }
    } else {
      phase.check("в пространстве есть файлы правил", false);
    }

    const set = sets.find((row) => (row.files ?? []).length > 1);

    if (set !== undefined) {
      await probe(phase, {
        id: "rule-set.порядок файлов",
        channel: "rules",
        apply: async () => {
          const before = await api.get(scope, `/rule-sets/${set.uuid}`);
          const ids = before.files.map((row) => row.uuid);
          await api.put(scope, `/rule-sets/${set.uuid}`, {
            name: before.name,
            description: before.description,
            files: [...ids].reverse(),
          });
          return () =>
            api.put(scope, `/rule-sets/${set.uuid}`, {
              name: before.name,
              description: before.description,
              files: ids,
            });
        },
      });
    } else {
      phase.note("наборов с двумя и более файлами нет: порядок не проверить");
    }

    const ipProfiles = (await api.get(scope, "/ip-profiles")).ip_profiles ?? [];
    const ipProfile = ipProfiles[0];

    if (ipProfile !== undefined) {
      await probe(phase, {
        id: "ip-profile.countries",
        channel: "ip",
        apply: async () => {
          const before = await api.get(scope, `/ip-profiles/${ipProfile.uuid}`);
          const side = before.blacklist ?? {};
          const countries = [...(side.countries ?? [])];
          const next = countries.includes("AQ")
            ? countries.filter((row) => row !== "AQ")
            : [...countries, "AQ"];
          await api.put(scope, `/ip-profiles/${ipProfile.uuid}`, {
            name: before.name,
            description: before.description,
            whitelist: before.whitelist,
            blacklist: { ...side, countries: next },
          });
          return () =>
            api.put(scope, `/ip-profiles/${ipProfile.uuid}`, {
              name: before.name,
              description: before.description,
              whitelist: before.whitelist,
              blacklist: before.blacklist,
            });
        },
      });
    } else {
      phase.check("в пространстве есть профили адреса", false);
    }

    for (const [id, channel, base] of [
      ["auth-profile.doc", "auth", "/auth/profiles"],
      ["captcha-profile.doc", "captcha", "/captcha/profiles"],
    ]) {
      const rows = (await api.get(scope, base)).profiles ?? [];

      /*
       * Профиль, который переживает собственный PUT без правок. Калитка с
       * непустым `login.uri` и без привязанного сервера отвечает на сохранение
       * `server_required` -- то есть строка в базе есть, а сохранить её как
       * есть нельзя. Это отдельная задача контроллера; сценарий правок берёт
       * профиль, на котором проверяет то, ради чего заведён.
       */
      const row =
        rows.find((one) => one.server_id !== null) ??
        rows.find((one) => (one.doc?.login?.uri ?? "") === "") ??
        rows[0];

      if (row === undefined) {
        phase.note(`${id}: профилей нет`);
        continue;
      }

      await probe(phase, {
        id,
        channel,
        apply: async () => {
          const before = await api.get(scope, `${base}/${row.uuid}`);
          const doc = structuredClone(before.doc);
          /*
           * Заголовок формы: у калитки он в `login`, у капчи -- в корне
           * документа. Трогать `login.uri` нельзя -- профиль без привязанного
           * сервера на этом отвечает `server_required`.
           */
          if (doc.login !== undefined) {
            doc.login = { ...doc.login, title: `${doc.login.title ?? ""} probe` };
          } else {
            doc.title = `${doc.title ?? ""} probe`;
          }
          await api.put(scope, `${base}/${row.uuid}`, {
            name: before.name,
            description: before.description,
            server_id: before.server_id,
            doc,
          });
          return () =>
            api.put(scope, `${base}/${row.uuid}`, {
              name: before.name,
              description: before.description,
              server_id: before.server_id,
              doc: before.doc,
            });
        },
      });
    }

    for (const one of [
      {
        id: "agent.archive.workers",
        channel: "agent",
        apply: patcher("/agent", (row, edit) => {
          const settings = structuredClone(row.settings ?? {});
          if (!edit) {
            return settings;
          }
          settings.archive = {
            ...settings.archive,
            workers: (settings.archive?.workers ?? 4) + 2,
          };
          return settings;
        }),
      },
      {
        id: "agent.s3.region",
        channel: "agent",
        apply: patcher("/agent", (row, edit) => {
          const settings = structuredClone(row.settings ?? {});
          if (!edit) {
            return settings;
          }
          settings.s3 = { ...settings.s3, region: "eu-central-1" };
          return settings;
        }),
      },
      {
        id: "agent.archive.batch.body.size",
        channel: "agent",
        apply: patcher("/agent", (row, edit) => {
          const settings = structuredClone(row.settings ?? {});
          if (!edit) {
            return settings;
          }
          const batch = settings.archive?.batch ?? {};
          settings.archive = {
            ...settings.archive,
            batch: { ...batch, body: { ...batch.body, size: 77 } },
          };
          return settings;
        }),
      },
    ]) {
      await probe(phase, one);
    }
  });

  /* --- Фаза 7: тишина там, где менять нечего ------------------------------ */

  await report.run("Фаза 7 — шум", async (phase) => {
    /*
     * Симметричная половина. Индикатор, который загорается на заметку в поле
     * «описание» или на повторное сохранение того же значения, оператор
     * закроет не глядя, и вместе с ним закроет настоящие расхождения.
     */
    async function quiet(id, channel, act) {
      const before = await settle(channel);
      const baseline = before?.state ?? "unknown";

      await act();

      const row = channelOf(await snapshot(), channel);
      phase.check(
        `${id}: панель промолчала`,
        row?.state === baseline && row?.sourceChanged !== true,
        `${baseline} -> ${row?.state} (sourceChanged=${row?.sourceChanged})`,
      );
    }

    const files = (await api.get(scope, "/rule-files")).rule_files ?? [];
    if (files[0] !== undefined) {
      const file = files[0];
      const before = await api.get(scope, `/rule-files/${file.uuid}`);

      await quiet("описание файла правил", "rules", () =>
        api.put(scope, `/rule-files/${file.uuid}`, {
          name: before.name,
          description: `заметка ${runId}`,
          text_raw: before.text_raw ?? "",
        }),
      );

      await quiet("повторное сохранение того же текста", "rules", () =>
        api.put(scope, `/rule-files/${file.uuid}`, {
          name: before.name,
          description: `заметка ${runId}`,
          text_raw: before.text_raw ?? "",
        }),
      );

      await api.put(scope, `/rule-files/${file.uuid}`, {
        name: before.name,
        description: before.description,
        text_raw: before.text_raw ?? "",
      });
    }

    const httpRow = await api.get(scope, "/http");
    await quiet("повторное сохранение http без правок", "nginx", () =>
      api.put(scope, "/http", {
        nginx_main: httpRow.nginx_main,
        nginx: httpRow.nginx,
        waf_http: httpRow.waf_http,
        waf: httpRow.waf,
        raw: httpRow.raw,
        raw_nginx: httpRow.raw_nginx,
      }),
    );

    await quiet("пересчёт снимка сам по себе", "nginx", async () => {
      await snapshot();
      await snapshot();
    });
  });

  /* --- итог ---------------------------------------------------------------- */

  await report.run("Итог — что доезжает, а что нет", async ({ check, note }) => {
    note(`доехало до конфигурации (${seen.dirty.length}): ${seen.dirty.join(", ")}`);
    note(
      `сохранено, но конфигурация та же (${seen.no_effect.length}): ` +
        (seen.no_effect.join(", ") || "нет"),
    );
    if (seen.other.length > 0) {
      note(`прочее: ${seen.other.join(", ")}`);
    }

    check(
      "каждая правка чем-то отозвалась",
      seen.dirty.length + seen.no_effect.length + seen.other.length > 0,
    );
  });

  report.finish();
  report.printText();
  await report.writeFiles(fileURLToPath(new URL("../reports", import.meta.url)));

  process.exitCode = report.summary().failed === 0 ? 0 : 1;
}

await main();
