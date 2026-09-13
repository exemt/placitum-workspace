/**
 * Объявления инспекторов пространства: та самая карта имён, из которой
 * компилятор печатает `waf_inspector` в http {}. Маршруты зовут инспекторов
 * по этим именам, поэтому снять объявление можно только после того, как
 * ссылки на него убраны со всех маршрутов — включая выключенные.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { WafApi } from "../api.ts";
import { reg } from "../register.ts";

interface SpaceHttp {
  nginx_main?: unknown;
  nginx?: unknown;
  waf_http?: unknown;
  waf?: { inspectors?: Record<string, { process?: string; profile?: string }> };
  raw?: unknown;
  raw_nginx?: unknown;
}

/** PUT /http принимает только эти поля; остальное — вывод контроллера. */
function putBody(doc: SpaceHttp): Record<string, unknown> {
  return {
    nginx_main: doc.nginx_main,
    nginx: doc.nginx,
    waf_http: doc.waf_http,
    waf: doc.waf,
    raw: doc.raw,
    raw_nginx: doc.raw_nginx,
  };
}

export function declarationReadTools(server: McpServer, api: WafApi): void {
  reg(
    server,
    "inspector_declarations",
    "Объявления инспекторов пространства: имя вызова -> процесс и профиль. " +
      "Именно эти имена маршруты пишут в requestInspectors; вызов мимо " +
      "объявления валит сборку (undeclared_inspector). Каталог процессов и " +
      "их реплики — fleet_status.",
    {},
    async () => {
      const row = (await api.getScoped("/inspectors/declared")) as {
        declared?: unknown[];
      };
      return { declared: row.declared ?? [] };
    },
  );
}

export function declarationWriteTools(server: McpServer, api: WafApi): void {
  reg(
    server,
    "inspector_declare",
    "Объявить инспектора в пространстве, переназначить его профиль или снять " +
      "объявление (remove). Имя — то, которым маршруты зовут инспектора; " +
      "process нужен, когда имя отличается от процесса (несколько профилей " +
      "одного инспектора). Снимать объявление можно только после того, как " +
      "ни один маршрут его не зовёт, иначе сборка ответит undeclared_inspector. " +
      "После правки издать канал nginx.",
    {
      name: z.string().describe("Имя вызова, например auth-any"),
      process: z
        .string()
        .optional()
        .describe("Процесс инспектора (auth2, captcha, counter...); по умолчанию — само имя"),
      profile: z
        .string()
        .optional()
        .describe("Профиль инспектора; без него берётся default"),
      remove: z
        .boolean()
        .optional()
        .describe("Снять объявление вместо правки"),
    },
    async ({ name, process: proc, profile, remove }) => {
      const doc = (await api.getScoped("/http")) as SpaceHttp;
      const waf = doc.waf ?? {};
      const inspectors = { ...(waf.inspectors ?? {}) };
      const key = name as string;

      if (remove === true) {
        if (inspectors[key] === undefined) {
          return {
            error: `inspector "${key}" is not declared`,
            declared: Object.keys(inspectors),
          };
        }
        delete inspectors[key];
      } else {
        const decl: { process?: string; profile?: string } = {};
        if (proc !== undefined && proc !== key) {
          decl.process = proc as string;
        }
        if (profile !== undefined && profile !== "default") {
          decl.profile = profile as string;
        }
        inspectors[key] = decl;
      }

      const saved = (await api.sendScoped(
        "PUT",
        "/http",
        putBody({ ...doc, waf: { ...waf, inspectors } }),
      )) as SpaceHttp;

      return {
        inspectors: saved.waf?.inspectors ?? inspectors,
        publish_channel: "nginx",
      };
    },
  );
}
