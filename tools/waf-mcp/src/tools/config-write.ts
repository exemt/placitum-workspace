/**
 * Пишущая половина. Правка и издание разделены, как в панели: profile_save
 * и addresses_* меняют сохранённое состояние, publish издаёт его участникам
 * контура. Агент может накопить несколько правок и издать одним шагом.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { type WafApi, WafApiError, qs } from "../api.ts";
import { reg } from "../register.ts";
import { findDataset, trimConvergence } from "./config-read.ts";
import {
  INSPECTORS,
  SEND_PATHS,
  channelOf,
  profilesBase,
  resolveRef,
  type InspectorName,
} from "./profiles.ts";

const inspectorParam = z.enum(INSPECTORS);

export function configWriteTools(server: McpServer, api: WafApi): void {
  reg(
    server,
    "profile_save",
    "Сохранить документ профиля инспектора. Документ — целиком, в форме из " +
      "profile_get: прочитать, поправить, отдать назад. Ошибки валидации " +
      "контроллера возвращаются с полями — их можно исправить и повторить. " +
      "Правка не применяется, пока канал не издан через publish.",
    {
      inspector: inspectorParam,
      ref: z.string().describe("Имя профиля или uuid"),
      doc: z
        .record(z.unknown())
        .describe("Полный документ профиля (форма profile_get)"),
    },
    async ({ inspector, ref, doc }) => {
      const base = profilesBase(inspector as InspectorName);
      const resolved = resolveRef(await api.getScoped(base), ref as string);

      if ("error" in resolved) {
        return resolved;
      }

      // Ручка PUT ждёт {name?, description?, doc?}: документ голым телом она
      // молча игнорирует (body.doc === undefined), трогая только updated_at.
      const saved = await api.sendScoped("PUT", `${base}/${resolved.uuid}`, {
        doc,
      });
      return {
        saved,
        publish_channel: channelOf(inspector as InspectorName),
        note: "правка сохранена, но не издана — примените publish",
      };
    },
  );

  reg(
    server,
    "profile_restore",
    "Вернуть профиль к поставке (умолчаниям дистрибутива). Работает для " +
      "профилей с шаблоном поставки; после восстановления канал надо издать.",
    {
      inspector: inspectorParam,
      ref: z.string().describe("Имя профиля или uuid"),
    },
    async ({ inspector, ref }) => {
      const base = profilesBase(inspector as InspectorName);
      const resolved = resolveRef(await api.getScoped(base), ref as string);

      if ("error" in resolved) {
        return resolved;
      }

      const restored = await api.sendScoped(
        "POST",
        `${base}/${resolved.uuid}/restore`,
      );
      return {
        restored,
        publish_channel: channelOf(inspector as InspectorName),
      };
    },
  );

  reg(
    server,
    "addresses_add",
    "Добавить адреса в адресный набор (заблокировать/разрешить — смысл " +
      "определяет набор и то, как его читают профили ip). ttl_s даёт " +
      "временную запись — обычный выбор для реакции на атаку. Записи " +
      "доезжают до участников живьём, издание не требуется; проверить — " +
      "address_find.",
    {
      dataset: z.string().describe("Имя набора (например blocklist) или uuid"),
      addresses: z.array(z.string()).describe("IP или CIDR"),
      ttl_s: z
        .number()
        .int()
        .optional()
        .describe("Срок жизни записи в секундах; без него — бессрочно"),
    },
    async ({ dataset, addresses, ttl_s }) => {
      const found = await findDataset(api, dataset as string);

      if ("error" in found) {
        return found;
      }

      return api.sendScoped("POST", `/datasets/${found.uuid}/addresses`, {
        addresses,
        ttl_s,
      });
    },
  );

  reg(
    server,
    "addresses_remove",
    "Убрать адреса из адресного набора. Адрес ищется в записях набора; " +
      "если точного совпадения нет, возвращаются кандидаты без удаления.",
    {
      dataset: z.string().describe("Имя набора или uuid"),
      addresses: z.array(z.string()).describe("Адреса, как они записаны в наборе"),
    },
    async ({ dataset, addresses }) => {
      const found = await findDataset(api, dataset as string);

      if ("error" in found) {
        return found;
      }

      const removed: string[] = [];
      const missing: { address: string; candidates: unknown[] }[] = [];

      for (const address of addresses as string[]) {
        const row = (await api.getScoped(
          `/datasets/${found.uuid}/addresses${qs({ q: address })}`,
        )) as { addresses: { uuid: string; address?: string }[] };

        const hit = row.addresses.find((a) => a.address === address);

        if (hit === undefined) {
          missing.push({ address, candidates: row.addresses });
          continue;
        }

        await api.sendScoped("DELETE", `/addresses/${hit.uuid}`);
        removed.push(address);
      }

      return { removed, missing };
    },
  );

  reg(
    server,
    "dataset_content_set",
    "Заменить содержимое контентного набора (kind=content): данные к " +
      "правилам modsec (`*FromFile`) и страницам. Текст целиком — прочитать " +
      "через dataset_get, поправить, отдать назад.",
    {
      dataset: z.string().describe("Имя набора или uuid"),
      text: z.string().describe("Новое содержимое целиком"),
    },
    async ({ dataset, text }) => {
      const found = await findDataset(api, dataset as string);

      if ("error" in found) {
        return found;
      }

      return api.sendScoped("PUT", `/datasets/${found.uuid}/content`, {
        blob: Buffer.from(text as string, "utf8").toString("base64"),
      });
    },
  );

  reg(
    server,
    "route_update",
    "Сохранить документ маршрута (или сервера, если path не задан). " +
      "Документ целиком, в форме route_get: прочитать, поправить блок waf " +
      "или nginx, отдать назад. Изменения нужно издать: publish канала nginx.",
    {
      server: z.string().describe("Имя сервера или uuid"),
      path: z
        .string()
        .optional()
        .describe("path маршрута или uuid; без него правится документ сервера"),
      doc: z.record(z.unknown()).describe("Полный документ (форма route_get)"),
    },
    async ({ server: serverRef, path, doc }) => {
      const srv = await resolveServer(api, serverRef as string);

      if ("error" in srv) {
        return srv;
      }

      if (path === undefined) {
        const saved = await api.sendScoped("PUT", `/servers/${srv.uuid}`, doc);
        return { saved, publish_channel: "nginx" };
      }

      const loc = await resolveLocation(api, srv, path as string);

      if ("error" in loc) {
        return loc;
      }

      const saved = await api.sendScoped("PUT", `/locations/${loc.uuid}`, doc);
      return { saved, publish_channel: "nginx" };
    },
  );

  reg(
    server,
    "route_create",
    "Создать маршрут (location) на сервере. Документ — в форме location из " +
      "route_get: match (prefix|exact|regex|regex_i|named), path, position " +
      "(порядок в конфиге; для regex он же порядок проверки), enabled, " +
      "handler (proxy|static|return), protocol (http|websocket: у websocket " +
      "фазы запрос и кадры, ответа нет, ключи кадров только на нём), " +
      "upstream_id для proxy, блоки nginx и " +
      "waf. Корень prefix / у сервера уже есть (builtin), заново его не " +
      "создать. Маршрут не работает, пока канал nginx не издан через publish.",
    {
      server: z.string().describe("Имя сервера или uuid"),
      doc: z
        .record(z.unknown())
        .describe("Документ location (форма route_get, без uuid)"),
    },
    async ({ server: serverRef, doc }) => {
      const srv = await resolveServer(api, serverRef as string);

      if ("error" in srv) {
        return srv;
      }

      const created = await api.sendScoped(
        "POST",
        `/servers/${srv.uuid}/locations`,
        doc,
      );
      return { created, publish_channel: "nginx" };
    },
  );

  reg(
    server,
    "route_delete",
    "Удалить маршрут (location) насовсем. Строка пропадает из панели и из " +
      "следующего издания; откатить нельзя — только создать заново. " +
      "Корень сервера (prefix /, builtin) не удаляется и не меняет адрес: " +
      "он заводится вместе с сервером, чтобы у каждого запроса был маршрут. " +
      "Компилятор проверяет ссылки и у выключенных маршрутов, поэтому " +
      "сначала удалить маршрут, потом чистить его профили и объявления. " +
      "После удаления издать канал nginx.",
    {
      server: z.string().describe("Имя сервера или uuid"),
      path: z.string().describe("path маршрута или uuid"),
    },
    async ({ server: serverRef, path }) => {
      const srv = await resolveServer(api, serverRef as string);

      if ("error" in srv) {
        return srv;
      }

      const loc = await resolveLocation(api, srv, path as string);

      if ("error" in loc) {
        return loc;
      }

      const deleted = await api.sendScoped("DELETE", `/locations/${loc.uuid}`);
      return { deleted, publish_channel: "nginx" };
    },
  );

  reg(
    server,
    "profile_delete",
    "Удалить профиль инспектора насовсем. 409 in_use — не сбой, а ответ: " +
      "профиль занят, тело перечисляет места (маршруты, объявления); " +
      "сначала снять ссылки, потом удалять. Поставочные профили удалению " +
      "не подлежат. После удаления издать канал инспектора.",
    {
      inspector: inspectorParam,
      ref: z.string().describe("Имя профиля или uuid"),
    },
    async ({ inspector, ref }) => {
      const base = profilesBase(inspector as InspectorName);
      const resolved = resolveRef(await api.getScoped(base), ref as string);

      if ("error" in resolved) {
        return resolved;
      }

      const deleted = await api.sendScoped("DELETE", `${base}/${resolved.uuid}`);
      return {
        deleted,
        publish_channel: channelOf(inspector as InspectorName),
      };
    },
  );

  reg(
    server,
    "auth_source_delete",
    "Удалить источник входа калитки (auth). Умирают его форма, кука и " +
      "пространство сессий; профили, ссылающиеся на источник, удалить " +
      "раньше — иначе 409 in_use. Набор пользователей источника остаётся. " +
      "После удаления издать канал auth.",
    { ref: z.string().describe("Имя источника или uuid") },
    async ({ ref }) => {
      const resolved = resolveRef(
        await api.getScoped("/auth/sources"),
        ref as string,
      );

      if ("error" in resolved) {
        return resolved;
      }

      const deleted = await api.sendScoped(
        "DELETE",
        `/auth/sources/${resolved.uuid}`,
      );
      return { deleted, publish_channel: "auth" };
    },
  );

  reg(
    server,
    "dataset_delete",
    "Удалить набор данных вместе с записями — насовсем. 409 in_use — набор " +
      "занят (профили, маршруты, источники); тело перечисляет места. " +
      "Встроенные (builtin) не удаляются. Посмотреть содержимое перед " +
      "удалением — dataset_get.",
    { ref: z.string().describe("Имя набора или uuid") },
    async ({ ref }) => {
      const found = await findDataset(api, ref as string);

      if ("error" in found) {
        return found;
      }

      const deleted = await api.sendScoped("DELETE", `/datasets/${found.uuid}`);
      return { deleted };
    },
  );

  reg(
    server,
    "publish",
    "Издать сохранённые правки участникам контура. Без channels издаются " +
      "все каналы с dirty=true; с channels — перечисленные (nginx, agent, " +
      "rules, ip, auth, captcha, json, action, cookie, counter, vlai). wait_s > 0 " +
      "дожидается, пока каналы сойдутся, и возвращает итоговую сходимость.",
    {
      channels: z
        .array(z.string())
        .optional()
        .describe("Каналы издания; по умолчанию — все несведённые"),
      wait_s: z
        .number()
        .int()
        .max(120)
        .optional()
        .describe("Сколько секунд ждать сходимости; по умолчанию 30"),
    },
    async ({ channels, wait_s }) => {
      const snapshot = (await api.getScoped("/convergence")) as {
        channels: { id: string; dirty: boolean; state: string }[];
      };

      let targets: string[];

      if (channels !== undefined && (channels as string[]).length > 0) {
        const unknown = (channels as string[]).filter(
          (c) => SEND_PATHS[c] === undefined,
        );
        if (unknown.length > 0) {
          return {
            error: `unknown channels: ${unknown.join(", ")}`,
            known: Object.keys(SEND_PATHS),
          };
        }
        targets = channels as string[];
      } else {
        targets = snapshot.channels
          .filter((c) => c.dirty)
          .map((c) => c.id)
          .filter((id) => SEND_PATHS[id] !== undefined);
      }

      if (targets.length === 0) {
        return {
          sent: [],
          note: "нечего издавать: все каналы сведены",
          convergence: trimConvergence(snapshot),
        };
      }

      const sent: Record<string, unknown> = {};

      for (const id of targets) {
        const path = SEND_PATHS[id];
        if (path === undefined) {
          continue;
        }
        try {
          sent[id] = { ok: true, result: await api.sendScoped("POST", path) };
        } catch (err) {
          if (err instanceof WafApiError) {
            sent[id] = {
              ok: false,
              status: err.detail.status,
              response: err.detail.body,
            };
            continue;
          }
          throw err;
        }
      }

      const deadline = Date.now() + (wait_s ?? 30) * 1000;
      let last = await api.sendScoped("POST", "/convergence/refresh");

      while (Date.now() < deadline) {
        const row = last as {
          channels: { id: string; dirty: boolean; state: string }[];
        };
        const pending = row.channels.filter(
          (c) => targets.includes(c.id) && (c.dirty || c.state !== "ok"),
        );
        if (pending.length === 0) {
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 2000));
        last = await api.sendScoped("POST", "/convergence/refresh");
      }

      return { sent, convergence: trimConvergence(last) };
    },
  );
}

async function resolveServer(
  api: WafApi,
  ref: string,
): Promise<{ uuid: string; name: string } | { error: string; known: string[] }> {
  const row = (await api.getScoped("/servers")) as {
    servers: { uuid: string; name: string }[];
  };
  const srv = row.servers.find((s) => s.uuid === ref || s.name === ref);

  if (srv === undefined) {
    return {
      error: `server "${ref}" not found`,
      known: row.servers.map((s) => s.name),
    };
  }

  return { uuid: srv.uuid, name: srv.name };
}

async function resolveLocation(
  api: WafApi,
  srv: { uuid: string; name: string },
  ref: string,
): Promise<{ uuid: string; path: string } | { error: string; known: string[] }> {
  const row = (await api.getScoped(`/servers/${srv.uuid}/locations`)) as {
    locations: { uuid: string; path: string }[];
  };
  const loc = row.locations.find((l) => l.uuid === ref || l.path === ref);

  if (loc === undefined) {
    return {
      error: `location "${ref}" not found on ${srv.name}`,
      known: row.locations.map((l) => l.path),
    };
  }

  return { uuid: loc.uuid, path: loc.path };
}
