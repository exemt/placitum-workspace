/**
 * Чтение конфигурации: профили инспекторов, маршруты, наборы, предпросмотр
 * nginx и сходимость. Всё без побочных эффектов — эту половину можно выдать
 * агенту без пишущей.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { qs, type WafApi } from "../api.ts";
import { reg } from "../register.ts";
import {
  INSPECTORS,
  firstArray,
  profilesBase,
  resolveRef,
  type InspectorName,
} from "./profiles.ts";

const inspectorParam = z
  .enum(INSPECTORS)
  .describe("Инспектор: modsec, ip, auth, captcha, json, counter, vlai, action, cookie");

export function configReadTools(server: McpServer, api: WafApi): void {
  reg(
    server,
    "profile_list",
    "Профили одного инспектора: имена, uuid, статус. Профиль — документ " +
      "настройки, на который ссылаются маршруты; содержимое — profile_get.",
    { inspector: inspectorParam },
    async ({ inspector }) =>
      api.getScoped(profilesBase(inspector as InspectorName)),
  );

  reg(
    server,
    "profile_get",
    "Документ профиля инспектора — в том виде, в каком его правит панель и " +
      "принимает profile_save. `ref` — имя или uuid.",
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

      return api.getScoped(`${base}/${resolved.uuid}`);
    },
  );

  reg(
    server,
    "route_get",
    "Полный документ маршрута: сервер по имени/uuid, маршрут по path или " +
      "uuid. Возвращает документ location (nginx, waf с инспекторами) и " +
      "наследование. Без `path` — документ сервера со списком маршрутов.",
    {
      server: z.string().describe("Имя сервера или uuid"),
      path: z
        .string()
        .optional()
        .describe("path маршрута (`/`, `waf_deny`, ...) или его uuid"),
    },
    async ({ server: serverRef, path }) => {
      const serversRow = (await api.getScoped("/servers")) as {
        servers: { uuid: string; name: string }[];
      };
      const srv = serversRow.servers.find(
        (s) => s.uuid === serverRef || s.name === serverRef,
      );

      if (srv === undefined) {
        return {
          error: `server "${serverRef}" not found`,
          known: serversRow.servers.map((s) => s.name),
        };
      }

      const locsRow = (await api.getScoped(
        `/servers/${srv.uuid}/locations`,
      )) as { locations: { uuid: string; path: string }[] };

      if (path === undefined) {
        const doc = await api.getScoped(`/servers/${srv.uuid}`);
        return { server: doc, locations: locsRow.locations };
      }

      const loc = locsRow.locations.find(
        (l) => l.uuid === path || l.path === path,
      );

      if (loc === undefined) {
        return {
          error: `location "${path}" not found on ${srv.name}`,
          known: locsRow.locations.map((l) => l.path),
        };
      }

      const [doc, inheritance] = await Promise.all([
        api.getScoped(`/locations/${loc.uuid}`),
        api.getScoped(`/locations/${loc.uuid}/inheritance`),
      ]);

      return { location: doc, inheritance };
    },
  );

  reg(
    server,
    "auth_source_list",
    "Источники входа калитки (auth): форма, кука, пространство сессий, " +
      "набор пользователей. Профили auth ссылаются на источник по имени; " +
      "у формы и куки один хозяин-источник.",
    {},
    async () => {
      const rows = firstArray(
        await api.getScoped("/auth/sources"),
      ) as Record<string, unknown>[];

      return {
        sources: rows.map((s) => {
          const doc = (s.doc ?? {}) as Record<string, unknown>;
          const login = (doc.login ?? {}) as Record<string, unknown>;
          const session = (doc.session ?? {}) as Record<string, unknown>;
          const list = (doc.list ?? {}) as Record<string, unknown>;
          const providers = (doc.providers ?? {}) as Record<string, unknown>;
          const local = (providers.local ?? {}) as Record<string, unknown>;

          return {
            uuid: s.uuid,
            name: s.name,
            provider: s.provider,
            description: s.description,
            login_uri: login.uri,
            login_title: login.title,
            session_cookie: session.cookie,
            fast_cookie: list.cookie,
            sessions_dataset: list.sessions,
            users_dataset: local.users,
          };
        }),
      };
    },
  );

  reg(
    server,
    "dataset_list",
    "Наборы данных пространства: адресные списки (kind=list) для блокировок " +
      "и разрешений, контентные (kind=content) — данные к правилам modsec " +
      "(`*FromFile`) и страницам. Встроенные помечены builtin.",
    {},
    async () => {
      const row = await api.getScoped("/datasets");
      const rows = firstArray(row) as Record<string, unknown>[];

      return {
        datasets: rows.map((d) => ({
          uuid: d.uuid,
          name: d.name,
          kind: d.kind,
          type: d.type,
          active: d.active,
          builtin: d.builtin,
          size: d.size,
          ttl: d.ttl,
          in_nginx: d.in_nginx,
          hash: d.hash,
          description: d.description,
        })),
      };
    },
  );

  reg(
    server,
    "dataset_get",
    "Содержимое набора: для адресного — записи (фильтр q, например по " +
      "адресу), для контентного — текст. `ref` — имя или uuid.",
    {
      ref: z.string().describe("Имя набора или uuid"),
      q: z.string().optional().describe("Фильтр записей адресного набора"),
    },
    async ({ ref, q }) => {
      const found = await findDataset(api, ref as string);

      if ("error" in found) {
        return found;
      }

      const meta = await api.getScoped(`/datasets/${found.uuid}`);

      if (found.kind === "list") {
        const rows = await api.getScoped(
          `/datasets/${found.uuid}/addresses${qs({ q })}`,
        );
        return { dataset: meta, ...(rows as object) };
      }

      const content = (await api.getScoped(
        `/datasets/${found.uuid}/content`,
      )) as Record<string, unknown>;

      return { dataset: meta, content: decodeBlob(content) };
    },
  );

  reg(
    server,
    "address_find",
    "Где числится адрес: поиск по всем адресным наборам пространства. " +
      "Отвечает на «этот адрес уже заблокирован?» до того, как блокировать.",
    { address: z.string().describe("IP или CIDR") },
    async ({ address }) =>
      api.getScoped(`/addresses${qs({ address: address as string })}`),
  );

  reg(
    server,
    "nginx_preview",
    "Собранный nginx-конфиг, каким его увидят ноды: тот же компилятор, что " +
      "печатает файл при издании. Ошибка компиляции возвращается как ответ " +
      "422 с причинами — это состояние конфигурации, а не сбой.",
    {},
    async () => api.getScoped("/config/preview"),
  );

  reg(
    server,
    "convergence_status",
    "Сходимость контура по каналам: сохранено ли, издано ли, применили ли " +
      "участники. dirty=true — есть правки, которые ещё не изданы; их " +
      "издаёт publish.",
    {},
    async () => trimConvergence(await api.getScoped("/convergence")),
  );
}

export async function findDataset(
  api: WafApi,
  ref: string,
): Promise<{ uuid: string; kind: string; name: string } | { error: string; known: string[] }> {
  const rows = firstArray(await api.getScoped("/datasets")) as {
    uuid: string;
    name: string;
    kind: string;
  }[];

  const hit = rows.find((d) => d.uuid === ref || d.name === ref);

  if (hit === undefined) {
    return {
      error: `dataset "${ref}" not found`,
      known: rows.map((d) => d.name),
    };
  }

  return { uuid: hit.uuid, kind: hit.kind, name: hit.name };
}

function decodeBlob(content: Record<string, unknown>): unknown {
  if (typeof content.blob === "string") {
    const text = Buffer.from(content.blob, "base64").toString("utf8");
    // Бинарь не показываем текстом: замены при декодировании — признак,
    // что это не текст, и тогда честнее оставить base64.
    if (!text.includes("�")) {
      return { ...content, blob: undefined, text };
    }
  }
  return content;
}

export function trimConvergence(row: unknown): unknown {
  if (typeof row !== "object" || row === null) {
    return row;
  }
  const snap = row as Record<string, unknown>;
  const channels = Array.isArray(snap.channels)
    ? (snap.channels as Record<string, unknown>[]).map((c) => ({
        id: c.id,
        state: c.state,
        dirty: c.dirty,
        sourceChanged: c.sourceChanged,
      }))
    : snap.channels;

  return { at: snap.at, lamp: snap.lamp, worst: snap.worst, channels };
}
