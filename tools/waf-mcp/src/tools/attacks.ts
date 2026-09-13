/**
 * Анализ журнала: список, группы, карточка, сырьё, находки поперёк запросов.
 * Всё ходит через прокси контроллера `/api/search` — форма ответов принадлежит
 * waf-search, здесь она не пересобирается.
 */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { qs, type WafApi } from "../api.ts";
import { reg } from "../register.ts";

/**
 * Общие фильтры списка и групп — те же, что принимает GET /api/audit.
 * `ip` повторяемый и понимает CIDR; `var`/`header`/`param` — пары `имя=значение`.
 */
const FILTERS = {
  verdict: z
    .string()
    .optional()
    .describe("Вердикт: allow | deny; кто вынес — фильтр inspector"),
  code: z.string().optional().describe("Код вердикта (например CRS_ANOMALY)"),
  method: z.string().optional(),
  host: z.string().optional(),
  uri: z.string().optional().describe("Подстрока URI"),
  server: z
    .string()
    .optional()
    .describe(
      "Имя блока server (первое server_name, `_` у перехватчика), можно " +
        "несколько через запятую. Это конфигурация, не заголовок Host",
    ),
  route: z
    .string()
    .optional()
    .describe(
      "Uuid пути (route_get), можно несколько через запятую: все запросы " +
        "этих маршрутов, включая regex",
    ),
  status: z.number().int().optional().describe("HTTP-статус ответа"),
  node: z.string().optional().describe("Имя ноды (edge-01, ...)"),
  phase: z.string().optional().describe("Фаза: request | response | frame | session (кадры и сессии WebSocket)"),
  inspector: z
    .string()
    .optional()
    .describe("Участвовал инспектор (modsec, ip, counter, ...)"),
  ip: z
    .array(z.string())
    .optional()
    .describe("Адрес клиента, можно CIDR, можно несколько"),
  header: z
    .array(z.string())
    .optional()
    .describe("Заголовок вида `имя=подстрока`"),
  param: z
    .array(z.string())
    .optional()
    .describe("Параметр запроса вида `имя=подстрока`"),
  body: z.string().optional().describe("Подстрока в теле"),
  from: z.string().optional().describe("Начало окна, ISO-время"),
  to: z.string().optional().describe("Конец окна, ISO-время"),
} as const;

type FilterArgs = {
  [K in keyof typeof FILTERS]?: unknown;
};

function filterQs(args: FilterArgs): Record<string, string | number | string[] | undefined> {
  return {
    verdict: args.verdict as string | undefined,
    code: args.code as string | undefined,
    method: args.method as string | undefined,
    host: args.host as string | undefined,
    uri: args.uri as string | undefined,
    route: args.route as string | undefined,
    server: args.server as string | undefined,
    status: args.status as number | undefined,
    node: args.node as string | undefined,
    phase: args.phase as string | undefined,
    inspector: args.inspector as string | undefined,
    ip: args.ip as string[] | undefined,
    header: args.header as string[] | undefined,
    param: args.param as string[] | undefined,
    body: args.body as string | undefined,
    from: args.from as string | undefined,
    to: args.to as string | undefined,
  };
}

export function attackTools(server: McpServer, api: WafApi): void {
  reg(
    server,
    "attacks_search",
    "Журнал запросов с фильтрами: вердикт, код, метод, host, uri, адрес " +
      "клиента (CIDR), нода, фаза, инспектор, подстрока в теле, окно времени. " +
      "Каждая запись — запрос с ключом node+ray; разворот — attack_card.",
    {
      ...FILTERS,
      ray: z.string().optional().describe("Точный ray запроса"),
      limit: z.number().int().max(200).optional().describe("По умолчанию 50"),
      offset: z.number().int().optional(),
    },
    async (args) =>
      api.get(
        `/api/search/audit${qs({
          ...filterQs(args),
          ray: args.ray,
          limit: args.limit ?? 50,
          offset: args.offset,
        })}`,
      ),
  );

  reg(
    server,
    "attacks_top",
    "Топы журнала: тот же фильтр, свёрнутый по осям. Оси: ip, host, uri, " +
      "server (имя блока server), route (uuid пути: regex-путь схлопывает " +
      "разные uri в одну строку), " +
      "method, status, verdict, code, by (кто вынес вердикт), node, phase — " +
      "до четырёх через запятую. Отвечает на «какие адреса долбят» и «куда».",
    {
      ...FILTERS,
      by: z
        .string()
        .describe("Оси группировки через запятую, например `ip,uri`"),
      limit: z.number().int().max(200).optional(),
    },
    async (args) =>
      api.get(
        `/api/search/audit/groups${qs({
          ...filterQs(args),
          by: args.by,
          limit: args.limit ?? 30,
        })}`,
      ),
  );

  reg(
    server,
    "attack_card",
    "Карточка одного запроса по node+ray: запись журнала, участвовавшие " +
      "инспекторы с их вердиктами и находки (какие правила стрельнули). " +
      "Сырые заголовки/аргументы/тело — attack_content.",
    {
      node: z.string(),
      ray: z.string(),
    },
    async ({ node, ray }) => {
      const base = `/api/search/audit/${encodeURIComponent(node)}/${encodeURIComponent(ray)}`;
      const [record, inspectors, findings] = await Promise.all([
        api.get(base),
        api.get(`${base}/inspectors`),
        api.get(`${base}/findings`),
      ]);
      return { record, inspectors, findings };
    },
  );

  reg(
    server,
    "attack_content",
    "Сырьё запроса с обменника: headers, args или body. Тело может быть " +
      "большим — читается порциями через offset/limit (байты).",
    {
      node: z.string(),
      ray: z.string(),
      part: z.enum(["headers", "args", "body"]),
      offset: z.number().int().optional(),
      limit: z.number().int().optional().describe("По умолчанию до 65536 байт"),
    },
    async ({ node, ray, part, offset, limit }) =>
      api.get(
        `/api/search/audit/${encodeURIComponent(node)}/${encodeURIComponent(ray)}/${part}${qs(
          { offset, limit: limit ?? (part === "body" ? 65536 : undefined) },
        )}`,
      ),
  );

  reg(
    server,
    "findings_search",
    "Поиск находок поперёк запросов: где ещё стреляло правило. Главный " +
      "инструмент оценки масштаба ложного срабатывания или атаки — сначала " +
      "attack_card показывает правило, потом сюда с rule.",
    {
      rule: z.string().optional().describe("Идентификатор правила (например 942100)"),
      inspector: z.string().optional(),
      profile: z.string().optional(),
      verdict: z.string().optional(),
      code: z.string().optional(),
      severity: z.string().optional(),
      node: z.string().optional(),
      phase: z.string().optional(),
      from: z.string().optional(),
      to: z.string().optional(),
      limit: z.number().int().max(200).optional(),
      offset: z.number().int().optional(),
    },
    async (args) =>
      api.get(
        `/api/search/findings${qs({
          rule: args.rule,
          inspector: args.inspector,
          profile: args.profile,
          verdict: args.verdict,
          code: args.code,
          severity: args.severity,
          node: args.node,
          phase: args.phase,
          from: args.from,
          to: args.to,
          limit: args.limit ?? 50,
          offset: args.offset,
        })}`,
      ),
  );

  reg(
    server,
    "waf_logs",
    "Журнал процессов нод (не атаки): error_log nginx, логи агента и " +
      "инспекторов. Нужен, когда правка «не доехала» или нода ведёт себя " +
      "странно. `facets: true` вернёт, кто и по какому сервису писал в окно.",
    {
      writer: z.string().optional().describe("Кто писал (nginx, agent, ...)"),
      service: z.string().optional(),
      severity: z.string().optional().describe("error | warn | info | ..."),
      text: z.string().optional().describe("Подстрока в строке лога"),
      from: z.string().optional(),
      to: z.string().optional(),
      limit: z.number().int().max(500).optional(),
      offset: z.number().int().optional(),
      facets: z
        .boolean()
        .optional()
        .describe("Вместо строк вернуть срез: писатели и сервисы окна"),
    },
    async (args) => {
      if (args.facets === true) {
        return api.get(
          `/api/search/logs/facets${qs({ from: args.from, to: args.to })}`,
        );
      }
      return api.get(
        `/api/search/logs${qs({
          writer: args.writer,
          service: args.service,
          severity: args.severity,
          text: args.text,
          from: args.from,
          to: args.to,
          limit: args.limit ?? 100,
          offset: args.offset,
        })}`,
      );
    },
  );
}
