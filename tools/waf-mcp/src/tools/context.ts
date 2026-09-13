/**
 * Ориентация: карта защищаемого и состояние контура. С этих двух инструментов
 * агент начинает любую сессию — без карты он не знает, что настраивает,
 * без пульса — жив ли контур вообще.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { WafApi } from "../api.ts";
import { reg } from "../register.ts";

interface ServerRow {
  uuid: string;
  name: string;
  server_names: string[];
  enabled: boolean;
}

interface LocationRow {
  uuid: string;
  match: string;
  path: string;
  position: number;
  enabled: boolean;
  handler: string;
  protocol?: string;
  waf?: { enabled?: boolean; inspectors?: { name?: string }[] } & Record<
    string,
    unknown
  >;
}

export function contextTools(server: McpServer, api: WafApi): void {
  reg(
    server,
    "waf_map",
    "Карта защищаемого: серверы (виртуальные хосты), их маршруты и какие " +
      "инспекторы включены на каждом маршруте. Первый вызов любой сессии. " +
      "Подробный документ маршрута — route_get, профили инспекторов — profile_list.",
    {},
    async () => {
      const scope = await api.scope();
      const serversRow = (await api.getScoped("/servers")) as {
        servers: ServerRow[];
      };

      const servers = [];
      for (const s of serversRow.servers) {
        const locsRow = (await api.getScoped(
          `/servers/${s.uuid}/locations`,
        )) as { locations: LocationRow[] };

        servers.push({
          uuid: s.uuid,
          name: s.name,
          server_names: s.server_names,
          enabled: s.enabled,
          locations: locsRow.locations.map((l) => ({
            uuid: l.uuid,
            match: l.match,
            path: l.path,
            position: l.position,
            enabled: l.enabled,
            handler: l.handler,
            protocol: l.protocol ?? "http",
            waf_enabled: l.waf?.enabled ?? false,
            waf: l.waf,
          })),
        });
      }

      return { space: scope, servers };
    },
  );

  reg(
    server,
    "fleet_status",
    "Пульс контура: ноды и агенты (статус, применённые поколения, cpu/память, " +
      "rps и коды ответов), инспекторы с их репликами, обменники, ошибки. " +
      "Отвечает на «жив ли WAF, доехала ли раскатка, куда идёт трафик».",
    {},
    async () => {
      const snap = (await api.get("/api/fleet")) as Record<string, unknown>;

      // Снимок большой; хост-метрики агента сворачиваются до сути, чтобы
      // ответ читался, а не листался.
      const agents = Array.isArray(snap.agents)
        ? (snap.agents as Record<string, unknown>[]).map(trimAgent)
        : snap.agents;

      return {
        at: snap.at,
        agents,
        orphans: snap.orphans,
        inspectors: snap.inspectors,
        stores: snap.stores,
        services: snap.services,
        routes: snap.routes,
      };
    },
  );
}

function trimAgent(agent: Record<string, unknown>): Record<string, unknown> {
  const host = agent.host as
    | {
        cpu?: { cores?: number; usage?: number; load1?: number };
        memory?: { total?: number; available?: number };
        disk?: unknown;
      }
    | undefined;

  return {
    uuid: agent.uuid,
    kind: agent.kind,
    status: agent.status,
    age_ms: agent.age_ms,
    apply: agent.apply,
    agent_conf: agent.agent_conf,
    rps: agent.rps,
    codes: agent.codes,
    health: agent.health,
    cpu_usage: host?.cpu?.usage,
    load1: host?.cpu?.load1,
    mem_available: host?.memory?.available,
    mem_total: host?.memory?.total,
  };
}
