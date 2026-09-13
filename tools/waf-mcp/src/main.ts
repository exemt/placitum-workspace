#!/usr/bin/env node
/**
 * MCP-сервер оператора WAF. Транспорт stdio; всё состояние — на стороне
 * контроллера, сюда не кладётся ничего, кроме прибитого пространства.
 *
 * Окружение:
 *   WAF_URL       адрес контроллера (по умолчанию http://127.0.0.1:8080;
 *                 именно 127.0.0.1 — localhost на Windows уходит в IPv6,
 *                 где проброс Docker не слушает)
 *   WAF_SPACE     имя или uuid пространства; можно опустить, если оно одно
 *   WAF_READONLY  =1 — только анализ и чтение конфигурации, без правок
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { WafApi } from "./api.ts";
import { docsTools } from "./docs.ts";
import { attackTools } from "./tools/attacks.ts";
import { configReadTools } from "./tools/config-read.ts";
import { configWriteTools } from "./tools/config-write.ts";
import { contextTools } from "./tools/context.ts";
import {
  declarationReadTools,
  declarationWriteTools,
} from "./tools/declarations.ts";

const readonly = process.env.WAF_READONLY === "1";

const server = new McpServer({
  name: "waf-operator",
  version: "0.1.0",
});

const api = new WafApi();

await docsTools(server);
contextTools(server, api);
attackTools(server, api);
configReadTools(server, api);
declarationReadTools(server, api);

if (!readonly) {
  configWriteTools(server, api);
  declarationWriteTools(server, api);
}

await server.connect(new StdioServerTransport());

// stdout занят протоколом, всё человеческое — в stderr.
console.error(
  `waf-mcp: controller ${api.base}, ${readonly ? "read-only" : "read-write"}`,
);
