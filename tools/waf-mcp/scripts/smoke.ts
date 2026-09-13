/**
 * Дымовой прогон против живого контроллера: поднимает сервер по stdio,
 * перечисляет инструменты и вызывает читающие. Пишущие не трогает —
 * прогон не должен менять стенд.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const client = new Client({ name: "smoke", version: "0.0.0" });

await client.connect(
  new StdioClientTransport({
    command: process.execPath,
    args: ["src/main.ts"],
    env: { ...process.env },
  }),
);

const tools = await client.listTools();
console.log(
  "tools:",
  tools.tools.map((t) => t.name).sort().join(", "),
);

const calls: [string, Record<string, unknown>][] = [
  ["waf_doc", { topic: "overview" }],
  ["waf_map", {}],
  ["fleet_status", {}],
  ["attacks_top", { by: "ip,verdict", limit: 5 }],
  ["attacks_search", { limit: 2 }],
  ["profile_list", { inspector: "modsec" }],
  ["auth_source_list", {}],
  ["inspector_declarations", {}],
  ["dataset_list", {}],
  ["address_find", { address: "10.99.99.99" }],
  ["convergence_status", {}],
  ["nginx_preview", {}],
];

for (const [name, args] of calls) {
  const res = await client.callTool({ name, arguments: args });
  const first = Array.isArray(res.content) ? res.content[0] : undefined;
  const text =
    first !== undefined && first.type === "text" ? first.text : "(no text)";
  const mark = res.isError === true ? "ERR " : "ok  ";
  console.log(`${mark}${name}: ${text.slice(0, 200).replaceAll("\n", " ")}`);
}

// Карточка по живой записи: ключ берётся из только что найденного списка.
const listRes = await client.callTool({
  name: "attacks_search",
  arguments: { limit: 1 },
});
const listFirst = Array.isArray(listRes.content) ? listRes.content[0] : undefined;
if (listFirst?.type === "text") {
  const row = JSON.parse(listFirst.text) as {
    items?: { node?: string; ray?: string }[];
  };
  const item = row.items?.[0];
  if (item?.node !== undefined && item.ray !== undefined) {
    const card = await client.callTool({
      name: "attack_card",
      arguments: { node: item.node, ray: item.ray },
    });
    const cardFirst = Array.isArray(card.content) ? card.content[0] : undefined;
    const text = cardFirst?.type === "text" ? cardFirst.text : "(no text)";
    const mark = card.isError === true ? "ERR " : "ok  ";
    console.log(`${mark}attack_card: ${text.slice(0, 200).replaceAll("\n", " ")}`);
  }
}

await client.close();
