/**
 * Документация оператора. Раздаётся двумя путями: ресурсами MCP (для
 * клиентов, которые их читают) и инструментом waf_doc — потому что не
 * всякий агент заглядывает в ресурсы, а прочитать «как это устроено» до
 * первой правки обязан каждый.
 */

import { readdir, readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const DOCS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "docs");

const SUMMARIES: Record<string, string> = {
  overview:
    "устройство контура: ноды, инспекторы, профили, правка→издание→применение",
  journal: "как разбирать журнал атак: записи, фазы, порядок разбора, FP vs атака",
  inspectors: "какие инспекторы есть и что у каждого крутить",
  playbooks:
    "рецепты: блокировка источника, разбор ложного срабатывания, лимиты, проверка правок",
};

export async function docsTools(server: McpServer): Promise<void> {
  const files = (await readdir(DOCS_DIR)).filter((f) => f.endsWith(".md"));
  const topics = files.map((f) => f.replace(/\.md$/, "")).sort();

  for (const topic of topics) {
    server.registerResource(
      `doc-${topic}`,
      `waf-doc://${topic}`,
      {
        title: topic,
        description: SUMMARIES[topic] ?? "документация оператора WAF",
        mimeType: "text/markdown",
      },
      async (uri) => ({
        contents: [
          {
            uri: uri.href,
            mimeType: "text/markdown",
            text: await readFile(join(DOCS_DIR, `${topic}.md`), "utf8"),
          },
        ],
      }),
    );
  }

  const index = topics
    .map((t) => `- ${t} — ${SUMMARIES[t] ?? ""}`)
    .join("\n");

  server.registerTool(
    "waf_doc",
    {
      description:
        "Документация оператора WAF. Прочитать overview и playbooks до " +
        `первой правки конфигурации. Темы:\n${index}`,
      inputSchema: {
        topic: z.enum(topics as [string, ...string[]]),
      },
    },
    async ({ topic }) => ({
      content: [
        {
          type: "text" as const,
          text: await readFile(join(DOCS_DIR, `${topic}.md`), "utf8"),
        },
      ],
    }),
  );
}
