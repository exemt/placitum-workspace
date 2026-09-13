/**
 * Общая обвязка инструментов: JSON в текстовый блок, ошибка контроллера —
 * структурированный ответ с isError, а не падение вызова. Агенту важно
 * читать 409 и 422 как данные: `in_use` и ошибки валидации — часть работы.
 */

import type {
  McpServer,
  ToolCallback,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZodRawShape, objectOutputType, ZodTypeAny } from "zod";

import { WafApiError } from "./api.ts";

export function reg<Shape extends ZodRawShape>(
  server: McpServer,
  name: string,
  description: string,
  shape: Shape,
  handler: (
    args: objectOutputType<Shape, ZodTypeAny>,
  ) => Promise<unknown>,
): void {
  // Дженерик ToolCallback не сводится с objectOutputType в обе стороны;
  // аргументы в рантайме валидирует zod по shape, приведение ничего не прячет.
  const callback = async (args: objectOutputType<Shape, ZodTypeAny>) => {
    try {
      const out = await handler(args);
      return {
        content: [{ type: "text" as const, text: asText(out) }],
      };
    } catch (err) {
      if (err instanceof WafApiError) {
        return {
          content: [
            {
              type: "text" as const,
              text: asText({
                controller_status: err.detail.status,
                response: err.detail.body,
              }),
            },
          ],
          isError: true,
        };
      }
      return {
        content: [
          {
            type: "text" as const,
            text: err instanceof Error ? err.message : String(err),
          },
        ],
        isError: true,
      };
    }
  };

  server.registerTool(
    name,
    { description, inputSchema: shape },
    callback as unknown as ToolCallback<Shape>,
  );
}

function asText(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value, null, 1);
}
