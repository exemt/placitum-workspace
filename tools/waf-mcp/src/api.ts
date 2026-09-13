/**
 * Тонкий клиент API контроллера. Сервер MCP не знает ни ClickHouse, ни NATS,
 * ни базы — только REST контроллера: тот сам проксирует поиск в waf-search
 * и держит границу валидации. Ошибки контроллера отдаются агенту как есть,
 * с кодом и телом: `{"error":"in_use"}` для него не сбой, а ответ.
 */

const DEFAULT_URL = "http://127.0.0.1:8080";

export interface ApiError {
  status: number;
  body: unknown;
}

export class WafApi {
  readonly base: string;
  private scopeUuid: string | undefined;
  private readonly scopeName: string | undefined;

  constructor(env: NodeJS.ProcessEnv = process.env) {
    this.base = (env.WAF_URL ?? DEFAULT_URL).replace(/\/$/, "");
    this.scopeUuid = undefined;
    this.scopeName = env.WAF_SPACE;
  }

  /**
   * Пространство прибивается один раз на процесс: либо из `WAF_SPACE`
   * (имя или uuid), либо единственное существующее. Несколько пространств
   * без явного выбора — ошибка конфигурации сервера, а не повод гадать.
   */
  async scope(): Promise<string> {
    if (this.scopeUuid !== undefined) {
      return this.scopeUuid;
    }

    const row = (await this.get("/api/spaces")) as {
      spaces: { uuid: string; name: string }[];
    };
    const spaces = row.spaces;

    if (this.scopeName !== undefined) {
      const found = spaces.find(
        (s) => s.uuid === this.scopeName || s.name === this.scopeName,
      );
      if (found === undefined) {
        throw new Error(
          `space "${this.scopeName}" not found; known: ${spaces.map((s) => s.name).join(", ")}`,
        );
      }
      this.scopeUuid = found.uuid;
      return found.uuid;
    }

    if (spaces.length === 1 && spaces[0] !== undefined) {
      this.scopeUuid = spaces[0].uuid;
      return spaces[0].uuid;
    }

    throw new Error(
      `WAF_SPACE is required: controller has ${spaces.length} spaces (${spaces.map((s) => s.name).join(", ")})`,
    );
  }

  async get(path: string): Promise<unknown> {
    return this.call("GET", path);
  }

  async getScoped(path: string): Promise<unknown> {
    const scope = await this.scope();
    return this.call("GET", `/api/${scope}${path}`);
  }

  async sendScoped(
    method: "POST" | "PUT" | "DELETE",
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    const scope = await this.scope();
    return this.call(method, `/api/${scope}${path}`, body);
  }

  private async call(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    const res = await fetch(`${this.base}${path}`, {
      method,
      headers: body === undefined ? {} : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });

    const text = await res.text();
    let parsed: unknown = text;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      // предпросмотр nginx и содержимое наборов приезжают text/plain
    }

    if (!res.ok) {
      const err: ApiError = { status: res.status, body: parsed };
      throw new WafApiError(err);
    }

    return parsed;
  }
}

export class WafApiError extends Error {
  readonly detail: ApiError;

  constructor(detail: ApiError) {
    super(`controller answered ${detail.status}`);
    this.detail = detail;
  }
}

/** Строка запроса из объекта: undefined выбрасывается, массивы повторяются. */
export function qs(
  params: Record<string, string | number | string[] | undefined>,
): string {
  const out = new URLSearchParams();

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        out.append(key, item);
      }
      continue;
    }
    out.append(key, String(value));
  }

  const text = out.toString();
  return text === "" ? "" : `?${text}`;
}
