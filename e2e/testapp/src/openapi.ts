/*
 * Контракт API. Это не документация ради документации: этот же документ
 * кладётся в раздел данных контроллера объектом содержимого, и по нему
 * инспектор контракта судит и запрос, и ответ.
 *
 * Поэтому схемы нарочно строгие -- `required` и `additionalProperties: false`
 * везде, где можно. На вольной схеме нарушение не построить, и проверять было
 * бы нечего.
 *
 * Префикс /api описан в `servers[].url`: маршрутизатор инспектора срезает его
 * всегда, и `base_path` в профиле для этого не нужен.
 */

const item = {
  type: "object",
  additionalProperties: false,
  required: ["id", "title", "tag", "priceRub", "obj", "canary", "blurb"],
  properties: {
    id: { type: "integer", minimum: 1 },
    title: { type: "string", maxLength: 200 },
    tag: { type: "string", maxLength: 40 },
    priceRub: { type: "integer", minimum: 0 },
    obj: { type: "string", pattern: "^obj=[0-9]+$" },
    canary: { type: "string", pattern: "^canary-[0-9a-f]{8}$" },
    blurb: { type: "string", maxLength: 500 },
  },
} as const;

const error = {
  type: "object",
  additionalProperties: false,
  required: ["ok", "error"],
  properties: {
    ok: { type: "boolean" },
    error: { type: "string" },
  },
} as const;

const json = (schema: unknown) => ({
  content: { "application/json": { schema } },
});

export const OPENAPI = {
  openapi: "3.0.3",
  info: {
    title: "Витрина",
    version: "1.0.0",
    description:
      "API защищаемого приложения стенда. Схемы строгие намеренно: по ним инспектор контракта судит запрос и ответ.",
  },
  servers: [{ url: "/api" }],
  paths: {
    "/items": {
      get: {
        operationId: "listItems",
        parameters: [
          { name: "page", in: "query", schema: { type: "integer", minimum: 1 } },
          { name: "per", in: "query", schema: { type: "integer", enum: [12, 24, 48] } },
          { name: "q", in: "query", schema: { type: "string", maxLength: 200 } },
          { name: "tag", in: "query", schema: { type: "string", maxLength: 40 } },
          {
            name: "broken",
            in: "query",
            description:
              "1 -- ответ намеренно нарушает эту же схему: priceRub строкой, title выброшен. Так проверяется сторона ОТВЕТА.",
            schema: { type: "string", enum: ["1"] },
          },
        ],
        responses: {
          "200": {
            description: "страница выдачи",
            ...json({
              type: "object",
              additionalProperties: false,
              required: ["page", "per", "total", "pages", "items"],
              properties: {
                page: { type: "integer", minimum: 1 },
                per: { type: "integer", enum: [12, 24, 48] },
                total: { type: "integer", minimum: 0 },
                pages: { type: "integer", minimum: 1 },
                items: { type: "array", items: item },
              },
            }),
          },
        },
      },
    },
    "/items/{id}": {
      get: {
        operationId: "getItem",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer", minimum: 1 } }],
        responses: {
          "200": { description: "позиция", ...json(item) },
          "404": { description: "нет такой", ...json(error) },
        },
      },
    },
    "/search": {
      post: {
        operationId: "search",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: false,
                required: ["q"],
                properties: {
                  q: { type: "string", maxLength: 200 },
                  tag: { type: "string", maxLength: 40 },
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description: "что нашлось",
            ...json({
              type: "object",
              additionalProperties: false,
              required: ["q", "echo", "total", "items"],
              properties: {
                q: { type: "string" },
                echo: {
                  type: "string",
                  description:
                    "запрос дословно, без экранирования: строка JSON ничего не исполняет, зато инспектору на фазе ответа есть что смотреть",
                },
                total: { type: "integer", minimum: 0 },
                items: { type: "array", items: item },
              },
            }),
          },
        },
      },
    },
    "/orders": {
      post: {
        operationId: "createOrder",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: false,
                required: ["itemId", "qty", "card"],
                properties: {
                  itemId: { type: "integer", minimum: 1 },
                  qty: { type: "integer", minimum: 1, maximum: 10 },
                  card: { type: "string", pattern: "^[0-9]{16}$" },
                },
              },
            },
          },
        },
        responses: {
          "201": {
            description: "чек",
            ...json({
              type: "object",
              additionalProperties: false,
              required: ["ok", "orderId", "itemId", "qty", "totalRub", "card", "canary"],
              properties: {
                ok: { type: "boolean" },
                orderId: { type: "string" },
                itemId: { type: "integer" },
                qty: { type: "integer" },
                totalRub: { type: "integer" },
                card: { type: "string" },
                canary: { type: "string", pattern: "^canary-[0-9a-f]{8}$" },
              },
            }),
          },
          "400": { description: "не по схеме", ...json(error) },
        },
      },
    },
    "/review": {
      post: {
        operationId: "postReview",
        description: "Свободный текст: то, чем кормят модель.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: false,
                required: ["itemId", "text"],
                properties: {
                  itemId: { type: "integer", minimum: 1 },
                  text: { type: "string", minLength: 1, maxLength: 4000 },
                },
              },
            },
          },
        },
        responses: {
          "202": {
            description: "принято",
            ...json({
              type: "object",
              additionalProperties: false,
              required: ["ok", "itemId", "length", "echo"],
              properties: {
                ok: { type: "boolean" },
                itemId: { type: "integer" },
                length: { type: "integer" },
                echo: { type: "string" },
              },
            }),
          },
        },
      },
    },
    "/bulk": {
      post: {
        operationId: "bulk",
        description: "Крупное тело: уезжает в обменник, а не инлайном в сообщении.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: false,
                required: ["rows"],
                properties: {
                  rows: {
                    type: "array",
                    maxItems: 100000,
                    items: {
                      type: "object",
                      additionalProperties: false,
                      required: ["id", "text"],
                      properties: {
                        id: { type: "integer" },
                        text: { type: "string", maxLength: 4000 },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description: "сколько приняли",
            ...json({
              type: "object",
              additionalProperties: false,
              required: ["ok", "rows", "bytes", "sha256"],
              properties: {
                ok: { type: "boolean" },
                rows: { type: "integer" },
                bytes: { type: "integer" },
                sha256: { type: "string" },
              },
            }),
          },
        },
      },
    },
    "/login": {
      post: {
        operationId: "login",
        description:
          "Вход приложения. Калитка (провайдер app) подсматривает его на фазе ответа: удача ставит НОВУЮ куку и отвечает ok:true.",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: false,
                required: ["username", "password"],
                properties: {
                  username: { type: "string", maxLength: 64 },
                  password: { type: "string", maxLength: 128 },
                },
              },
            },
            "application/x-www-form-urlencoded": {
              schema: {
                type: "object",
                required: ["username", "password"],
                properties: {
                  username: { type: "string", maxLength: 64 },
                  password: { type: "string", maxLength: 128 },
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description: "вошли",
            ...json({
              type: "object",
              additionalProperties: false,
              required: ["ok", "user", "groups"],
              properties: {
                ok: { type: "boolean" },
                user: { type: "string" },
                groups: { type: "array", items: { type: "string" } },
              },
            }),
          },
          "401": { description: "не вошли, куки нет", ...json(error) },
        },
      },
    },
    "/logout": {
      post: {
        operationId: "logout",
        description: "Отвечает ТЕЛОМ, не 204: на 204 модуль не запускает фазу ответа и выход не подсмотреть.",
        responses: {
          "200": {
            description: "вышли",
            ...json({
              type: "object",
              additionalProperties: false,
              required: ["ok"],
              properties: { ok: { type: "boolean" } },
            }),
          },
        },
      },
    },
    "/token": {
      post: {
        operationId: "issueToken",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: false,
                required: ["username", "password"],
                properties: {
                  username: { type: "string", maxLength: 64 },
                  password: { type: "string", maxLength: 128 },
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description: "токен RS256",
            ...json({
              type: "object",
              additionalProperties: false,
              required: ["token", "expiresIn"],
              properties: {
                token: { type: "string" },
                expiresIn: { type: "integer" },
              },
            }),
          },
          "401": { description: "не те учётные данные", ...json(error) },
        },
      },
    },
    "/private/me": {
      get: {
        operationId: "me",
        description: "Закрыто калиткой (провайдер jwt). Приложение подпись НЕ проверяет — показывает притязания как есть.",
        responses: {
          "200": {
            description: "притязания токена",
            ...json({
              type: "object",
              additionalProperties: false,
              required: ["ok", "claims", "verifiedByApp"],
              properties: {
                ok: { type: "boolean" },
                claims: { type: "object" },
                verifiedByApp: { type: "boolean" },
              },
            }),
          },
          "401": { description: "токена нет", ...json(error) },
        },
      },
    },
  },
} as const;
