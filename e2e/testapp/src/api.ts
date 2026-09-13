/*
 * JSON API -- то, что описано контрактом в src/openapi.ts. Здесь важны две
 * вещи, которых нет у обычного приложения:
 *
 *   1. `?broken=1` у /items ломает ОТВЕТ под своей же схемой. Иначе сторону
 *      ответа у инспектора контракта нечем проверить: приложение, которое
 *      всегда право, доказывает только то, что проверка молчит.
 *   2. `echo` возвращает присланное ДОСЛОВНО. В строке JSON полезная нагрузка
 *      ничего не исполняет, зато инспектору на фазе ответа есть что смотреть
 *      -- в HTML то же самое пришлось бы экранировать.
 */

import { createHash, randomUUID } from "node:crypto";
import { Router } from "express";
import type { Request, Response } from "express";

import { selectPage } from "./data.ts";
import type { Item } from "./data.ts";
import { authenticate, peekClaims, SESSION_COOKIE } from "./auth.ts";
import type { Sessions, Tokens } from "./auth.ts";
import { log } from "./log.ts";
import { OPENAPI } from "./openapi.ts";

export interface ApiDeps {
  items: Item[];
  sessions: Sessions;
  tokens: Tokens;
  sessionTtlS: number;
  tokenTtlS: number;
}

declare module "express-serve-static-core" {
  interface Request {
    /** сырое тело кладёт middleware в main.ts: по нему считается размер и sha256 */
    rawBody?: Buffer;
  }
}

/* `cookies` объявлен в типах express как any -- переобъявлять его нельзя, свой
 * разбор кладёт туда Record<string, string>; см. main.ts. */

export function apiRouter(deps: ApiDeps): Router {
  const api = Router();

  api.get("/items", (req, res) => {
    const page = selectPage(
      deps.items,
      req.query.page,
      req.query.per,
      asString(req.query.q),
      asString(req.query.tag),
    );

    if (req.query.broken === "1") {
      /* Нарушение ровно двух видов: не тот тип и пропущенное required-поле. */
      res.json({
        ...page,
        items: page.items.map(({ title: _title, ...rest }) => ({
          ...rest,
          priceRub: String(rest.priceRub),
        })),
      });
      return;
    }

    res.json(page);
  });

  api.get("/items/:id", (req, res) => {
    const one = deps.items.find((item) => item.id === Number(req.params.id));

    if (one === undefined) {
      res.status(404).json({ ok: false, error: "not_found" });
      return;
    }

    res.json(one);
  });

  api.post("/search", (req, res) => {
    const q = asString((req.body as Record<string, unknown>)?.q);
    const tag = asString((req.body as Record<string, unknown>)?.tag);
    const page = selectPage(deps.items, 1, 48, q, tag);

    res.json({ q, echo: q, total: page.total, items: page.items });
  });

  api.post("/orders", (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const one = deps.items.find((item) => item.id === Number(body.itemId));
    const qty = Number(body.qty);

    if (one === undefined || !Number.isInteger(qty) || qty < 1 || qty > 10) {
      res.status(400).json({ ok: false, error: "bad_order" });
      return;
    }

    res.status(201).json({
      ok: true,
      orderId: randomUUID(),
      itemId: one.id,
      qty,
      totalRub: one.priceRub * qty,
      /* Номер уезжает в ответ как пришёл: это цель маскирования у модификатора. */
      card: asString(body.card),
      canary: one.canary,
    });
  });

  api.post("/review", (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const text = asString(body.text);

    res.status(202).json({
      ok: true,
      itemId: Number(body.itemId) || 0,
      length: text.length,
      echo: text,
    });
  });

  api.post("/bulk", (req, res) => {
    const raw = req.rawBody ?? Buffer.alloc(0);
    const rows = Array.isArray((req.body as Record<string, unknown>)?.rows)
      ? ((req.body as { rows: unknown[] }).rows).length
      : 0;

    res.json({
      ok: true,
      rows,
      bytes: raw.length,
      sha256: createHash("sha256").update(raw).digest("hex"),
    });
  });

  /* --- вход, который держит приложение -------------------------------- */

  api.post("/login", (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const user = authenticate(body.username, body.password);

    if (user === undefined) {
      /*
       * Куки нет намеренно. Приложение, ставящее куку и на неудаче, подписало
       * бы сессию атакующего чужим логином первым же неудачным POST -- за это
       * у калитки и включён предикат cookie_new.
       */
      log("info", "login rejected", { user: asString(body.username) });
      res.status(401).json({ ok: false, error: "bad_credentials" });
      return;
    }

    const session = deps.sessions.open(user);

    res.cookie(SESSION_COOKIE, session.sid, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: deps.sessionTtlS * 1000,
    });
    log("info", "login", { user: user.login, sessions: deps.sessions.size });
    res.json({ ok: true, user: user.login, groups: user.groups });
  });

  api.post("/logout", (req, res) => {
    const closed = deps.sessions.close(req.cookies?.[SESSION_COOKIE]);

    res.clearCookie(SESSION_COOKIE, { path: "/" });
    log("info", "logout", { closed, sessions: deps.sessions.size });
    /* Тело обязательно: на 204 фаза ответа не запускается и выход не подсмотреть. */
    res.json({ ok: true });
  });

  api.post("/token", (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const user = authenticate(body.username, body.password);

    if (user === undefined) {
      res.status(401).json({ ok: false, error: "bad_credentials" });
      return;
    }

    const { token, claims } = deps.tokens.issue(user);

    log("info", "token issued", { user: user.login, sid: claims.sid });
    res.json({ token, expiresIn: deps.tokenTtlS });
  });

  api.get("/private/me", (req: Request, res: Response) => {
    const claims = peekClaims(req.get("authorization"));

    if (claims === null) {
      res.status(401).json({ ok: false, error: "no_token" });
      return;
    }

    res.json({ ok: true, claims, verifiedByApp: false });
  });

  api.get("/openapi.json", (_req, res) => {
    res.json(OPENAPI);
  });

  return api;
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}
