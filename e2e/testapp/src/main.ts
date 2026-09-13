/*
 * Сборка приложения: middleware, страницы, монтаж API и сокетов.
 *
 * Приложение не знает про WAF и ничего не решает про вердикты -- это обычный
 * апстрим за проксёй. Единственное, что оно про контур умеет, -- показать
 * заголовки, которые ему подставила калитка (/whoami, /account, /admin).
 * Закрытость /account и /admin держит калитка, а не приложение: напрямую, в
 * обход контура, они открыты, и это правильно -- иначе проверялось бы, что
 * приложение умеет закрывать само себя.
 */

import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import express from "express";
import type { NextFunction, Request, Response } from "express";

import { apiRouter } from "./api.ts";
import { Sessions, SESSION_COOKIE, Tokens, peekClaims } from "./auth.ts";
import { load } from "./config.ts";
import { buildItems, canaryOf, selectPage } from "./data.ts";
import { log, setLevel } from "./log.ts";
import { OPENAPI } from "./openapi.ts";
import * as view from "./view.ts";
import { mountSockets } from "./ws.ts";

const cfg = load();
setLevel(cfg.logLevel);

const items = buildItems(cfg.items);
const sessions = new Sessions(cfg.sessionTtlS);
const tokens = new Tokens(cfg.jwtPrivateKeyPem, cfg.tokenTtlS, "shop.waf.test");
const publicDir = join(dirname(fileURLToPath(import.meta.url)), "..", "public");

const app = express();

/* Заголовок Server приложение не печатает: у модификатора он цель `unset`. */
app.disable("x-powered-by");
app.set("etag", false);

/* --- middleware --------------------------------------------------------- */

/*
 * Сырое тело нужно /api/bulk и /upload: они считают размер и sha256 того, что
 * реально доехало. Разобранное тело для этого не годится -- после разбора
 * байты уже не те.
 */
const keepRaw = (req: Request, _res: Response, buf: Buffer): void => {
  req.rawBody = buf;
};

app.use(express.json({ limit: cfg.maxBodyBytes, verify: keepRaw }));
app.use(express.urlencoded({ extended: false, limit: cfg.maxBodyBytes, verify: keepRaw }));
app.use(express.text({ type: "text/*", limit: cfg.maxBodyBytes, verify: keepRaw }));
app.use(express.raw({ type: "multipart/*", limit: cfg.maxBodyBytes, verify: keepRaw }));

/* Разбор куки свой, ради одной строки тащить зависимость незачем. */
app.use((req, _res, next) => {
  const raw = req.headers.cookie ?? "";

  req.cookies = Object.fromEntries(
    raw
      .split(";")
      .map((pair) => pair.trim())
      .filter((pair) => pair !== "")
      .map((pair) => {
        const eq = pair.indexOf("=");
        return eq === -1
          ? [pair, ""]
          : [pair.slice(0, eq), decodeURIComponent(pair.slice(eq + 1))];
      }),
  );

  next();
});

/*
 * Общие заголовки ответа. X-App-Secret здесь ради модификатора: это цель
 * `unset`, и по её исчезновению видно, что группа заголовков отработала.
 */
app.use((req, res, next) => {
  res.setHeader("X-App-Name", cfg.name);
  res.setHeader("X-App-Version", "1.0.0");
  res.setHeader("X-App-Secret", `sekret-${canaryOf(`hdr:${req.path}`).slice(7)}`);
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.use((req, res, next) => {
  const started = performance.now();

  /* originalUrl, а не path: внутри смонтированной статики path уже без /static. */
  const url = req.originalUrl;

  res.on("finish", () => {
    log("info", "request", {
      method: req.method,
      path: url,
      status: res.statusCode,
      user: req.get("x-waf-user") ?? "",
      took_ms: Number((performance.now() - started).toFixed(3)),
    });
  });

  next();
});

function viewerOf(req: Request): view.Viewer {
  const groups = (req.get("x-waf-groups") ?? "")
    .split(/[,\s]+/)
    .filter((g) => g !== "");

  return {
    user: req.get("x-waf-user") ?? "",
    groups,
    appLogin: sessions.get(req.cookies?.[SESSION_COOKIE])?.login ?? "",
  };
}

function html(res: Response, body: string, status = 200): void {
  res.status(status).type("html").send(body);
}

/* --- служебное ---------------------------------------------------------- */

app.get("/healthz", (_req, res) => {
  res.type("text").send("ok\n");
});

app.get("/keys/jwt.pub", (_req, res) => {
  res.type("text/plain").send(tokens.publicPem);
});

app.get("/openapi.json", (_req, res) => {
  res.json(OPENAPI);
});

app.use("/static", express.static(publicDir, { maxAge: "1h", index: false }));

/* --- страницы ----------------------------------------------------------- */

app.get("/", (req, res) => {
  html(res, view.home(viewerOf(req), items.slice(0, 6)));
});

app.get("/catalog", (req, res) => {
  const q = asString(req.query.q);
  const tag = asString(req.query.tag);

  html(res, view.catalog(viewerOf(req), selectPage(items, req.query.page, req.query.per, q, tag), q, tag));
});

app.get("/item/:id", (req, res) => {
  const one = items.find((candidate) => candidate.id === Number(req.params.id));

  if (one === undefined) {
    html(res, view.notice(viewerOf(req), "Нет такой позиции", `Позиция ${req.params.id} не найдена.`), 404);
    return;
  }

  html(res, view.item(viewerOf(req), one));
});

app.get("/order/:id", (req, res) => {
  renderOrder(req, res, Number(req.params.id), 1);
});

app.post("/order", (req, res) => {
  const body = (req.body ?? {}) as Record<string, unknown>;

  renderOrder(req, res, Number(body.itemId), Math.min(Math.max(1, Number(body.qty) || 1), 10));
});

function renderOrder(req: Request, res: Response, id: number, qty: number): void {
  const one = items.find((candidate) => candidate.id === id);

  if (one === undefined) {
    html(res, view.notice(viewerOf(req), "Нет такой позиции", `Позиция ${id} не найдена.`), 404);
    return;
  }

  html(res, view.order(viewerOf(req), one, qty));
}

app.get("/leak", (req, res) => {
  html(res, view.leak(viewerOf(req)));
});

app.get("/socket", (req, res) => {
  html(res, view.socketPage(viewerOf(req)));
});

/*
 * Закрытые разделы. Закрывает их калитка на маршруте; сюда запрос доходит уже
 * пропущенным, и приложение только показывает, кем его признали.
 */
app.get("/account", (req, res) => {
  html(res, view.gated(viewerOf(req), "/account", "Личное", "Раздел за калиткой: пускают любого вошедшего."));
});

app.get("/admin", (req, res) => {
  html(res, view.gated(viewerOf(req), "/admin", "Админка", "Раздел за калиткой: нужна группа admins."));
});

app.get("/profile", (req, res) => {
  const viewer = viewerOf(req);

  html(res, view.profile(viewer, viewer.appLogin !== ""), viewer.appLogin === "" ? 401 : 200);
});

/* Поверхность обхода каталога: имя отражается, диск не читается вовсе. */
app.get("/files", (req, res) => {
  html(res, view.files(viewerOf(req), asString(req.query.name)));
});

/* --- крупные тела ------------------------------------------------------- */

app.get("/big", (req, res) => {
  const want = Math.min(Math.max(1, Number(req.query.kb) || 64), Math.floor(cfg.maxBigBytes / 1024));
  const line = `${canaryOf("big:line")} строка наполнителя, чтобы тело ответа было предсказуемого размера.\n`;
  const times = Math.ceil((want * 1024) / Buffer.byteLength(line));

  res.type("text/plain").send(line.repeat(times));
});

app.post("/upload", (req, res) => {
  const raw = req.rawBody ?? Buffer.alloc(0);

  /* Файл никуда не пишется: приложение честное и диска не касается. */
  res.json({
    ok: true,
    contentType: req.get("content-type") ?? "",
    bytes: raw.length,
    sha256: createHash("sha256").update(raw).digest("hex"),
    head: raw.subarray(0, 200).toString("utf8"),
  });
});

/* --- площадка нагрузки -------------------------------------------------- */

/*
 * Любой метод и любой путь под /load и /logic: крошечный ответ, тело не
 * разбирается и не отражается. Сюда смотрят маршруты нагрузочных кейсов (tests/load): предмет
 * проверки -- контур между клиентом и приложением, и приложению незачем
 * добавлять свою цену к каждой ступени. bytes -- сколько байт тела доехало,
 * чтобы было видно, что тело не срезано по дороге.
 */
app.use(["/load", "/logic"], (req, res) => {
  const body: Record<string, unknown> = {
    ok: true,
    method: req.method,
    path: req.path,
    bytes: req.rawBody?.length ?? 0,
  };

  /*
   * `?objects=<n>` -- выдача штуками. Нужна поведенческим кейсам: счётчик
   * меряет не запросы, а объекты в ответе (`regex_count` по `obj=<id>`, ровно
   * одно вхождение на объект -- та же метка, что на карточках витрины), и
   * прогон обязан управлять их числом. Метка `canary-…` рядом -- материал для
   * модификатора: по ней видно, замаскировали ответ или отдали как есть.
   *
   * Без параметра ответ прежний, байт в байт: нагрузочные ступени, снятые
   * раньше, остаются сравнимыми.
   */
  const objects = Math.min(Math.max(0, Number(req.query.objects) || 0), 200);

  if (objects > 0) {
    body.objects = Array.from({ length: objects }, (_, i) => ({
      obj: `obj=${i + 1}`,
      canary: canaryOf(`logic:obj:${i + 1}`),
    }));
  }

  res.json(body);
});

/* --- кто я -------------------------------------------------------------- */

app.all("/whoami", (req, res) => {
  const viewer = viewerOf(req);
  const payload = {
    app: cfg.name,
    method: req.method,
    path: req.path,
    query: req.query,
    /* Заголовки целиком: именно тут видно X-WAF-User, X-WAF-Groups, X-WAF-Captcha и ray. */
    headers: req.headers,
    cookies: Object.keys(req.cookies ?? {}),
    session: viewer.appLogin === "" ? null : { login: viewer.appLogin },
    tokenClaims: peekClaims(req.get("authorization")),
    bodyBytes: req.rawBody?.length ?? 0,
    canary: canaryOf("whoami"),
  };

  if ((req.get("accept") ?? "").includes("text/html")) {
    html(
      res,
      view.notice(viewer, "Кто я", "Полный ответ — в JSON: тот же адрес с Accept: application/json.", "/whoami")
        .replace("</main>", `<pre class="dump">${view.esc(JSON.stringify(payload, null, 2))}</pre></main>`),
    );
    return;
  }

  res.json(payload);
});

/* --- API ---------------------------------------------------------------- */

app.use(
  "/api",
  apiRouter({ items, sessions, tokens, sessionTtlS: cfg.sessionTtlS, tokenTtlS: cfg.tokenTtlS }),
);

/* --- хвост -------------------------------------------------------------- */

app.use((req, res) => {
  if ((req.get("accept") ?? "").includes("text/html")) {
    html(res, view.notice(viewerOf(req), "Нет такой страницы", `${req.method} ${req.path}`), 404);
    return;
  }

  res.status(404).json({ ok: false, error: "not_found" });
});

app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
  /*
   * Разбор тела падает на битом JSON и на превышении лимита. Это законный
   * ответ приложения, а не сбой контура: отвечаем 400 и говорим чем.
   */
  log("warn", "request failed", { path: req.path, error: err.message });

  if (res.headersSent) {
    return;
  }

  res.status(400).json({ ok: false, error: "bad_request" });
});

/* --- запуск ------------------------------------------------------------- */

const server = createServer({ maxHeaderSize: 1024 * 1024 }, app);
const stopSockets = mountSockets(server, {
  feedIntervalMs: cfg.feedIntervalMs,
  maxFrameBytes: cfg.maxFrameBytes,
});

server.listen(cfg.port, () => {
  log("info", "listening", { port: cfg.port, name: cfg.name, items: items.length });
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    log("info", "shutting down", { signal });
    stopSockets();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}
