/*
 * Сокеты. Две точки нарочно разные, потому что фаза кадров у модуля
 * двусторонняя, а проверять стороны удобнее по отдельности:
 *
 *   /socket/chat -- клиент говорит, сервер отвечает: c2s и s2c в одном
 *                   соединении, инициатива у клиента;
 *   /socket/feed -- сервер шлёт сам, клиент молчит: чистый поток s2c, на
 *                   котором видно правку и разбор кадров без действий клиента.
 *
 * Кадры чата -- JSON: по ним работает и контракт (bindings фазы кадров), и
 * модификатор (метка canary- внутри). Текст не-JSON и бинарь обрабатываются
 * тоже: у фазы кадров есть ось opcode, и ей нужно чем питаться.
 */

import { WebSocketServer } from "ws";
import type { WebSocket } from "ws";
import type { IncomingMessage, Server } from "node:http";

import { canaryOf } from "./data.ts";
import { log } from "./log.ts";

export interface WsDeps {
  feedIntervalMs: number;
  maxFrameBytes: number;
}

export function mountSockets(server: Server, deps: WsDeps): () => void {
  const chat = new WebSocketServer({ noServer: true, maxPayload: deps.maxFrameBytes });
  const feed = new WebSocketServer({ noServer: true, maxPayload: deps.maxFrameBytes });
  const timers = new Set<NodeJS.Timeout>();

  /* --- чат: c2s -> s2c ------------------------------------------------- */

  chat.on("connection", (socket: WebSocket, req: IncomingMessage) => {
    const peer = req.headers["x-forwarded-for"] ?? req.socket.remoteAddress ?? "?";
    let seen = 0;

    log("info", "ws open", { path: "/socket/chat", peer });
    send(socket, { type: "hello", note: "чат: пришлите JSON {\"type\":\"say\",\"text\":\"…\"}", canary: canaryOf("ws:hello") });

    socket.on("message", (raw: Buffer, isBinary: boolean) => {
      seen += 1;

      /* Бинарь отражаем бинарём: иначе ось opcode на s2c нечем проверить. */
      if (isBinary) {
        log("debug", "ws binary", { bytes: raw.length, seen });
        socket.send(raw, { binary: true });
        return;
      }

      const text = raw.toString("utf8");
      let parsed: Record<string, unknown> | null = null;

      try {
        const value: unknown = JSON.parse(text);
        parsed = typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null;
      } catch {
        parsed = null;
      }

      /* Не-JSON тоже принимаем и возвращаем текстом: это отдельный вид кадра. */
      if (parsed === null) {
        send(socket, { type: "echo", text, canary: canaryOf(`ws:echo:${seen}`), seen });
        return;
      }

      if (parsed.type === "ping") {
        send(socket, { type: "pong", seen, canary: canaryOf(`ws:pong:${seen}`) });
        return;
      }

      if (parsed.type === "say") {
        const said = {
          type: "said",
          from: typeof parsed.from === "string" ? parsed.from : "гость",
          /* Дословно, как и `echo` у API: в строке JSON это ничего не исполняет. */
          text: typeof parsed.text === "string" ? parsed.text : "",
          seen,
          canary: canaryOf(`ws:said:${seen}`),
        };

        /* Бродкаст: у второго клиента кадр приходит без его запроса -- тоже s2c. */
        for (const peerSocket of chat.clients) {
          send(peerSocket, said);
        }

        return;
      }

      send(socket, { type: "unknown", got: parsed.type ?? null, seen, canary: canaryOf(`ws:unknown:${seen}`) });
    });

    socket.on("close", (code) => {
      log("info", "ws close", { path: "/socket/chat", code, seen });
    });
  });

  /* --- поток: только s2c ----------------------------------------------- */

  feed.on("connection", (socket: WebSocket) => {
    let n = 0;

    log("info", "ws open", { path: "/socket/feed" });

    const timer = setInterval(() => {
      n += 1;
      send(socket, { type: "tick", n, at: new Date().toISOString(), canary: canaryOf(`ws:tick:${n}`) });
    }, deps.feedIntervalMs);

    timers.add(timer);

    socket.on("close", () => {
      clearInterval(timer);
      timers.delete(timer);
      log("info", "ws close", { path: "/socket/feed", ticks: n });
    });
  });

  /* --- маршрутизация рукопожатия --------------------------------------- */

  server.on("upgrade", (req, socket, head) => {
    const path = new URL(req.url ?? "/", "http://internal").pathname;

    if (path === "/socket/chat") {
      chat.handleUpgrade(req, socket, head, (ws) => chat.emit("connection", ws, req));
      return;
    }

    if (path === "/socket/feed") {
      feed.handleUpgrade(req, socket, head, (ws) => feed.emit("connection", ws, req));
      return;
    }

    /* Чужой путь: рукопожатие не принимаем, но и сокет не бросаем молча. */
    socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
    socket.destroy();
  });

  return () => {
    for (const timer of timers) {
      clearInterval(timer);
    }

    chat.close();
    feed.close();
  };
}

function send(socket: WebSocket, payload: unknown): void {
  if (socket.readyState === socket.OPEN) {
    socket.send(JSON.stringify(payload));
  }
}
