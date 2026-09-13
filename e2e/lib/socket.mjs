/*
 * Кадры WebSocket для логических кейсов: рукопожатие через край, кадр за
 * кадром, без библиотеки.
 *
 * Кадрирование берётся готовым у прогона модуля (`nginx/tests/ws/ws.mjs`) --
 * там оно написано ради проверки байтов и лишнего не прячет. Здесь только то,
 * чего там нет: соединение через край стенда с нужным именем хоста и
 * заголовком входа, и шаги кейса «послать кадр -- посмотреть, что вернулось».
 *
 * Почему шаги не повторяются, в отличие от HTTP-проверок: кадр меняет
 * состояние. Корзина кадров ключуется личностью и переживает соединение, и
 * второй заход с той же личностью начинал бы не с нуля. Поэтому повтором
 * защищено только рукопожатие -- оно ничего не заряжает.
 */

import { connect } from "node:net";

import { OP, clientKey, decodeFrames, encodeFrame } from "../../node/tests/ws/ws.mjs";
import { SETTLE_MS } from "./check.mjs";
import { EDGE } from "./stand.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Рукопожатие руками: нужен и код ответа, и сокет, который после 101
 * продолжает жить потоком кадров.
 */
function handshake(path, { host, headers = {} }) {
  const target = new URL(EDGE);

  return new Promise((resolve, reject) => {
    const socket = connect({ host: target.hostname, port: Number(target.port) || 80 }, () => {
      const key = clientKey();
      const extra = Object.entries(headers).map(([name, value]) => `${name}: ${value}`);

      socket.write([
        `GET ${path} HTTP/1.1`,
        `Host: ${host}`,
        "Upgrade: websocket",
        "Connection: Upgrade",
        `Sec-WebSocket-Key: ${key}`,
        "Sec-WebSocket-Version: 13",
        ...extra,
        "", "",
      ].join("\r\n"));
    });

    let head = Buffer.alloc(0);

    /* Заголовок ответа приходит не обязательно одним куском. */
    const onData = (chunk) => {
      head = Buffer.concat([head, chunk]);

      const split = head.indexOf("\r\n\r\n");

      if (split < 0) {
        return;
      }

      socket.off("data", onData);

      const text = head.subarray(0, split).toString("latin1");

      resolve({
        socket,
        status: Number(/^HTTP\/1\.1 (\d{3})/.exec(text)?.[1] ?? 0),
        head: text,
        rest: head.subarray(split + 4),
      });
    };

    socket.on("data", onData);
    socket.setTimeout(10_000, () => reject(new Error("таймаут рукопожатия")));
    socket.on("error", reject);
  });
}

/** Читалка: копит байты, отдаёт разобранные кадры по одному. */
function reader(socket, seed) {
  let buf = seed;
  const frames = [];
  let closed = false;
  let taken = 0;

  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);

    const got = decodeFrames(buf);

    buf = got.rest;
    frames.push(...got.frames);
  });

  socket.on("end", () => { closed = true; });
  socket.on("close", () => { closed = true; });

  return {
    get closed() { return closed; },
    /** Следующий кадр с данными; служебные пропускаются, close возвращается. */
    async next(ms = 3000) {
      const until = Date.now() + ms;

      for (;;) {
        while (taken < frames.length) {
          const frame = frames[taken];

          taken += 1;

          if (frame.opcode === OP.ping || frame.opcode === OP.pong) {
            continue;
          }

          return frame;
        }

        if (closed || Date.now() > until) {
          return null;
        }

        await sleep(20);
      }
    },
  };
}

/**
 * Рукопожатие с повтором до срока: сразу после издания край может ещё не
 * знать маршрута, а соединение ничего не заряжает -- повторять его безопасно.
 */
async function open(spec, target, settleMs) {
  const until = Date.now() + settleMs;
  let last = null;

  for (;;) {
    const got = await handshake(spec.path, {
      host: target.host,
      headers: spec.headers ?? {},
    });

    if (got.status === 101) {
      return got;
    }

    last = got;
    got.socket.destroy();

    if (Date.now() > until) {
      throw new Error(`рукопожатие ${spec.path}: код ${last.status}, ждали 101`);
    }

    await sleep(1000);
  }
}

/**
 * Шаги кейса на одном соединении. Каждый шаг -- текстовый кадр клиенту в
 * сторону приложения и ожидание того, что вернулось: эхо приложения (с
 * подменой или без) либо закрытие соединения.
 */
export async function runSocket(target, spec, say = () => {}, settleMs = SETTLE_MS) {
  const { socket, rest } = await open(spec, target, settleMs);
  const rd = reader(socket, rest);

  say(`рукопожатие ${spec.path}: 101`);

  try {
    for (const step of spec.steps) {
      /* Шаг без `send` только читает: кадр приложения бывает и без просьбы. */
      if (step.send !== undefined) {
        socket.write(encodeFrame({
          opcode: OP.text,
          payload: Buffer.from(step.send, "utf8"),
          /* Кадр клиента обязан быть маскированным: немаскированный закрывают. */
          mask: true,
        }));
      }

      const started = Date.now();
      const bad = await checkStep(rd, step);

      if (bad.length > 0) {
        throw new Error(`кадр «${step.name}»: ${bad.join("; ")}`);
      }

      /* Время ответа печатается всегда: у кадра нет отладочного заголовка, и
       * задержка -- единственное, что видно снаружи без аудита. */
      say(`ok  ${step.name} (${Date.now() - started} мс)`);
    }
  } finally {
    socket.destroy();
  }
}

async function checkStep(rd, step) {
  const want = step.expect ?? {};
  const wait = step.waitMs ?? 3000;
  const bad = [];

  /*
   * Закрытие: ждём именно его, а кадры с данными по дороге пропускаем.
   * Приложение могло ответить на предыдущий кадр в тот же миг, когда модуль
   * закрывал соединение из-за этого, -- очередь ответа тут ничего не значит.
   */
  if (want.closed === true) {
    const until = Date.now() + wait;

    for (;;) {
      const frame = await rd.next(Math.max(0, until - Date.now()));

      if (frame === null) {
        if (!rd.closed) {
          bad.push("соединение живо, а должно было закрыться");
        }

        return bad;
      }

      if (frame.opcode === OP.close) {
        return bad;
      }
    }
  }

  const frame = await rd.next(wait);

  if (frame === null) {
    bad.push("ответа нет: соединение закрылось или кадр не пришёл");

    return bad;
  }

  if (frame.opcode === OP.close) {
    bad.push("соединение закрыто кадром close, а ждали ответ");

    return bad;
  }

  const body = frame.payload.toString("utf8");

  for (const has of [].concat(want.echoHas ?? [])) {
    if (!body.includes(has)) {
      bad.push(`в ответе нет «${has}»: ${body.slice(0, 160)}`);
    }
  }

  for (const lacks of [].concat(want.echoLacks ?? [])) {
    if (body.includes(lacks)) {
      bad.push(`в ответе осталось «${lacks}»`);
    }
  }

  return bad;
}
