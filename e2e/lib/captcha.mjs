/*
 * Прохождение виджета капчи прогоном.
 *
 * Браузера в контуре нет, а картинку прочитать нечем -- в этом и смысл капчи.
 * Поэтому прогон делает то же, что делает оператор, когда разбирает жалобу:
 * подглядывает ответ в Redis по нонсу билета (`cap:img:<нонс>`). Так же устроен
 * и `tests/captcha/captcha.sh`, откуда взят порядок шагов.
 *
 * Это единственное место во всей библиотеке, где прогон выходит за пределы
 * «только API контроллера и край», и единственное, где он зовёт docker. Вынесено
 * отдельным файлом, чтобы исключение было видно, а не размазано: всё остальное
 * по-прежнему ходит через HTTP и переживает переезд стенда на другую машину.
 *
 * Состояния в Redis прогон при этом не чистит и чистить не должен -- билет и
 * клиренс живут своими сроками, а каждый запуск начинает с чистого адреса
 * (см. про свежие логины в README логической секции).
 */

import http from "node:http";
import { execFile } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { EDGE } from "./stand.mjs";

const run = promisify(execFile);
/* Контур — проект compose стенда: exec по имени проекта, файл compose не нужен. */
const PROJECT = process.env.WAF_E2E_PROJECT ?? "placitum";

/* Форма нонса на странице виджета: скрытое поле формы, шестнадцатеричное. */
const CSRF_RE = /name="csrf"\s+value="([a-f0-9]+)"/;

/* --- банка с куками ------------------------------------------------------ */

/**
 * Куки одного клиента между запросами. Полноценного разбора атрибутов нет и не
 * нужно: у капчи всё на одном хосте и одном пути, а срок нас не касается --
 * прогон короче любого из них.
 */
export function jar() {
  const cookies = new Map();

  return {
    header() {
      return [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    },
    take(res) {
      for (const line of res.headers["set-cookie"] ?? []) {
        const [pair] = line.split(";");
        const eq = pair.indexOf("=");

        if (eq > 0) {
          cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
        }
      }
    },
    names() {
      return [...cookies.keys()];
    },
  };
}

/**
 * Запрос через край с банкой кук. node:http, а не fetch, по той же причине, что
 * и в `probe`: undici считает Host запрещённым заголовком и молча его
 * выбрасывает, после чего запрос уходит на сервер по умолчанию.
 *
 * Редиректы не разворачиваются намеренно: код `303` и заголовок `Location` --
 * предмет проверки, а не помеха на пути к телу.
 */
export function request(path, { host, method = "GET", headers = {}, body = null, cookies = null } = {}) {
  const target = new URL(EDGE);

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: target.hostname,
        port: target.port || 80,
        path,
        method,
        headers: {
          Host: host,
          ...(cookies !== null && cookies.header() !== "" ? { Cookie: cookies.header() } : {}),
          ...(body === null ? {} : {
            "content-type": "application/x-www-form-urlencoded",
            "content-length": Buffer.byteLength(body),
          }),
          ...headers,
        },
        timeout: 15_000,
      },
      (res) => {
        const chunks = [];

        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          if (cookies !== null) {
            cookies.take(res);
          }

          resolve({
            status: res.statusCode,
            headers: res.headers,
            location: res.headers.location ?? "",
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );

    req.on("timeout", () => req.destroy(new Error("запрос виджета не уложился в срок")));
    req.on("error", reject);

    if (body !== null) {
      req.write(body);
    }

    req.end();
  });
}

/* --- подглядывание в Redis ----------------------------------------------- */

/**
 * Ответ картинки по нонсу билета. Ключ и его смысл -- контракт капчи, не наш:
 * `cap:img:<нонс>` кладёт HTTP-процесс, когда рисует картинку, и снимает,
 * когда её приняли или перерисовали. Лежит он во внутреннем Redis контура
 * (redis-internal), не в обменнике тел: роастер калитки -- служебное состояние.
 */
async function answerOf(nonce) {
  const key = `cap:img:${nonce}`;

  try {
    const { stdout } = await run(
      "docker",
      ["compose", "-p", PROJECT, "exec", "-T", "redis-internal", "redis-cli", "--raw", "get", key],
      { windowsHide: true },
    );
    const answer = stdout.trim();

    if (answer === "") {
      throw new Error(`в Redis пусто под ${key}: картинку не рисовали или её уже приняли`);
    }

    return answer;
  } catch (err) {
    if (err.code === "ENOENT") {
      throw new Error("нет docker: ответ картинки читать нечем, кейс с виджетом не пройти");
    }

    throw err;
  }
}

/* --- прохождение --------------------------------------------------------- */

/**
 * Пройти виджет и вернуть банку с клиренсом.
 *
 * `from` -- защищённый путь, с которого капча отправит на виджет: билет
 * выдаётся редиректом, а страница виджета без билета отвечает 403. Порядок
 * шагов повторяет `tests/captcha/captcha.sh`, и каждый из них -- утверждение:
 * несостоявшийся шаг называется в исключении, а не молча даёт пустой клиренс.
 */
export async function solveCaptcha({ host, from, ip = null, cookies = jar(), say = () => {} }) {
  /*
   * Адрес обязан быть тем же, что у остальных проб кейса: корзины капчи
   * ключуются им, и виджет с чужого адреса увидит пустую корзину и никуда не
   * пошлёт. Клиренс потом привязывается к подсети (`clearance.bind`), так что
   * адрес нужен и на прохождении, и на проверках после него.
   */
  const from_ = ip === null ? {} : { "X-Forwarded-For": ip };
  const gate = await request(from, { host, cookies, headers: { Accept: "text/html", ...from_ } });

  if (gate.status !== 303 && gate.status !== 302 && gate.status !== 307) {
    throw new Error(`ждали редирект на виджет с ${from}, получили ${gate.status}`);
  }

  const widget = gate.location.split("?")[0];

  if (widget === "") {
    throw new Error("редирект без Location: адреса виджета нет");
  }

  say(`билет выдан, виджет на ${widget}`);

  const page = await request(gate.location, { host, cookies, headers: { Accept: "text/html", ...from_ } });

  if (page.status !== 200) {
    throw new Error(`страница виджета ответила ${page.status}, ждали 200`);
  }

  const nonce = CSRF_RE.exec(page.body)?.[1];

  if (nonce === undefined) {
    throw new Error("на странице виджета нет нонса билета (поле csrf)");
  }

  if (!page.body.includes("src=\"data:image/png;base64,")) {
    throw new Error("картинка не встроена в страницу: провайдер не image?");
  }

  const answer = await answerOf(nonce);

  say(`картинка прочитана: ответ ${answer}`);

  const form = `csrf=${encodeURIComponent(nonce)}&answer_image=${encodeURIComponent(answer)}`;
  const post = await request(widget, { host, method: "POST", cookies, body: form, headers: from_ });

  if (post.status !== 303 && post.status !== 302) {
    throw new Error(`верный ответ не дал клиренса: ${post.status}`);
  }

  say(`клиренс выдан, куки: ${cookies.names().join(", ")}`);

  return cookies;
}
