/*
 * Каталог логических кейсов.
 *
 * Соглашение то же, что у нагрузочных: кейс автономен и описывает всё, что
 * нужно завести на пустом стенде. Отличие в том, что проверяется -- не потолок
 * темпа, а поведение на конкретных запросах, поэтому вместо `traffic`/`clean`
 * здесь `target` (куда стучаться) и `probes` (что должно получиться).
 *
 * Только данные и чистые функции, без импортов: файл читает раннер, и он же
 * должен оставаться пригодным для чтения человеком без прыжков по модулям.
 */

const APP = { name: "e2e-app", peers: [{ host: "app", port: 8080 }] };

const SERVER = "e2e-logic.waf.test";

const SERVER_SPEC = {
  name: SERVER,
  server_names: [SERVER],
  port: "http-8080",
  nginx: { realIpFrom: ["0.0.0.0/0", "::/0"], realIpHeader: "X-Forwarded-For" },
  waf: { enabled: true, debugHeader: true },
};

/** Общая часть документа маршрута: снимаем заголовки, отказ шины виден кодом. */
const ROUTE_WAF = {
  capture: ["request headers args"],
  preview: ["headers=16k/2k", "args=8k/1k"],
  deadlineMs: 2000,
  exception: ["request deny response=error"],
  responseInspectors: "none",
};

/** Волна на инспектора, по порядку списка. */
function chain(names) {
  return names.map((name, wave) => ({ name, wave }));
}

/** Профиль адреса без правил: всегда allow. Нужен, чтобы в цепочке был кто-то живой. */
const PASS_PROFILE = { name: "e2e-logic-pass", default: "allow", rules: [] };

/* --- поведенческие кейсы: калитка и счётчик ------------------------------ */

/*
 * Маршрут поведенческого кейса: снимаются заголовки запроса (по ним калитка
 * читает токен) и тело ответа целиком (по нему счётчик считает объекты).
 * `responseHold: gate` -- ответ держится до вердикта фазы: иначе заряд корзины
 * случался бы уже после того, как клиент получил тело, и следующий шаг прогона
 * судил бы недосчитанную корзину.
 *
 * Незнание любой из фаз -- отказ страницей error, а не тихий пропуск: зелёный
 * прогон обязан значить «сработало», а не «инспектор промолчал».
 */
const BEHAVIOUR_WAF = {
  capture: ["request headers args", "response headers body"],
  preview: ["headers=16k/2k", "args=8k/1k"],
  bodyLimit: "response 4m",
  bodyLimitPolicy: "pass",
  responseHold: "gate",
  deadlineMs: 2000,
  responseDeadlineMs: 3000,
  exception: ["request deny response=error", "response deny response=error"],
};

/*
 * Источник входа для поведенческих кейсов: внешний провайдер jwt. Формы,
 * билета и набора сессий у него нет, поэтому он заводится до сервера и ничего
 * за собой не тянет, а токены прогон выписывает сам -- пара ключей живёт один
 * запуск (tests/lib/identity.mjs). Подпись проверяет калитка: только у
 * проверенной записи счётчик берёт ключ корзины.
 */
const JWT_SOURCE = {
  name: "e2e-cnt-jwt",
  provider: "jwt",
  providers: {
    jwt: {
      header: "authorization",
      prefix: "Bearer",
      verify: { alg: "RS256", key: "@jwt.public", leeway_s: 30 },
      claims: { user: "sub", session: "sid" },
    },
  },
};

/** Калитка: гость получает 401, а не форму -- редиректов у внешнего входа нет. */
const JWT_GATE = { name: "e2e-cnt-gate", sourceFrom: "e2e-cnt-jwt" };

/**
 * Корзина объектов на человека: ключ -- логин, названный калиткой. Ёмкость
 * мала намеренно (двадцать объектов), потери малы, чтобы уровень не утёк
 * между шагами прогона: тихий человек остывает за сто секунд.
 */
const USER_COUNTER = {
  "e2e-cnt-objects": { unit: "obj", axes: { user: { max: 20, loss: 0.5 } }, from: "session:user" },
};

/** Правило учёта: одно вхождение `obj=<id>` на объект в теле ответа. */
const MEASURE_OBJECTS = {
  if: { status: [200], contentType: ["application/json", "+json"] },
  source: "regex_count",
  regex: "obj=\\d+",
  counter: "e2e-cnt-objects",
  axes: ["user"],
};

/* --- витрина, касса и ловушка -------------------------------------------- */

/**
 * Капча зовётся только для подозреваемых: условие вызова по живому набору.
 * Остальной трафик за неё не платит вовсе -- строка, снятая условием, не
 * публикуется, и в отладочном заголовке её нет.
 */
const SFT_SUSPECT = [{ value: "$remote_addr", dataset: "e2e-sft-suspects" }];

/** Заказ, который приложение примет: товар есть, количество в пределах. */
const SFT_ORDER = { itemId: 7, qty: 1, card: "4111 1111 1111 1111" };

/** Заказ на товар, которого нет: приложение отвечает 400 bad_order. */
const SFT_BAD_ORDER = { itemId: 999999, qty: 1, card: "4111 1111 1111 1111" };

export const cases = [
  {
    id: "one-denies",
    title: "Пятеро проверяют, один отказывает: решает отказ",
    about: [
      "Пять проверок адреса подряд. Четыре смотрят в пустой профиль и всегда",
      "отвечают allow, пятая отказывает по своему списку. Проверяется не то, что",
      "отказ случился, а то, что четыре согласия его не перевесили и что запрос",
      "дошёл до пятого: в отладочном заголовке видно ответ каждого.",
    ].join("\n"),
    needs: {
      datasets: [{ name: "e2e-logic-bad", addresses: ["203.0.113.0/24"] }],
      ipSets: [{ name: "e2e-logic-badset", lists: ["e2e-logic-bad"] }],
      ipProfiles: [
        PASS_PROFILE,
        {
          name: "e2e-logic-deny",
          default: "allow",
          datasets: ["e2e-logic-bad"],
          rules: [{ action: "deny", set: "e2e-logic-badset", response: "blocked", code: "E2E_LOGIC_DENY" }],
        },
      ],
      upstreams: [APP],
      declarations: {
        "e2e-lg-01": { process: "ip", profileFrom: "e2e-logic-pass" },
        "e2e-lg-02": { process: "ip", profileFrom: "e2e-logic-pass" },
        "e2e-lg-03": { process: "ip", profileFrom: "e2e-logic-pass" },
        "e2e-lg-04": { process: "ip", profileFrom: "e2e-logic-pass" },
        "e2e-lg-05": { process: "ip", profileFrom: "e2e-logic-deny" },
      },
      servers: [SERVER_SPEC],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/one-denies/",
          position: 100,
          upstream: APP.name,
          waf: { ...ROUTE_WAF, requestInspectors: chain(["e2e-lg-01", "e2e-lg-02", "e2e-lg-03", "e2e-lg-04", "e2e-lg-05"]) },
        },
      ],
    },
    target: { host: SERVER, path: "/logic/one-denies/" },
    probes: [
      {
        name: "чистый адрес: спросили всех пятерых, все согласны",
        ip: "8.8.8.8",
        expect: {
          status: 200,
          verdict: "allow",
          answers: {
            "e2e-lg-01": "allow",
            "e2e-lg-04": "allow",
            "e2e-lg-05": "allow",
          },
        },
      },
      {
        name: "адрес из списка: четверо согласны, пятый отказывает",
        ip: "203.0.113.7",
        expect: {
          deny: "blocked",
          verdict: "deny",
          answers: {
            "e2e-lg-01": "allow",
            "e2e-lg-04": "allow",
            "e2e-lg-05": "deny",
          },
        },
      },
    ],
  },

  {
    id: "off-saves",
    title: "Первый сверяется со списком и выключает того, кто отказал бы",
    about: [
      "Тот же конвейер из пяти, но первый инспектор смотрит в список исключений",
      "и, найдя там адрес, просит модуль выключить пятого -- того самого, который",
      "по своему списку этот адрес отказал бы. Список исключений -- подмножество",
      "списка отказа, поэтому оба правила на таком адресе истинны, и видно, чьё",
      "слово оказалось раньше.",
      "",
      "Что проверяется. Адрес из списка отказа, но не из исключений, получает",
      "отказ. Адрес из обоих проходит, и пятого в отладочном заголовке нет вовсе:",
      "выключенного инспектора модуль не печатает. Это и есть разница между",
      "«отказ не сработал» и «отказавшего не спросили».",
    ].join("\n"),
    needs: {
      datasets: [
        { name: "e2e-logic-bad", addresses: ["203.0.113.0/24"] },
        { name: "e2e-logic-vip", addresses: ["203.0.113.200/29"] },
      ],
      ipSets: [{ name: "e2e-logic-badset", lists: ["e2e-logic-bad"] }],
      ipProfiles: [
        PASS_PROFILE,
        {
          name: "e2e-logic-guard",
          default: "allow",
          datasets: ["e2e-logic-vip"],
          rules: [
            {
              action: "request",
              dataset: "e2e-logic-vip",
              verb: "off",
              axis: "request",
              to: "e2e-lg-05",
              code: "E2E_LOGIC_VIP",
            },
          ],
        },
        {
          name: "e2e-logic-deny",
          default: "allow",
          datasets: ["e2e-logic-bad"],
          rules: [{ action: "deny", set: "e2e-logic-badset", response: "blocked", code: "E2E_LOGIC_DENY" }],
        },
      ],
      upstreams: [APP],
      declarations: {
        "e2e-lg-01": { process: "ip", profileFrom: "e2e-logic-guard" },
        "e2e-lg-02": { process: "ip", profileFrom: "e2e-logic-pass" },
        "e2e-lg-03": { process: "ip", profileFrom: "e2e-logic-pass" },
        "e2e-lg-04": { process: "ip", profileFrom: "e2e-logic-pass" },
        "e2e-lg-05": { process: "ip", profileFrom: "e2e-logic-deny" },
      },
      servers: [SERVER_SPEC],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/off-saves/",
          position: 100,
          upstream: APP.name,
          waf: { ...ROUTE_WAF, requestInspectors: chain(["e2e-lg-01", "e2e-lg-02", "e2e-lg-03", "e2e-lg-04", "e2e-lg-05"]) },
        },
      ],
    },
    target: { host: SERVER, path: "/logic/off-saves/" },
    probes: [
      {
        name: "чистый адрес проходит, пятого спросили",
        ip: "8.8.8.8",
        expect: { status: 200, verdict: "allow", asked: ["e2e-lg-01", "e2e-lg-05"] },
      },
      {
        name: "в списке отказа, не в исключениях: отказ от пятого",
        ip: "203.0.113.7",
        expect: { deny: "blocked", verdict: "deny", answers: { "e2e-lg-05": "deny" } },
      },
      {
        name: "в обоих списках: первый выключил пятого, запрос прошёл",
        ip: "203.0.113.201",
        expect: {
          status: 200,
          verdict: "allow",
          asked: ["e2e-lg-01", "e2e-lg-04"],
          notAsked: "e2e-lg-05",
        },
      },
    ],
  },

  {
    id: "score-blocks",
    title: "Инспектор действий добавляет очки, маршрут отказывает по сумме",
    about: [
      "Никто из инспекторов не выносит отказ. Отказ выносит сам маршрут по сумме",
      "очков: у него порог 100, а инспектор действий на нужном префиксе просит",
      "начислить ровно столько. На соседнем префиксе тот же инспектор молчит, и",
      "запрос проходит.",
      "",
      "Проверяется, что отказ пришёл именно по сумме, а не от инспектора: в",
      "отладочном заголовке это отдельная пометка (by=score).",
    ].join("\n"),
    /*
     * Глагол score появился в реестре канала позже, чем собран контроллер,
     * который сейчас поднят на стенде: тот отвечает «do is not a verb of the
     * actions channel». Прогон это проверяет заранее и помечает кейс
     * пропущенным, а не красным.
     */
    requires: { verb: "score" },
    needs: {
      actionProfiles: [
        {
          name: "e2e-logic-score",
          rules: [
            {
              name: "e2e-score",
              pathPrefix: "/logic/score/",
              actions: [{ verb: "score", axis: "request", value: 100, code: "E2E_LOGIC_SCORE" }],
            },
          ],
        },
      ],
      ipProfiles: [PASS_PROFILE],
      upstreams: [APP],
      declarations: {
        "e2e-lg-act": { process: "action", profileFrom: "e2e-logic-score" },
        "e2e-lg-01": { process: "ip", profileFrom: "e2e-logic-pass" },
      },
      servers: [SERVER_SPEC],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...ROUTE_WAF,
            /* Порог суммы: ровно столько, сколько просит инспектор действий. */
            scoreDeny: { response: "blocked", threshold: 100 },
            requestInspectors: chain(["e2e-lg-act", "e2e-lg-01"]),
          },
        },
      ],
    },
    target: { host: SERVER, path: "/logic/score/" },
    probes: [
      {
        name: "нужный префикс: очки добраны до порога, отказ по сумме",
        path: "/logic/score/x",
        expect: { deny: "blocked", verdict: "deny", by: "score" },
      },
      {
        name: "соседний префикс: очков нет, запрос проходит",
        path: "/logic/plain/x",
        expect: { status: 200, verdict: "allow" },
      },
    ],
  },

  {
    id: "cond-asks",
    title: "Инспектор действий просит по условию: ключ в наборе, аргумент равен тексту",
    about: [
      "У профиля действий два условия: «ключ доверенный» -- заголовок X-Api-Key",
      "есть в активном наборе, и «debug включён» -- аргумент debug равен 1. Очки",
      "до порога просятся, если ключ не доверенный (unless), и если debug",
      "включён (if). Никто из инспекторов не отказывает сам: отказ выносит",
      "маршрут по сумме.",
      "",
      "Проверяется и путь данных: заголовок инспектор берёт из снимка маршрута в",
      "обменнике, набор -- из зеркала keeper, аргумент -- из строки запроса.",
    ].join("\n"),
    needs: {
      datasets: [
        /* Вечных записей у активного набора нет: без срока keeper отвечает no_ttl. */
        { name: "e2e-logic-keys", kind: "list", type: "string", active: true, ttl: "1h", addresses: ["k1"] },
      ],
      actionProfiles: [
        {
          name: "e2e-logic-cond",
          conditions: [
            {
              name: "trusted_key",
              all: [{ value: "$http_x_api_key", op: "in", dataset: "e2e-logic-keys" }],
            },
            { name: "debug_on", all: [{ value: "$arg_debug", op: "eq", text: "1" }] },
          ],
          rules: [
            {
              name: "e2e-untrusted",
              unless: "trusted_key",
              actions: [{ verb: "score", axis: "request", value: 100, code: "E2E_LOGIC_UNTRUSTED" }],
            },
            {
              name: "e2e-debug",
              if: "debug_on",
              actions: [{ verb: "score", axis: "request", value: 100, code: "E2E_LOGIC_DEBUG" }],
            },
          ],
        },
      ],
      ipProfiles: [PASS_PROFILE],
      upstreams: [APP],
      declarations: {
        "e2e-lg-cnd": { process: "action", profileFrom: "e2e-logic-cond" },
        "e2e-lg-01": { process: "ip", profileFrom: "e2e-logic-pass" },
      },
      servers: [SERVER_SPEC],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...ROUTE_WAF,
            scoreDeny: { response: "blocked", threshold: 100 },
            requestInspectors: chain(["e2e-lg-cnd", "e2e-lg-01"]),
          },
        },
      ],
    },
    target: { host: SERVER, path: "/logic/cond/" },
    probes: [
      {
        name: "без ключа: «не доверенный» истинно, очки до порога, отказ по сумме",
        path: "/logic/cond/x",
        expect: { deny: "blocked", verdict: "deny", by: "score" },
      },
      {
        name: "ключ из набора: просьбы нет, запрос проходит",
        path: "/logic/cond/x",
        headers: { "X-Api-Key": "k1" },
        expect: { status: 200, verdict: "allow" },
      },
      {
        name: "чужой ключ: не в наборе, отказ по сумме",
        path: "/logic/cond/x",
        headers: { "X-Api-Key": "nope" },
        expect: { deny: "blocked", verdict: "deny", by: "score" },
      },
      {
        name: "ключ доверенный, но debug=1: второе условие, отказ по сумме",
        path: "/logic/cond/x?debug=1",
        headers: { "X-Api-Key": "k1" },
        expect: { deny: "blocked", verdict: "deny", by: "score" },
      },
    ],
  },

  {
    id: "action-list-scopes",
    title: "Инспектор действий пишет в наборы адрес, подсеть и систему по условию",
    about: [
      "Автодействия пишут в живые наборы теми же охватами, что капча: адрес",
      "клиента, самый узкий анонс (net), все анонсы, накрывающие адрес",
      "(net_all), и систему целиком (asn). Подсеть и систему инспектор берёт у",
      "кодера гео синхронно, в бюджете сообщения, и пишет одним кадром keeper.",
      "",
      "Адрес прогона -- из 1.1.1.0/24: у 13335 на стенде три анонса, включая",
      "IPv6, и запись системы уезжает пачкой из трёх префиксов -- ровно тот",
      "путь, на котором пачка прежде молча не записывалась. Вложенных анонсов",
      "на стенде нет, поэтому net_all здесь совпадает с net. Без условия",
      "(аргумента bot) правило молчит, и наборы остаются пустыми.",
    ].join("\n"),
    address: { within: "1.1.1.0/24" },
    needs: {
      datasets: [
        { name: "e2e-scope-ip", description: "Адрес клиента: пишет инспектор действий", type: "ip", active: true },
        { name: "e2e-scope-net", description: "Самый узкий анонс адреса", type: "ip", active: true },
        { name: "e2e-scope-all", description: "Все анонсы, накрывающие адрес", type: "ip", active: true },
        { name: "e2e-scope-asn", description: "Система целиком: все её анонсы", type: "ip", active: true },
      ],
      actionProfiles: [
        {
          name: "e2e-scope-act",
          conditions: [{ name: "bot", all: [{ value: "$arg_bot", op: "eq", text: "1" }] }],
          rules: [
            {
              name: "e2e-scope",
              if: "bot",
              actions: [
                { list: "e2e-scope-ip", ttlS: 60, code: "E2E_SCOPE" },
                { list: "e2e-scope-net", write: "net", ttlS: 60, code: "E2E_SCOPE" },
                { list: "e2e-scope-all", write: "net_all", ttlS: 60, code: "E2E_SCOPE" },
                { list: "e2e-scope-asn", write: "asn", ttlS: 60, code: "E2E_SCOPE" },
              ],
            },
          ],
        },
      ],
      ipProfiles: [PASS_PROFILE],
      upstreams: [APP],
      declarations: {
        "e2e-sc-act": { process: "action", profileFrom: "e2e-scope-act" },
        "e2e-lg-01": { process: "ip", profileFrom: "e2e-logic-pass" },
      },
      servers: [SERVER_SPEC],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/scope/",
          position: 100,
          upstream: APP.name,
          waf: { ...ROUTE_WAF, requestInspectors: chain(["e2e-sc-act", "e2e-lg-01"]) },
        },
      ],
    },
    target: { host: SERVER, path: "/logic/scope/" },
    probes: [
      {
        name: "без условия: правило молчит, запрос проходит",
        path: "/logic/scope/x",
        ip: "@run.ip",
        expect: { status: 200, verdict: "allow" },
      },
      { name: "набор адреса пуст", list: "e2e-scope-ip", expect: { lacks: "@run.ip" } },
      { name: "набор системы пуст", list: "e2e-scope-asn", expect: { lacks: "1.1.1.0/24" } },
      {
        name: "bot=1: условие истинно, записи уходят, запрос проходит",
        path: "/logic/scope/x?bot=1",
        ip: "@run.ip",
        expect: { status: 200, verdict: "allow" },
      },
      { name: "адрес прогона в наборе адреса", list: "e2e-scope-ip", expect: { has: "@run.ip", ttlMax: 60 } },
      { name: "самый узкий анонс -- 1.1.1.0/24", list: "e2e-scope-net", expect: { has: "1.1.1.0/24", ttlMax: 60 } },
      { name: "все накрывающие -- тот же анонс: вложенных на стенде нет", list: "e2e-scope-all", expect: { has: "1.1.1.0/24" } },
      { name: "система 13335 целиком: свой анонс", list: "e2e-scope-asn", expect: { has: "1.1.1.0/24" } },
      { name: "... и соседний анонс той же системы", list: "e2e-scope-asn", expect: { has: "1.0.0.0/24" } },
      { name: "... и её IPv6 -- одна пачка из трёх", list: "e2e-scope-asn", expect: { has: "2606:4700:4700::/48" } },
      { name: "в набор анонса система не попала", list: "e2e-scope-net", expect: { lacks: "1.0.0.0/24" } },
    ],
  },

  {
    id: "cond-logic",
    title: "Условия по ИЛИ, по И и ссылками друг на друга",
    about: [
      "Условие «доверенный» -- ИЛИ из четырёх строк: заголовок X-Api-Key в",
      "активном наборе, аргумент key равен k1, адрес из X-Forwarded-For в наборе",
      "сетей, cookie sid в наборе с hash=md5. Условие «опасный» -- ИЛИ из двух",
      "ссылок: «доверенный» ложно либо «debug» истинно, где «debug» -- И из одной",
      "строки по аргументу. Очки до порога просятся, если «опасный» истинно.",
      "",
      "Проверяется каждая ветка ИЛИ, ссылка с отрицанием и И поверх ИЛИ; заодно",
      "-- адресный набор с префиксом и набор с md5, где значение хеширует сам",
      "инспектор.",
    ].join("\n"),
    needs: {
      datasets: [
        /* Вечных записей у активного набора нет: без срока keeper отвечает no_ttl. */
        { name: "e2e-logic-keys", kind: "list", type: "string", active: true, ttl: "1h", addresses: ["k1"] },
        { name: "e2e-logic-office", kind: "list", type: "ipv4", active: true, ttl: "1h", addresses: ["10.77.0.0/16"] },
        { name: "e2e-logic-sess", kind: "list", type: "string", active: true, hash: true, ttl: "1h", addresses: ["s3cr3t"] },
      ],
      actionProfiles: [
        {
          name: "e2e-logic-logic",
          conditions: [
            {
              name: "trusted",
              any: [
                { value: "$http_x_api_key", op: "in", dataset: "e2e-logic-keys" },
                { value: "$arg_key", op: "eq", text: "k1" },
                { value: "$http_x_forwarded_for", op: "in", dataset: "e2e-logic-office" },
                { value: "$cookie_sid", op: "in", dataset: "e2e-logic-sess" },
              ],
            },
            { name: "debug", all: [{ value: "$arg_debug", op: "eq", text: "1" }] },
            { name: "risky", any: [{ cond: "trusted", op: "is_not" }, { cond: "debug", op: "is" }] },
          ],
          rules: [
            {
              name: "e2e-risky",
              if: "risky",
              actions: [{ verb: "score", axis: "request", value: 100, code: "E2E_LOGIC_RISKY" }],
            },
          ],
        },
      ],
      ipProfiles: [PASS_PROFILE],
      upstreams: [APP],
      declarations: {
        "e2e-lg-lgc": { process: "action", profileFrom: "e2e-logic-logic" },
        "e2e-lg-01": { process: "ip", profileFrom: "e2e-logic-pass" },
      },
      servers: [SERVER_SPEC],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...ROUTE_WAF,
            scoreDeny: { response: "blocked", threshold: 100 },
            requestInspectors: chain(["e2e-lg-lgc", "e2e-lg-01"]),
          },
        },
      ],
    },
    target: { host: SERVER, path: "/logic/logic/" },
    probes: [
      {
        name: "ничего: «доверенный» ложно, «опасный» истинно, отказ по сумме",
        path: "/logic/logic/x",
        expect: { deny: "blocked", verdict: "deny", by: "score" },
      },
      {
        name: "ветка ИЛИ 1: заголовок из набора, проход",
        path: "/logic/logic/x",
        headers: { "X-Api-Key": "k1" },
        expect: { status: 200, verdict: "allow" },
      },
      {
        name: "ветка ИЛИ 2: аргумент равен тексту, проход",
        path: "/logic/logic/x?key=k1",
        expect: { status: 200, verdict: "allow" },
      },
      {
        name: "ветка ИЛИ 3: адрес из X-Forwarded-For в наборе сетей, проход",
        path: "/logic/logic/x",
        ip: "10.77.1.2",
        expect: { status: 200, verdict: "allow" },
      },
      {
        name: "ветка ИЛИ 4: cookie в наборе с md5, проход",
        path: "/logic/logic/x",
        headers: { Cookie: "theme=dark; sid=s3cr3t" },
        expect: { status: 200, verdict: "allow" },
      },
      {
        name: "чужие значения во всех ветках: отказ по сумме",
        path: "/logic/logic/x?key=nope",
        ip: "10.78.1.2",
        headers: { "X-Api-Key": "nope", Cookie: "sid=nope" },
        expect: { deny: "blocked", verdict: "deny", by: "score" },
      },
      {
        name: "доверенный, но debug=1: вторая ссылка, отказ по сумме",
        path: "/logic/logic/x?key=k1&debug=1",
        expect: { deny: "blocked", verdict: "deny", by: "score" },
      },
    ],
  },
  {
    id: "counter-user",
    title: "Корзина на человека: считаем отданные объекты, отказываем по логину",
    about: [
      "Счёт ведётся не по адресу и не по куке, а по личности, которую назвала",
      "калитка: `subjects.user.from: session:user`. Калитка стоит на маршруте",
      "первой волной и проверяет подпись токена; счётчик стоит второй и берёт",
      "логин из секции sessions самого сообщения.",
      "",
      "Что проверяется. Фаза ответа считает объекты (`obj=<id>` в теле, ровно",
      "одно вхождение на объект), фаза запроса судит уровень корзины. Двадцать",
      "объектов наполняют её до потолка, и следующий запрос того же человека",
      "получает отказ -- **с другого адреса**: адрес в ключе не участвует вовсе.",
      "Сосед по маршруту -- другой человек, его корзина пуста, и чужой отказ он",
      "не наследует.",
      "",
      "Гость до счётчика не доходит: калитка отказывает раньше, и в отладочном",
      "заголовке счётчика нет вовсе.",
    ].join("\n"),
    identity: { logins: ["alice", "bob"] },
    needs: {
      counterShared: USER_COUNTER,
      counterProfiles: [
        {
          name: "e2e-cnt-user",
          description: "Объекты на человека: суд по заполнению корзины логина",
          request: {
            judge: [
              {
                counter: "e2e-cnt-objects",
                axis: "user",
                at: 90,
                action: "deny",
                code: "E2E_CNT_USER",
              },
            ],
            denyResponse: "counter_limit",
          },
          response: { measure: [MEASURE_OBJECTS] },
        },
      ],
      authSources: [JWT_SOURCE],
      authProfiles: [JWT_GATE],
      upstreams: [APP],
      declarations: {
        "e2e-gate": { process: "auth", profileFrom: "e2e-cnt-gate" },
        "e2e-cnt": { process: "counter", profileFrom: "e2e-cnt-user" },
      },
      servers: [SERVER_SPEC],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/counter-user/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            /*
             * Калитка обязана стоять раньше счётчика и меньшим номером волны:
             * волна, которая уже высказалась, ничего дослать не может, и
             * личности в сообщении счётчику не окажется.
             */
            requestInspectors: [
              { name: "e2e-gate", wave: 0 },
              { name: "e2e-cnt", wave: 1 },
            ],
            responseInspectors: [{ name: "e2e-cnt", wave: 0 }],
          },
        },
      ],
    },
    target: { host: SERVER, path: "/logic/counter-user/" },
    probes: [
      {
        name: "гость: калитка отказывает, счётчика не спрашивают вовсе",
        expect: { deny: "auth_required", verdict: "deny", notAsked: "e2e-cnt" },
      },
      {
        name: "вошедший берёт двадцать объектов: корзина до потолка",
        path: "/logic/counter-user/?objects=10",
        times: 2,
        headers: { Authorization: "@bearer.alice" },
        expect: { status: 200, verdict: "allow", answers: { "e2e-cnt": "allow" } },
      },
      {
        name: "тот же человек с другого адреса: отказ по корзине логина",
        path: "/logic/counter-user/?objects=10",
        ip: "203.0.113.77",
        headers: { Authorization: "@bearer.alice" },
        expect: { deny: "counter_limit", verdict: "deny", answers: { "e2e-cnt": "deny" } },
      },
      {
        name: "сосед по маршруту: своя корзина, чужой отказ не наследуется",
        path: "/logic/counter-user/?objects=10",
        headers: { Authorization: "@bearer.bob" },
        expect: { status: 200, verdict: "allow", answers: { "e2e-cnt": "allow" } },
      },
    ],
  },

  {
    id: "counter-user-mask",
    title: "Корзина на человека включает маскирование выдачи",
    about: [
      "Тот же счёт по личности, но исход другой: никто не отказывает. Дойдя до",
      "половины корзины, счётчик просит соседа-модификатора включить группу",
      "`mask` (`do: mutate`), и человек продолжает получать ответы -- но с",
      "замаскированными метками.",
      "",
      "Проверяется в том числе стык фаз: просьба высказана на фазе запроса, а",
      "исполняет её инспектор фазы ответа -- секция prior сквозная, и `mutate`",
      "с осью request живёт до конца транзакции.",
      "",
      "Группа модификатора выключена по умолчанию (`default: false`) и правило",
      "приёма названо поимённо: пока счётчик не попросит, ответ отдаётся как",
      "есть. Соседу по маршруту -- другому человеку -- маска не включается: у",
      "него своя корзина.",
    ].join("\n"),
    identity: { logins: ["alice", "bob"] },
    needs: {
      counterShared: USER_COUNTER,
      counterProfiles: [
        {
          name: "e2e-cnt-mask",
          description: "Объекты на человека: с половины корзины просим маску",
          request: {
            judge: [],
            outcomes: [
              {
                on: "level",
                if: { counter: "e2e-cnt-objects", axis: "user" },
                at: 50,
                to: "e2e-rw",
                verb: "mutate",
                axis: "request",
                group: "mask",
                set: "on",
                code: "E2E_CNT_MASK",
              },
            ],
          },
          response: { measure: [MEASURE_OBJECTS] },
        },
      ],
      rewriteProfiles: [
        {
          name: "e2e-cnt-rewrite",
          description: "Маска меток: группа выключена, включает её просьба счётчика",
          groups: [
            {
              name: "mask",
              default: false,
              on: "response",
              status: [200],
              contentType: ["application/json", "+json"],
              body: [{ op: "replace", pattern: "canary-([0-9a-f]{8})", to: "masked-$1" }],
            },
          ],
          /* Грант поимённый: включить маску вправе названный отправитель и по названному поводу. */
          prior: [{ from: "e2e-cnt", accept: ["mutate"], codes: ["E2E_CNT_MASK"] }],
        },
      ],
      authSources: [JWT_SOURCE],
      authProfiles: [JWT_GATE],
      upstreams: [APP],
      declarations: {
        "e2e-gate": { process: "auth", profileFrom: "e2e-cnt-gate" },
        "e2e-cnt": { process: "counter", profileFrom: "e2e-cnt-mask" },
        "e2e-rw": { process: "rewrite", profileFrom: "e2e-cnt-rewrite" },
      },
      servers: [SERVER_SPEC],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/counter-mask/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            requestInspectors: [
              { name: "e2e-gate", wave: 0 },
              { name: "e2e-cnt", wave: 1 },
            ],
            /* Модификатор правит тело раньше, чем счётчик его считает: метки объектов он не трогает. */
            responseInspectors: [
              { name: "e2e-rw", wave: 0, timeoutMs: 2500 },
              { name: "e2e-cnt", wave: 1 },
            ],
          },
        },
      ],
    },
    target: { host: SERVER, path: "/logic/counter-mask/" },
    probes: [
      {
        name: "первые двенадцать объектов: корзина ниже половины, метки как есть",
        path: "/logic/counter-mask/?objects=6",
        times: 2,
        headers: { Authorization: "@bearer.alice" },
        expect: { status: 200, verdict: "allow", bodyHas: "canary-", bodyLacks: "masked-" },
      },
      {
        name: "корзина за половиной: счётчик попросил маску, метки замаскированы",
        path: "/logic/counter-mask/?objects=6",
        headers: { Authorization: "@bearer.alice" },
        expect: { status: 200, verdict: "allow", bodyHas: "masked-", bodyLacks: "canary-" },
      },
      {
        name: "сосед по маршруту: его корзина пуста, маски нет",
        path: "/logic/counter-mask/?objects=6",
        headers: { Authorization: "@bearer.bob" },
        expect: { status: 200, verdict: "allow", bodyHas: "canary-", bodyLacks: "masked-" },
      },
    ],
  },

  {
    id: "counter-user-silent",
    title: "Личности нет -- правило молчит: четыре способа остаться без субъекта",
    about: [
      "Обратная сторона счёта по личности: корзина ключуется тем, что сказала",
      "калитка, и без её слова субъекта на запросе нет. Правило по такой оси",
      "молчит -- не отказывает и не пропускает «на всякий случай», а просто не",
      "участвует. Это самая дорогая ошибка настройки: профиль выглядит рабочим,",
      "счётчик отвечает allow, и никто не считает.",
      "",
      "Один и тот же человек с одним и тем же токеном ходит на пять маршрутов",
      "с одним профилем счётчика. Корзину он наполняет на первом -- там калитка",
      "стоит как надо, и отказ приходит. На остальных четырёх счётчик спрошен и",
      "отвечает allow с полной корзиной:",
      "",
      "  * калитки на маршруте нет вовсе -- личность назвать некому;",
      "  * калитка стоит, но в режиме passive -- записи пассивного отправителя",
      "    соседям не доставляются вовсе (это же делает и наблюдение при",
      "    внедрении: калитку включили смотреть, а счёт по людям перестал идти);",
      "  * калитка стоит позже счётчика -- волна, которая уже высказалась,",
      "    ничего дослать не может;",
      "  * калитка приняла токен, но подпись не проверяла (`alg: none`) --",
      "    непроверенная запись это то, что прислал клиент, и ключом счёта она",
      "    не становится.",
      "",
      "Гость на правильном маршруте до счётчика не доходит: его останавливает",
      "калитка.",
    ].join("\n"),
    identity: { logins: ["alice"] },
    needs: {
      counterShared: USER_COUNTER,
      counterProfiles: [
        {
          name: "e2e-cnt-user",
          description: "Объекты на человека: суд по заполнению корзины логина",
          request: {
            judge: [
              {
                counter: "e2e-cnt-objects",
                axis: "user",
                at: 90,
                action: "deny",
                code: "E2E_CNT_USER",
              },
            ],
            denyResponse: "counter_limit",
          },
          response: { measure: [MEASURE_OBJECTS] },
        },
      ],
      authSources: [
        JWT_SOURCE,
        {
          /*
           * Тот же провайдер без проверки подписи. Токен разбирается, личность
           * называется, но запись едет с verified: false -- ровно то, что
           * калитка говорит о чужом токене, который она не может проверить.
           */
          name: "e2e-cnt-jwt-none",
          provider: "jwt",
          providers: {
            jwt: {
              header: "authorization",
              prefix: "Bearer",
              verify: { alg: "none", leeway_s: 30 },
              claims: { user: "sub", session: "sid" },
            },
          },
        },
      ],
      authProfiles: [
        JWT_GATE,
        { name: "e2e-cnt-gate-none", sourceFrom: "e2e-cnt-jwt-none" },
      ],
      upstreams: [APP],
      declarations: {
        "e2e-gate": { process: "auth", profileFrom: "e2e-cnt-gate" },
        "e2e-gate-none": { process: "auth", profileFrom: "e2e-cnt-gate-none" },
        "e2e-cnt": { process: "counter", profileFrom: "e2e-cnt-user" },
      },
      servers: [SERVER_SPEC],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/silent/gated/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            requestInspectors: [
              { name: "e2e-gate", wave: 0 },
              { name: "e2e-cnt", wave: 1 },
            ],
            responseInspectors: [{ name: "e2e-cnt", wave: 0 }],
          },
        },
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/silent/nogate/",
          position: 101,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            requestInspectors: [{ name: "e2e-cnt", wave: 0 }],
            responseInspectors: [{ name: "e2e-cnt", wave: 0 }],
          },
        },
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/silent/passive/",
          position: 102,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            requestInspectors: [
              { name: "e2e-gate", wave: 0, mode: "passive" },
              { name: "e2e-cnt", wave: 1 },
            ],
            responseInspectors: [{ name: "e2e-cnt", wave: 0 }],
          },
        },
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/silent/late/",
          position: 103,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            requestInspectors: [
              { name: "e2e-cnt", wave: 0 },
              { name: "e2e-gate", wave: 1 },
            ],
            responseInspectors: [{ name: "e2e-cnt", wave: 0 }],
          },
        },
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/silent/unverified/",
          position: 104,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            requestInspectors: [
              { name: "e2e-gate-none", wave: 0 },
              { name: "e2e-cnt", wave: 1 },
            ],
            responseInspectors: [{ name: "e2e-cnt", wave: 0 }],
          },
        },
      ],
    },
    target: { host: SERVER, path: "/logic/silent/gated/" },
    probes: [
      {
        name: "правильный маршрут: двадцать объектов наполняют корзину",
        path: "/logic/silent/gated/?objects=10",
        times: 2,
        headers: { Authorization: "@bearer.alice" },
        expect: { status: 200, verdict: "allow", answers: { "e2e-cnt": "allow" } },
      },
      {
        name: "и отказывают тому же человеку: механизм работает",
        path: "/logic/silent/gated/?objects=10",
        headers: { Authorization: "@bearer.alice" },
        expect: { deny: "counter_limit", verdict: "deny", answers: { "e2e-cnt": "deny" } },
      },
      {
        name: "калитки на маршруте нет: субъекта нет, полная корзина не судит",
        path: "/logic/silent/nogate/?objects=10",
        headers: { Authorization: "@bearer.alice" },
        expect: { status: 200, verdict: "allow", answers: { "e2e-cnt": "allow" } },
      },
      {
        name: "калитка пассивна: её записи соседям не доставляются",
        path: "/logic/silent/passive/?objects=10",
        headers: { Authorization: "@bearer.alice" },
        expect: { status: 200, verdict: "allow", answers: { "e2e-cnt": "allow" } },
      },
      {
        name: "пассивная калитка и не гейтит: гость проходит",
        path: "/logic/silent/passive/?objects=10",
        expect: { status: 200, verdict: "allow", answers: { "e2e-cnt": "allow" } },
      },
      {
        name: "калитка позже счётчика: дослать высказавшейся волне нечего",
        path: "/logic/silent/late/?objects=10",
        headers: { Authorization: "@bearer.alice" },
        expect: { status: 200, verdict: "allow", answers: { "e2e-cnt": "allow" } },
      },
      {
        name: "подпись не проверялась: непроверенная личность ключом не становится",
        path: "/logic/silent/unverified/?objects=10",
        headers: { Authorization: "@bearer-unsigned.alice" },
        expect: { status: 200, verdict: "allow", answers: { "e2e-cnt": "allow" } },
      },
      {
        /*
         * Скобка на все четыре проверки молчания: корзина всё это время
         * оставалась полной. Без неё зелёный прогон мог бы значить не
         * «субъекта нет», а «уровень утёк ниже порога, пока шли шаги».
         */
        name: "корзина всё ещё полна: молчали не потому, что уровень утёк",
        path: "/logic/silent/gated/?objects=10",
        headers: { Authorization: "@bearer.alice" },
        expect: { deny: "counter_limit", verdict: "deny" },
      },
      {
        name: "гость на правильном маршруте: его останавливает калитка",
        path: "/logic/silent/gated/?objects=10",
        expect: { deny: "auth_required", verdict: "deny", notAsked: "e2e-cnt" },
      },
    ],
  },

  {
    id: "counter-user-frames",
    title: "То же на сокете: кадры человека включают маску, а потом закрывают соединение",
    about: [
      "Счёт по личности на фазе кадров. Калитка стоит на рукопожатии и называет",
      "человека; секция sessions сквозная, поэтому на каждом кадре счётчик видит",
      "ту же личность, что на рукопожатии, и ключует корзины ею -- не",
      "соединением. Соединений у человека может быть много, корзина одна.",
      "",
      "Лестница из двух корзин на кадры клиента. Первая мала (два кадра): дойдя",
      "до неё, счётчик просит модификатора включить группу `mask`, и приложение",
      "получает уже замаскированный кадр -- эхо возвращает маску. Вторая (пять",
      "кадров) судит сама: кадр, доливший её до порога, закрывается кадром Close",
      "по записи ws_policy. На кадрах учёт и суд живут на одном кадре, поэтому",
      "отказ получает тот кадр, который перелил, а не следующий.",
      "",
      "Первые проверки -- обычные HTTP-запросы на соседний маршрут с теми же",
      "объявлениями: ими прогон убеждается, что калитка принимает токен, а",
      "поколение профиля доехало до инспектора, до того как считать кадры.",
    ].join("\n"),
    identity: { logins: ["alice"] },
    needs: {
      counterShared: {
        /*
         * Обе корзины на человека и обе малы: лестница берётся вторым и пятым
         * кадром. Потери большие -- пауза в секунды остужает их, и соседний
         * прогон не наследует уровень (логин у каждого запуска всё равно свой).
         */
        "e2e-ws-mask": { unit: "frm", axes: { user: { max: 2, loss: 5 } }, from: "session:user" },
        "e2e-ws-ban": { unit: "frm", axes: { user: { max: 5, loss: 5 } }, from: "session:user" },
      },
      counterProfiles: [
        {
          name: "e2e-cnt-frames",
          description: "Кадры на человека: маска со второго, закрытие с пятого",
          frame: {
            measure: [
              {
                if: { direction: ["c2s"], opcode: ["text"] },
                source: "const",
                counter: "e2e-ws-mask",
                axes: ["user"],
              },
              {
                if: { direction: ["c2s"], opcode: ["text"] },
                source: "const",
                counter: "e2e-ws-ban",
                axes: ["user"],
              },
            ],
            judge: [
              { counter: "e2e-ws-ban", axis: "user", at: 90, action: "deny", code: "E2E_WS_FLOOD" },
            ],
            denyResponse: "ws_policy",
            outcomes: [
              {
                on: "level",
                if: { counter: "e2e-ws-mask", axis: "user" },
                at: 90,
                to: "e2e-rw",
                verb: "mutate",
                /* Ось request на кадре -- «этот кадр»: следующий снова решается заново. */
                axis: "request",
                group: "mask",
                set: "on",
                code: "E2E_WS_MASK",
              },
            ],
          },
        },
      ],
      rewriteProfiles: [
        {
          name: "e2e-cnt-rewrite",
          description: "Маска в кадре клиента: группа включается просьбой счётчика",
          groups: [
            {
              name: "mask",
              default: false,
              on: "frame",
              /*
               * Сторона c2s: контроллер печатает вызов кадровых инспекторов
               * всегда как frame:c2s, и правка живёт в кадре клиента -- эхо
               * приложения возвращает уже подменённое.
               */
              direction: ["c2s"],
              opcode: ["text"],
              body: [{ op: "replace", pattern: "canary-([0-9a-f]{8})", to: "masked-$1" }],
            },
          ],
          prior: [{ from: "e2e-cnt", accept: ["mutate"], codes: ["E2E_WS_MASK"] }],
        },
      ],
      authSources: [JWT_SOURCE],
      authProfiles: [JWT_GATE],
      upstreams: [APP],
      declarations: {
        "e2e-gate": { process: "auth", profileFrom: "e2e-cnt-gate" },
        "e2e-cnt": { process: "counter", profileFrom: "e2e-cnt-frames" },
        "e2e-rw": { process: "rewrite", profileFrom: "e2e-cnt-rewrite" },
      },
      servers: [SERVER_SPEC],
      routes: [
        {
          /*
           * Путь именно `/socket/`: сокеты держит само приложение витрины
           * (`/socket/chat`), и переписывать путь маршруту незачем.
           */
          server: SERVER,
          match: "prefix",
          path: "/socket/",
          protocol: "websocket",
          position: 100,
          upstream: APP.name,
          nginx: {
            proxyHeaders: "websocket",
            proxySetHeaders: [
              { name: "Host", value: "$host" },
              { name: "X-Forwarded-For", value: "$proxy_add_x_forwarded_for" },
            ],
            proxyHttpVersion: "1.1",
            proxyReadTimeoutMs: 3_600_000,
          },
          waf: {
            /*
             * Снимается только сторона клиента: инспекторы стоят на ней, а
             * снимок стороны приложения означал бы, что кадр приложения едет
             * клиенту из обменника -- лишний круг там, где никто не смотрит.
             */
            /*
             * Снимок кадра срезом -- как его и пишут на живых маршрутах. До
             * 10.09.2026 это молча отменяло подмену: умолчание `waf_send frame
             * body` при срезе было `original`, инспектор писал в лог «frame
             * rewritten», а приложение получало исходный кадр. Теперь умолчание
             * -- «с правками», и кейс это стережёт: кадр в срез укладывается,
             * значит подмена обязана доехать. Кадр ШИРЕ среза по-прежнему
             * подменить нельзя -- это сбой подъёма по `waf_exception frame
             * body`, с `partial: true` в записи.
             */
            capture: ["request headers args", "frame:c2s body=64k"],
            bodyLimit: "frame:c2s 64k",
            bodyLimitPolicy: "block",
            preview: ["headers=16k/2k", "args=8k/1k"],
            deadlineMs: 2000,
            frameDeadlineMs: 1000,
            exception: ["request deny response=error", "frame deny response=ws_policy"],
            /*
             * Каждый спрошенный кадр уезжает записью, а не только тот, у
             * которого есть что сказать: разбирать несошедшийся шаг больше не
             * по чему -- отладочного заголовка у кадра нет.
             */
            frameAudit: "all",
            /* Калитка -- на рукопожатии: личность с него и приезжает на каждый кадр. */
            requestInspectors: [{ name: "e2e-gate", wave: 0 }],
            frameInspectors: [
              { name: "e2e-cnt", wave: 0, timeoutMs: 500 },
              { name: "e2e-rw", wave: 1, timeoutMs: 500 },
            ],
            responseInspectors: "none",
          },
        },
        {
          /* Соседний обычный маршрут: им проверяется вход и доехавшее поколение. */
          server: SERVER,
          match: "prefix",
          path: "/logic/counter-frames/",
          position: 101,
          upstream: APP.name,
          waf: {
            capture: ["request headers args"],
            preview: ["headers=16k/2k", "args=8k/1k"],
            deadlineMs: 2000,
            exception: ["request deny response=error"],
            requestInspectors: [
              { name: "e2e-gate", wave: 0 },
              { name: "e2e-cnt", wave: 1 },
            ],
            responseInspectors: "none",
          },
        },
      ],
    },
    target: { host: SERVER, path: "/logic/counter-frames/" },
    probes: [
      {
        name: "гость: калитка отказывает и на обычном маршруте",
        expect: { deny: "auth_required", verdict: "deny", notAsked: "e2e-cnt" },
      },
      {
        /*
         * Фаза запроса у профиля выключена -- счётчику здесь нечего делать, и
         * он отвечает allow. Проверка не про суд, а про то, что поколение с
         * секцией кадров доехало до инспектора: до кадров повторять уже нечего.
         */
        name: "вошедший проходит, профиль кадров доехал до инспектора",
        headers: { Authorization: "@bearer.alice" },
        expect: { status: 200, verdict: "allow", answers: { "e2e-cnt": "allow" } },
      },
    ],
    socket: {
      path: "/socket/chat",
      headers: { Authorization: "@bearer.alice" },
      /*
       * Шаг -- «послать кадр и прочитать, что вернулось», и читается на нём
       * ответ на ПРЕДЫДУЩИЙ кадр. Так вышло из-за приветствия: приложение
       * здоровается само, сразу после рукопожатия, а доезжает это приветствие
       * до клиента вместе с первым кадром клиента -- иногда сразу, а иногда
       * только тогда (замерено на этом же прогоне: с ожиданием в десять секунд
       * приветствия так и не было, а после первого кадра оно пришло за
       * тридцать миллисекунд). Ждать его отдельным шагом значит ловить эту
       * разницу; читать со сдвигом на кадр -- не значит.
       */
      steps: [
        {
          name: "кадр 1 -- в ответ приходит приветствие приложения",
          send: "canary-deadbeef",
          expect: { echoHas: "\"type\":\"hello\"" },
        },
        {
          /* Корзина маски была наполовину, когда решался кадр 1: метка цела. */
          name: "кадр 2 -- эхо первого: метка как есть, корзина маски полна",
          send: "canary-deadbeef",
          expect: { echoHas: "canary-deadbeef", echoLacks: "masked-deadbeef" },
        },
        {
          /* Кадр 2 решался на полной корзине: счётчик попросил маску. */
          name: "кадр 3 -- эхо второго: приложение получило маску",
          send: "canary-deadbeef",
          expect: { echoHas: "masked-deadbeef", echoLacks: "canary-deadbeef" },
        },
        {
          name: "кадр 4 -- эхо третьего: маска держится",
          send: "canary-deadbeef",
          expect: { echoHas: "masked-deadbeef" },
        },
        {
          /*
           * Пятый кадр переливает корзину закрытия (5 из 5) и отказывается сам
           * -- на кадрах учёт и суд живут на одном кадре. Эхо четвёртого могло
           * уже быть в пути: шаг ждёт именно закрытия, кадры с данными по
           * дороге пропускаются.
           */
          name: "кадр 5 переливает корзину закрытия: соединение закрыто",
          send: "canary-deadbeef",
          expect: { closed: true },
        },
      ],
    },
  },
  {
    id: "captcha-degrade",
    title: "Долбёжку не отказывают, а обедняют: маска до капчи, выдача после",
    about: [
      "Отказ -- не единственный ответ на подозрение. Клиенту можно продолжать",
      "отвечать 200 и при этом не отдавать то, ради чего он пришёл. На машинных",
      "путях это единственное, что работает: виджет там показывать некому.",
      "",
      "Раскладка: один маршрут, капча и модификатор объявлены на нём в режиме",
      "`off` -- записаны, но не публикуются, пока сосед не включит их глаголом",
      "(модуль держит таких «про запас», не платя за них на каждом запросе).",
      "Включает инспектор действий по пути: на `/page/` капча получает `active`",
      "и гейтит -- редирект на виджет; на `/api/` капча получает `vote`, а",
      "модификатор `active`. В `vote` капча с решения снята: её `deny` -- сотня",
      "очков, класть которую некуда, отказа клиент не видит.",
      "",
      "Корзину капчи наливает счётчик: считает отданные объекты на адрес и за",
      "половиной своей корзины просит капчу `note +100`. Дальше маску держит сама",
      "капча: её пороговое правило `bucket_captcha` срабатывает на каждом запросе,",
      "пока корзина выше порога, и каждый раз просит модификатора включить",
      "группу `prices`. Клиент получает 200 и ту же форму ответа без меток.",
      "",
      "Снимает маску клиренс. Прогон проходит виджет на `/page/`, и дальше на",
      "каждом запросе с действующим клиренсом капча просит `set=off`. На таком",
      "запросе она шлёт обе просьбы -- порог всё ещё выше, -- и обе едут одной",
      "пачкой в порядке «порог, потом клиренс». Кейс закрепляет, что последняя",
      "побеждает, а следом -- что клиренс не индульгенция: без куки маска",
      "возвращается.",
      "",
      "Пороговые правила капчи раньше глушились на минуту на субъекта, и маска",
      "включалась на один ответ; глушилка снята 10.09, четвёртая проба кейса",
      "стоит ровно на этом.",
    ].join("\n"),
    needs: {
      counterShared: {
        "e2e-cap-views": { unit: "obj", axes: { ip: { max: 20, loss: 0.5 } } },
      },
      counterProfiles: [
        {
          name: "e2e-cap-cnt",
          description: "Объекты на адрес: с половины корзины наливаем корзину капчи",
          request: {
            judge: [],
            outcomes: [
              {
                on: "level",
                if: { counter: "e2e-cap-views", axis: "ip" },
                at: 50,
                to: "e2e-cap",
                verb: "note",
                axis: "ip",
                /* Сто процентов шкалы получателя: одна просьба наливает корзину капчи доверху. */
                value: 100,
                code: "E2E_CAP_FILL",
              },
            ],
          },
          response: {
            measure: [
              {
                if: { status: [200], contentType: ["application/json", "+json"] },
                source: "regex_count",
                regex: "obj=\\d+",
                counter: "e2e-cap-views",
                axes: ["ip"],
              },
            ],
          },
        },
      ],
      actionProfiles: [
        {
          name: "e2e-cap-act",
          description: "Разводка по пути: где гейтить капчей, где обеднять выдачу",
          rules: [
            {
              /* Навигационная часть: капча боевая, виджет уместен. */
              name: "page",
              pathPrefix: "/logic/captcha-degrade/page/",
              actions: [{ to: "e2e-cap", verb: "active", axis: "request", code: "E2E_CAP_PAGE" }],
            },
            {
              /*
               * Машинная часть: капча совещательная -- спрашивается, просит,
               * но не решает; модификатор включён и ждёт её просьбы.
               */
              name: "api",
              pathPrefix: "/logic/captcha-degrade/api/",
              actions: [
                { to: "e2e-cap", verb: "vote", axis: "request", code: "E2E_CAP_API" },
                { to: "e2e-rw", verb: "active", axis: "request", code: "E2E_CAP_API" },
              ],
            },
          ],
        },
      ],
      rewriteProfiles: [
        {
          name: "e2e-cap-rw",
          description: "Маска выдачи: группа выключена, включает и выключает её капча",
          groups: [
            {
              name: "prices",
              default: false,
              on: "response",
              status: [200],
              contentType: ["application/json", "+json"],
              body: [{ op: "replace", pattern: "canary-([0-9a-f]{8})", to: "***" }],
            },
          ],
          /* Грант поимённый: переключать группу вправе только капча, по двум поводам. */
          prior: [{ from: "e2e-cap", accept: ["mutate"], codes: ["E2E_CAP_MASK", "E2E_CAP_CLEAR"] }],
        },
      ],
      upstreams: [
        APP,
        /* Виджет обслуживает свой процесс, не приложение: у капчи два контейнера. */
        { name: "e2e-cap-http", peers: [{ host: "captcha-http", port: 8080 }] },
      ],
      declarations: {
        "e2e-act": { process: "action", profileFrom: "e2e-cap-act" },
        "e2e-cnt": { process: "counter", profileFrom: "e2e-cap-cnt" },
        "e2e-rw": { process: "rewrite", profileFrom: "e2e-cap-rw" },
        /*
         * Профиль капчи заводится позже маршрутов (ему нужны сервер и локация
         * виджета), поэтому объявление зовёт его по имени, а не ссылкой на
         * заведённое: наличия профиля при записи объявлений никто не проверяет,
         * а к изданию он уже есть.
         */
        "e2e-cap": { process: "captcha", profile: "e2e-cap" },
      },
      servers: [
        {
          ...SERVER_SPEC,
          /* Без этого модуль не выпустит редирект капчи: цель обязана быть названа. */
          waf: { ...SERVER_SPEC.waf, redirectAllow: ["/waf/captcha"] },
        },
      ],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/captcha-degrade/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            /*
             * Кто просит -- раньше, кого просят -- позже: просьба едет в prior
             * следующих волн. Инспектор действий и счётчик просят капчу, поэтому
             * оба на нулевой волне, капча -- на первой. Капча и модификатор
             * записаны в `off`: их включает инспектор действий, и только там,
             * где они нужны.
             */
            requestInspectors: [
              { name: "e2e-act", wave: 0 },
              { name: "e2e-cnt", wave: 0 },
              { name: "e2e-cap", wave: 1, mode: "off" },
            ],
            responseInspectors: [
              { name: "e2e-rw", wave: 0, mode: "off", timeoutMs: 2500 },
              { name: "e2e-cnt", wave: 1 },
            ],
          },
        },
        {
          /*
           * Страница виджета. Инспекторов на ней нет вовсе -- рекурсию «капча
           * требует капчу» создают они, а не модуль, -- и вместе с ними
           * снимаются снимок, превью и архив: иначе `nginx -t` откажет
           * («preview wider than capture»).
           */
          server: SERVER,
          match: "prefix",
          path: "/waf/captcha",
          position: 90,
          upstream: "e2e-cap-http",
          waf: {
            requestInspectors: "none",
            responseInspectors: "none",
            capture: ["request none"],
            preview: ["request none"],
            archive: ["request none"],
          },
        },
      ],
      captchaProfiles: [
        {
          name: "e2e-cap",
          server: SERVER,
          path: "/waf/captcha",
          when: "buckets",
          /* Грант поимённый: наливать корзину вправе названный отправитель и по названному поводу. */
          prior: [{ from: "e2e-cnt", accept: ["note"], codes: ["E2E_CAP_FILL"] }],
          /*
           * Потери малы намеренно: корзина не должна остыть между шагами
           * прогона. Нулём их поставить нельзя -- контроллер требует (0..100],
           * и он прав: корзина без утечки не отпускает никогда.
           */
          buckets: { ip: { max: 100, loss: 0.1, captchaAt: 50, banAt: 0 } },
          gate: { redirectMethods: ["GET"], denyResponse: "captcha_required", htmlOnly: true },
          rules: [
            {
              /* Порог выше -- маска включена. Срабатывает на каждом запросе, пока так. */
              on: "bucket_captcha",
              bucket: "ip",
              to: "e2e-rw",
              verb: "mutate",
              axis: "request",
              group: "prices",
              set: "on",
              code: "E2E_CAP_MASK",
            },
            {
              /* Клиренс действует -- маска снята. Тоже на каждом таком запросе. */
              on: "cleared",
              to: "e2e-rw",
              verb: "mutate",
              axis: "request",
              group: "prices",
              set: "off",
              code: "E2E_CAP_CLEAR",
            },
            /* Прошёл человек -- своя корзина в ноль. Строка либо просьба, либо заряд. */
            { on: "cleared", charge: "ip", percent: -100 },
          ],
        },
      ],
    },
    target: { host: SERVER, path: "/logic/captcha-degrade/api/" },
    probes: [
      {
        name: "корзина пуста: выдача целая, капча спрошена совещательно",
        path: "/logic/captcha-degrade/api/?objects=6",
        ip: "@run.ip",
        expect: { status: 200, verdict: "allow", bodyHas: "canary-", asked: ["e2e-act", "e2e-cnt", "e2e-cap"] },
      },
      {
        name: "ниже половины: всё ещё целая",
        path: "/logic/captcha-degrade/api/?objects=6",
        ip: "@run.ip",
        expect: { status: 200, verdict: "allow", bodyHas: "canary-" },
      },
      {
        name: "за половиной: счётчик налил корзину капчи, порог просит маску",
        path: "/logic/captcha-degrade/api/?objects=6",
        ip: "@run.ip",
        times: 2,
        expect: { status: 200, verdict: "allow", bodyHas: "***", bodyLacks: "canary-" },
      },
      {
        /*
         * Проба, ради которой снята глушилка: раньше порог срабатывал раз в
         * минуту, и второй ответ подряд шёл целым.
         */
        name: "следующий запрос: маска держится, а не гаснет",
        path: "/logic/captcha-degrade/api/?objects=6",
        ip: "@run.ip",
        expect: { status: 200, verdict: "allow", bodyHas: "***", bodyLacks: "canary-" },
      },
      { solve: "виджет пройден на навигационной части", from: "/logic/captcha-degrade/page/", ip: "@run.ip" },
      {
        name: "с клиренсом: порог просит включить, клиренс -- выключить, побеждает поздний",
        path: "/logic/captcha-degrade/api/?objects=6",
        ip: "@run.ip",
        cleared: true,
        expect: { status: 200, verdict: "allow", bodyHas: "canary-", bodyLacks: "***" },
      },
      {
        name: "без куки: корзина всё ещё выше порога, маска возвращается",
        path: "/logic/captcha-degrade/api/?objects=6",
        ip: "@run.ip",
        expect: { status: 200, verdict: "allow", bodyHas: "***", bodyLacks: "canary-" },
      },
    ],
  },

  {
    id: "captcha-uncleared",
    title: "Не проходил капчу -- выдача замаскирована с первого запроса, без корзин",
    about: [
      "Событие `uncleared` капчи -- запрос клиента без действующего клиренса, что",
      "бы лестница ни решила дальше: пропустить или показать виджет. Им капча",
      "включает соседей дальше по цепочке -- здесь модификатор, который прячет",
      "метки выдачи. Корзин нет, счётчика нет: маску держит само отсутствие",
      "клиренса.",
      "",
      "Раскладка та же, что у `captcha-degrade`: капча и модификатор записаны в",
      "`off`, включает их инспектор действий по пути. На `/page/` капча `active` и",
      "гейтит (`when: always`) -- редирект на виджет; на `/api/` она `vote`: отказ",
      "без клиренса становится сотней очков, класть которую некуда, а просьба",
      "`mutate` доезжает модификатору -- запрос идёт дальше.",
      "",
      "Разница с `captcha-degrade` в том, кого маскируют. Там маску держит порог",
      "корзины, и пока корзина холодная, непроверенный клиент видит всё. Здесь --",
      "всякий, кто виджет не проходил, с первого же запроса. Клиренс маску не",
      "выключает: на запросе с ним капче просто нечего просить, а группа",
      "выключена по умолчанию.",
    ].join("\n"),
    needs: {
      actionProfiles: [
        {
          name: "e2e-cap-act",
          description: "Разводка по пути: где гейтить капчей, где обеднять выдачу",
          rules: [
            {
              /* Навигационная часть: капча боевая, виджет уместен. */
              name: "page",
              pathPrefix: "/logic/captcha-uncleared/page/",
              actions: [{ to: "e2e-cap", verb: "active", axis: "request", code: "E2E_CAP_PAGE" }],
            },
            {
              /*
               * Машинная часть: капча совещательная -- спрашивается, просит,
               * но не решает; модификатор включён и ждёт её просьбы.
               */
              name: "api",
              pathPrefix: "/logic/captcha-uncleared/api/",
              actions: [
                { to: "e2e-cap", verb: "vote", axis: "request", code: "E2E_CAP_API" },
                { to: "e2e-rw", verb: "active", axis: "request", code: "E2E_CAP_API" },
              ],
            },
          ],
        },
      ],
      rewriteProfiles: [
        {
          name: "e2e-cap-rw",
          description: "Маска выдачи: группа выключена, включает её капча тем, у кого нет клиренса",
          groups: [
            {
              name: "prices",
              default: false,
              on: "response",
              status: [200],
              contentType: ["application/json", "+json"],
              body: [{ op: "replace", pattern: "canary-([0-9a-f]{8})", to: "***" }],
            },
          ],
          /* Грант поимённый: переключать группу вправе только капча, по одному поводу. */
          prior: [{ from: "e2e-cap", accept: ["mutate"], codes: ["E2E_CAP_UNCLEARED"] }],
        },
      ],
      upstreams: [
        APP,
        /* Виджет обслуживает свой процесс, не приложение: у капчи два контейнера. */
        { name: "e2e-cap-http", peers: [{ host: "captcha-http", port: 8080 }] },
      ],
      declarations: {
        "e2e-act": { process: "action", profileFrom: "e2e-cap-act" },
        "e2e-rw": { process: "rewrite", profileFrom: "e2e-cap-rw" },
        /* Профиль капчи заводится позже маршрутов -- объявление зовёт его по имени. */
        "e2e-cap": { process: "captcha", profile: "e2e-cap" },
      },
      servers: [
        {
          ...SERVER_SPEC,
          /* Без этого модуль не выпустит редирект капчи: цель обязана быть названа. */
          waf: { ...SERVER_SPEC.waf, redirectAllow: ["/waf/captcha"] },
        },
      ],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/captcha-uncleared/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            /*
             * Кто просит -- раньше, кого просят -- позже: капча на волне
             * запроса, модификатор -- на фазе ответа. Оба записаны в `off`:
             * их включает инспектор действий, и только там, где они нужны.
             */
            requestInspectors: [
              { name: "e2e-act", wave: 0 },
              { name: "e2e-cap", wave: 1, mode: "off" },
            ],
            responseInspectors: [{ name: "e2e-rw", wave: 0, mode: "off", timeoutMs: 2500 }],
          },
        },
        {
          /* Страница виджета: инспекторов нет, и снимок с превью и архивом сняты с ними. */
          server: SERVER,
          match: "prefix",
          path: "/waf/captcha",
          position: 90,
          upstream: "e2e-cap-http",
          waf: {
            requestInspectors: "none",
            responseInspectors: "none",
            capture: ["request none"],
            preview: ["request none"],
            archive: ["request none"],
          },
        },
      ],
      captchaProfiles: [
        {
          name: "e2e-cap",
          server: SERVER,
          path: "/waf/captcha",
          /* Виджет каждому без клиренса: на `/page/` -- редирект, на `/api/` -- отказ, ставший очками. */
          when: "always",
          gate: { redirectMethods: ["GET"], denyResponse: "captcha_required", htmlOnly: true },
          rules: [
            {
              /* Клиренса нет -- маска включена. На каждом таком запросе, что бы капча ни решила. */
              on: "uncleared",
              to: "e2e-rw",
              verb: "mutate",
              axis: "request",
              group: "prices",
              set: "on",
              code: "E2E_CAP_UNCLEARED",
            },
          ],
        },
      ],
    },
    target: { host: SERVER, path: "/logic/captcha-uncleared/api/" },
    probes: [
      {
        name: "без клиренса на API: капча спрошена совещательно, выдача замаскирована с первого запроса",
        path: "/logic/captcha-uncleared/api/?objects=6",
        ip: "@run.ip",
        expect: { status: 200, verdict: "allow", bodyHas: "***", bodyLacks: "canary-", asked: ["e2e-act", "e2e-cap"] },
      },
      {
        name: "следующий запрос: маска держится -- событие на каждом запросе",
        path: "/logic/captcha-uncleared/api/?objects=6",
        ip: "@run.ip",
        expect: { status: 200, verdict: "allow", bodyHas: "***", bodyLacks: "canary-" },
      },
      {
        name: "без клиренса на странице: виджет",
        path: "/logic/captcha-uncleared/page/",
        ip: "@run.ip",
        headers: { Accept: "text/html" },
        expect: { status: 303 },
      },
      { solve: "виджет пройден на навигационной части", from: "/logic/captcha-uncleared/page/", ip: "@run.ip" },
      {
        name: "с клиренсом: маски нет -- капче нечего просить",
        path: "/logic/captcha-uncleared/api/?objects=6",
        ip: "@run.ip",
        cleared: true,
        expect: { status: 200, verdict: "allow", bodyHas: "canary-", bodyLacks: "***" },
      },
      {
        name: "без куки снова: маска возвращается",
        path: "/logic/captcha-uncleared/api/?objects=6",
        ip: "@run.ip",
        expect: { status: 200, verdict: "allow", bodyHas: "***", bodyLacks: "canary-" },
      },
    ],
  },

  {
    id: "captcha-widget-price",
    title: "Цена показа виджета: пропущенный без клиренса не платит, показы копят корзину до бана",
    about: [
      "Уточнение `next` у события `uncleared` -- что капча решила с клиентом на",
      "этом запросе: пропустила или показала виджет. Здесь им назначена цена",
      "показа: `uncleared` + `next: challenge` -- адресу плюс 30% в корзину. Бот,",
      "который виджет не решает и даже не пытается, провалов не копит -- `on:",
      "fail` его не видит, -- а показы копит: корзина доходит до `ban_at`, порог",
      "пишет адрес в живой набор, и режет инспектор адреса нулевой волной.",
      "",
      "Контроль -- тот же адрес на пропускающем пути. На `/free/` инспектор",
      "действий просит капчу `skip` (грант поимённый), капча пропускает, и",
      "правило с `next: challenge` молчит: шесть запросов без клиренса не стоят",
      "ничего, набор бана пуст. Там же срабатывает правило с `next: allow` --",
      "очки маршруту: пропуск событие тоже видит, только другим правилом.",
      "",
      "Порог бана 90, а не 100: заряд правила ложится после решения, а",
      "следующий запрос читает уровень уже за вычетом утечки -- упёршись в",
      "ёмкость, корзина до ста не дотягивает.",
    ].join("\n"),
    needs: {
      datasets: [
        { name: "e2e-ban-ip", description: "Бан адреса: пишет капча по цене показов", type: "ip", active: true },
      ],
      ipSets: [{ name: "e2e-ban-ipset", lists: ["e2e-ban-ip"] }],
      ipProfiles: [
        {
          name: "e2e-ban-prof",
          default: "allow",
          datasets: ["e2e-ban-ip"],
          rules: [{ action: "deny", set: "e2e-ban-ipset", response: "blocked", code: "E2E_BAN_IP" }],
        },
      ],
      actionProfiles: [
        {
          name: "e2e-price-act",
          description: "Пропускающий путь: капчу просят не спрашивать",
          rules: [
            {
              name: "free",
              pathPrefix: "/logic/captcha-widget-price/free/",
              actions: [{ to: "e2e-cap", verb: "skip", axis: "request", code: "E2E_CAP_FREE" }],
            },
          ],
        },
      ],
      upstreams: [
        APP,
        { name: "e2e-cap-http", peers: [{ host: "captcha-http", port: 8080 }] },
      ],
      declarations: {
        "e2e-ip": { process: "ip", profileFrom: "e2e-ban-prof" },
        "e2e-act": { process: "action", profileFrom: "e2e-price-act" },
        "e2e-cap": { process: "captcha", profile: "e2e-cap" },
      },
      servers: [
        {
          ...SERVER_SPEC,
          waf: { ...SERVER_SPEC.waf, redirectAllow: ["/waf/captcha"] },
        },
      ],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/captcha-widget-price/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...ROUTE_WAF,
            /*
             * Инспектор адреса один на нулевой волне: его отказ обрывает фазу,
             * и забаненный до капчи не доходит. Инспектор действий просит
             * капчу -- он раньше неё. Капча боевая на всём маршруте.
             */
            requestInspectors: [
              { name: "e2e-ip", wave: 0 },
              { name: "e2e-act", wave: 1 },
              { name: "e2e-cap", wave: 2 },
            ],
          },
        },
        {
          server: SERVER,
          match: "prefix",
          path: "/waf/captcha",
          position: 90,
          upstream: "e2e-cap-http",
          waf: {
            requestInspectors: "none",
            responseInspectors: "none",
            capture: ["request none"],
            preview: ["request none"],
            archive: ["request none"],
          },
        },
      ],
      captchaProfiles: [
        {
          name: "e2e-cap",
          server: SERVER,
          path: "/waf/captcha",
          /* Виджет каждому без клиренса -- кроме тех, за кого попросили skip. */
          when: "always",
          prior: [{ from: "e2e-act", accept: ["skip"], codes: ["E2E_CAP_FREE"] }],
          /* На виджет корзина не гонит (порог капчи 0): она только копит цену показов. */
          buckets: { ip: { max: 100, loss: 0.1, captchaAt: 0, banAt: 90 } },
          gate: { redirectMethods: ["GET"], denyResponse: "captcha_required", htmlOnly: true },
          rules: [
            /* Показала виджет -- плюс 30% адресу: четыре показа, и пятый запрос за порогом. */
            { on: "uncleared", next: "challenge", charge: "ip", percent: 30 },
            /* Пропустила -- очки маршруту: видно, что пропуск событие тоже видит. */
            { on: "uncleared", next: "allow", verb: "score", axis: "request", value: 7, code: "E2E_CAP_LET" },
            { on: "bucket_ban", bucket: "ip", list: "e2e-ban-ip", write: "addr", ttlS: 30, code: "E2E_BAN_PRICE" },
          ],
        },
      ],
    },
    target: { host: SERVER, path: "/logic/captcha-widget-price/page/" },
    probes: [
      {
        name: "пропускающий путь: шесть запросов без клиренса -- капча пропустила, очки начислены",
        path: "/logic/captcha-widget-price/free/",
        ip: "@run.ip",
        times: 6,
        expect: { status: 200, verdict: "allow", scoreAtLeast: 7, answers: { "e2e-cap": "allow" } },
      },
      { name: "пропуски не стоят ничего: набор бана пуст", list: "e2e-ban-ip", expect: { lacks: "@run.ip" } },
      {
        name: "три показа виджета: корзина копится, до порога бана ещё не дошла",
        path: "/logic/captcha-widget-price/page/",
        ip: "@run.ip",
        headers: { Accept: "text/html" },
        times: 3,
        expect: { status: 303, answers: { "e2e-ip": "allow", "e2e-cap": "redirect" } },
      },
      {
        name: "следующие показы переливают корзину за порог: бан, режет инспектор адреса",
        path: "/logic/captcha-widget-price/page/",
        ip: "@run.ip",
        headers: { Accept: "text/html" },
        times: 2,
        settleMs: 20_000,
        expect: { deny: "blocked", verdict: "deny", answers: { "e2e-ip": "deny/E2E_BAN_IP" } },
      },
      { name: "в наборе бана -- адрес прогона со сроком 30 с", list: "e2e-ban-ip", expect: { has: "@run.ip", ttlMax: 30 } },
    ],
  },

  {
    id: "captcha-ban-ladder",
    title: "Лестница капчи: с 60 маска, со 100 бан на адрес, подсеть и AS с разными сроками",
    about: [
      "Продолжение `captcha-degrade`: та же раскладка (капча и модификатор в",
      "`off`, включает их инспектор действий по пути), но корзина капчи ползёт",
      "вверх постепенно -- счётчик наливает её по двадцать процентов за запрос.",
      "От 60 клиент получает 200 с замаскированной выдачей, на 100 срабатывает",
      "`bucket_ban`, и капча пишет три записи с тремя сроками: адрес на 10 с,",
      "анонс подсети из гео на 30 с, номер AS на 60 с.",
      "",
      "Режет инспектор адреса, и стоит он **перед всеми**: нулевой волной, по",
      "живым наборам. Забаненный не доходит ни до счётчика, ни до капчи --",
      "корзины остывают, лестница не зацикливается. Коды отказа меняются во",
      "времени: сначала E2E_BAN_IP, через десять секунд запись адреса протухла",
      "-- E2E_BAN_NET, через тридцать протухла подсеть -- E2E_BAN_ASN, через",
      "минуту протухла и система -- клиент проходит с целой выдачей: обе",
      "корзины за это время остыли ниже порогов.",
      "",
      "Третий ярус -- не число в наборе, а сама система: капча спрашивает у",
      "кодера гео (gRPC, синхронно, в бюджете сообщения) все накрывающие анонсы",
      "и состав каждой системы и пишет их в тот же адресный набор одним кадром",
      "keeper -- либо всё, либо ничего. Режут те же, кто уже умеет: инспектор",
      "адреса по живому списку. Кодер нужен и молчит -- капча отвечает error,",
      "не пропуском. Кейс это не проверяет: молчащий кодер на стенде не",
      "устроить, не роняя его для всех.",
      "",
      "Что проверяется про «лишнее»: сосед из той же системы, но другого",
      "анонса, попадает под ярус AS и только под него; сосед из чужой системы",
      "не задет ни одним ярусом. На стенде у 15169 кодер знает один анонс,",
      "поэтому набор AS и набор анонсов совпадают -- ярусы различимы только",
      "сроками; на полной базе они различаются составом.",
      "",
      "Адрес прогона берётся из 8.8.8.0/24: гео на стенде частичный, а без",
      "резолва анонса `write: net` и `write: asn` молча не запишут ничего.",
    ].join("\n"),
    address: { within: "8.8.8.0/24" },
    needs: {
      datasets: [
        { name: "e2e-ban-ip", description: "Бан адреса: пишет капча, срок 10 с", type: "ip", active: true },
        { name: "e2e-ban-net", description: "Бан анонса: пишет капча, срок 30 с", type: "ip", active: true },
        { name: "e2e-ban-asn", description: "Бан AS целиком: капча пишет все её анонсы, срок 60 с", type: "ip", active: true },
      ],
      ipSets: [
        { name: "e2e-ban-ipset", lists: ["e2e-ban-ip"] },
        { name: "e2e-ban-netset", lists: ["e2e-ban-net"] },
        { name: "e2e-ban-asnset", lists: ["e2e-ban-asn"] },
      ],
      ipProfiles: [
        {
          name: "e2e-ban-prof",
          default: "allow",
          datasets: ["e2e-ban-ip", "e2e-ban-net", "e2e-ban-asn"],
          /*
           * Порядок значим: адрес совпадает со всеми тремя наборами, и код
           * называет первый живой. По мере протухания записей код сменяется
           * -- это и есть лестница, видимая снаружи.
           */
          rules: [
            { action: "deny", set: "e2e-ban-ipset", response: "blocked", code: "E2E_BAN_IP" },
            { action: "deny", set: "e2e-ban-netset", response: "blocked", code: "E2E_BAN_NET" },
            { action: "deny", set: "e2e-ban-asnset", response: "blocked", code: "E2E_BAN_ASN" },
          ],
        },
      ],
      counterShared: {
        /*
         * Потери у обеих корзин подобраны так, чтобы за окно бана они остыли
         * ниже порогов: иначе первый же запрос после протухания снова
         * наливает и снова банит, и лестница не кончается.
         */
        "e2e-ban-views": { unit: "obj", axes: { ip: { max: 20, loss: 2 } } },
      },
      counterProfiles: [
        {
          name: "e2e-ban-cnt",
          description: "Объекты на адрес: с половины корзины наливаем корзину капчи по двадцать",
          request: {
            judge: [],
            outcomes: [
              {
                on: "level",
                if: { counter: "e2e-ban-views", axis: "ip" },
                at: 50,
                to: "e2e-cap",
                verb: "note",
                axis: "ip",
                /* По двадцать, а не доверху: между маской и баном должно быть видно окно. */
                value: 20,
                code: "E2E_BAN_FILL",
              },
            ],
          },
          response: {
            measure: [
              {
                if: { status: [200], contentType: ["application/json", "+json"] },
                source: "regex_count",
                regex: "obj=\\d+",
                counter: "e2e-ban-views",
                axes: ["ip"],
              },
            ],
          },
        },
      ],
      actionProfiles: [
        {
          name: "e2e-ban-act",
          description: "Разводка по пути: где гейтить капчей, где обеднять выдачу",
          rules: [
            {
              name: "page",
              pathPrefix: "/logic/ban-ladder/page/",
              actions: [{ to: "e2e-cap", verb: "active", axis: "request", code: "E2E_BAN_PAGE" }],
            },
            {
              name: "api",
              pathPrefix: "/logic/ban-ladder/api/",
              actions: [
                { to: "e2e-cap", verb: "vote", axis: "request", code: "E2E_BAN_API" },
                { to: "e2e-rw", verb: "active", axis: "request", code: "E2E_BAN_API" },
              ],
            },
          ],
        },
      ],
      rewriteProfiles: [
        {
          name: "e2e-ban-rw",
          description: "Маска выдачи между порогами: включает капча",
          groups: [
            {
              name: "prices",
              default: false,
              on: "response",
              status: [200],
              contentType: ["application/json", "+json"],
              body: [{ op: "replace", pattern: "canary-([0-9a-f]{8})", to: "***" }],
            },
          ],
          prior: [{ from: "e2e-cap", accept: ["mutate"], codes: ["E2E_CAP_MASK"] }],
        },
      ],
      upstreams: [
        APP,
        { name: "e2e-cap-http", peers: [{ host: "captcha-http", port: 8080 }] },
      ],
      declarations: {
        "e2e-ip": { process: "ip", profileFrom: "e2e-ban-prof" },
        "e2e-act": { process: "action", profileFrom: "e2e-ban-act" },
        "e2e-cnt": { process: "counter", profileFrom: "e2e-ban-cnt" },
        "e2e-rw": { process: "rewrite", profileFrom: "e2e-ban-rw" },
        "e2e-cap": { process: "captcha", profile: "e2e-cap" },
      },
      servers: [
        {
          ...SERVER_SPEC,
          waf: { ...SERVER_SPEC.waf, redirectAllow: ["/waf/captcha"] },
        },
      ],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/logic/ban-ladder/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            /*
             * Инспектор адреса один на нулевой волне: его отказ обрывает фазу,
             * и забаненный не доходит до остальных. Инспектор действий и
             * счётчик просят капчу -- они раньше неё.
             */
            requestInspectors: [
              { name: "e2e-ip", wave: 0 },
              { name: "e2e-act", wave: 1 },
              { name: "e2e-cnt", wave: 1 },
              { name: "e2e-cap", wave: 2, mode: "off" },
            ],
            responseInspectors: [
              { name: "e2e-rw", wave: 0, mode: "off", timeoutMs: 2500 },
              { name: "e2e-cnt", wave: 1 },
            ],
          },
        },
        {
          server: SERVER,
          match: "prefix",
          path: "/waf/captcha",
          position: 90,
          upstream: "e2e-cap-http",
          waf: {
            requestInspectors: "none",
            responseInspectors: "none",
            capture: ["request none"],
            preview: ["request none"],
            archive: ["request none"],
          },
        },
      ],
      captchaProfiles: [
        {
          name: "e2e-cap",
          server: SERVER,
          path: "/waf/captcha",
          when: "buckets",
          prior: [{ from: "e2e-cnt", accept: ["note"], codes: ["E2E_BAN_FILL"] }],
          /* Ёмкость сто, маска с 60, бан на 100; остывает за 50 с -- быстрее окна подсети. */
          buckets: { ip: { max: 100, loss: 2, captchaAt: 60, banAt: 100 } },
          gate: { redirectMethods: ["GET"], denyResponse: "captcha_required", htmlOnly: true },
          rules: [
            {
              on: "bucket_captcha",
              bucket: "ip",
              to: "e2e-rw",
              verb: "mutate",
              axis: "request",
              group: "prices",
              set: "on",
              code: "E2E_CAP_MASK",
            },
            /* Три записи одного события с тремя сроками: строка -- одно действие. */
            { on: "bucket_ban", bucket: "ip", list: "e2e-ban-ip", write: "addr", ttlS: 10, code: "E2E_BAN_ADDR" },
            { on: "bucket_ban", bucket: "ip", list: "e2e-ban-net", write: "net", ttlS: 30, code: "E2E_BAN_NET" },
            { on: "bucket_ban", bucket: "ip", list: "e2e-ban-asn", write: "asn", ttlS: 60, code: "E2E_BAN_ASN" },
          ],
        },
      ],
    },
    target: { host: SERVER, path: "/logic/ban-ladder/api/" },
    probes: [
      {
        name: "корзины пусты: выдача целая, спрошены все",
        path: "/logic/ban-ladder/api/?objects=6",
        ip: "@run.ip",
        expect: { status: 200, verdict: "allow", bodyHas: "canary-", asked: ["e2e-ip", "e2e-act", "e2e-cnt", "e2e-cap"] },
      },
      {
        name: "ниже половины счётчика: всё ещё целая",
        path: "/logic/ban-ladder/api/?objects=6",
        ip: "@run.ip",
        expect: { status: 200, verdict: "allow", bodyHas: "canary-" },
      },
      {
        name: "корзина капчи от 60: выдача замаскирована, отказа нет",
        path: "/logic/ban-ladder/api/?objects=6",
        ip: "@run.ip",
        times: 3,
        expect: { status: 200, verdict: "allow", bodyHas: "***", bodyLacks: "canary-" },
      },
      {
        name: "корзина на 100: бан записан, инспектор адреса отказывает по адресу",
        path: "/logic/ban-ladder/api/?objects=6",
        ip: "@run.ip",
        times: 3,
        settleMs: 20_000,
        expect: { deny: "blocked", verdict: "deny", answers: { "e2e-ip": "deny/E2E_BAN_IP" } },
      },
      { name: "в наборе адресов -- адрес прогона со сроком 10 с", list: "e2e-ban-ip", expect: { has: "@run.ip", ttlMax: 10 } },
      { name: "в наборе анонсов -- подсеть из гео со сроком 30 с", list: "e2e-ban-net", expect: { has: "8.8.8.0/24", ttlMax: 30 } },
      { name: "в наборе системы -- её анонсы со сроком 60 с", list: "e2e-ban-asn", expect: { has: "8.8.8.0/24", ttlMax: 60 } },
      {
        /*
         * Не забанили лишнего: чужая система не задета ни одним ярусом, и её
         * клиент проходит, пока клиент из 8.8.8.0/24 сидит под баном.
         */
        name: "сосед из чужой системы проходит: ни один ярус его не задел",
        path: "/logic/ban-ladder/api/?objects=6",
        ip: "1.1.1.77",
        expect: { status: 200, verdict: "allow", bodyHas: "canary-", asked: ["e2e-ip", "e2e-cap"] },
      },
      {
        name: "через десять секунд адрес протух, держит подсеть: код сменился",
        path: "/logic/ban-ladder/api/?objects=6",
        ip: "@run.ip",
        settleMs: 25_000,
        expect: { deny: "blocked", verdict: "deny", answers: { "e2e-ip": "deny/E2E_BAN_NET" } },
      },
      { name: "запись адреса из набора ушла", list: "e2e-ban-ip", expect: { lacks: "@run.ip" } },
      {
        name: "через тридцать протухла подсеть, держит система: код сменился",
        path: "/logic/ban-ladder/api/?objects=6",
        ip: "@run.ip",
        settleMs: 45_000,
        expect: { deny: "blocked", verdict: "deny", answers: { "e2e-ip": "deny/E2E_BAN_ASN" } },
      },
      { name: "запись анонса из набора ушла", list: "e2e-ban-net", expect: { lacks: "8.8.8.0/24" } },
      {
        name: "через минуту протухла и система: корзины остыли, клиент проходит с целой выдачей",
        path: "/logic/ban-ladder/api/?objects=6",
        ip: "@run.ip",
        settleMs: 75_000,
        expect: { status: 200, verdict: "allow", bodyHas: "canary-", asked: ["e2e-cap"] },
      },
    ],
  },

  {
    id: "shop-funnel-trap",
    title: "Витрина, касса и ловушка: клиента судят по пути через сайт, а не по одному запросу",
    about: [
      "Три маршрута одного магазина и общее состояние между ними. Человек сначала",
      "смотрит витрину и только потом платит; бот либо бьёт в кассу напрямую,",
      "либо выкачивает каталог, либо идёт по ссылке, которой человек не видит.",
      "Улика собирается на одном маршруте, наказание исполняется на другом,",
      "оправдаться можно на третьем.",
      "",
      "Кредит. Каждая HTML-страница витрины кладёт в корзину счётчика единицу,",
      "каждый оформленный заказ снимает две. Корзина -- по адресу, и её ключ не",
      "знает профиля: витрина и касса стоят на разных профилях одного процесса,",
      "а счёт у них общий. Касса судит уровень на запросе: ниже 8% -- сотня очков",
      "и отказ по сумме; ниже 1% (витрину не открывали вовсе) -- ещё и запись",
      "адреса в набор подозреваемых.",
      "",
      "Ловушка. Приложение не трогается: модификатор вставляет в каждую",
      "HTML-страницу витрины перед </body> скрытую ссылку на прайс-лист. Человек",
      "её не видит, обходчик идёт по ней -- и инспектор действий на маршруте",
      "ловушки молча пишет адрес в тот же набор. Ответ -- обычный 404 приложения.",
      "Третий повод попасть туда же -- выкачка: больше 60 карточек на адрес.",
      "",
      "Подозреваемый. Капча стоит на витрине и на кассе, но зовётся условием",
      "вызова по набору -- остальной трафик за неё не платит вовсе. На витрине",
      "подозреваемый получает виджет, на кассе -- отказ телом, и кредит ему не",
      "заработать: отказанный ответ корзину не греет. Прошёл виджет -- капча на",
      "кассе просит счётчик не судить (`skip`), и касса пропускает проверенного",
      "даже без кредита. Капча стоит волной раньше счётчика: просьба доезжает",
      "только тем, кого спросят позже.",
      "",
      "Эскалация. Заказ на несуществующий товар -- 400 от приложения и единица в",
      "корзину провалов. Пятый провал пишет в набор бана весь анонс адреса",
      "(`write: net`), и узел режет подсеть локальной проверкой до всех волн --",
      "соседа по сети тоже, покупателя из другой сети нет.",
      "",
      "Попутно тот же модификатор маскирует номер карты в ответе кассы: другая",
      "группа того же профиля, другое условие -- JSON с кодом 201.",
    ].join("\n"),
    /*
     * Клиентов шесть, у каждого свой адрес. Осторожный кардер и его сосед --
     * в 1.1.1.0/24: запись `net` берёт анонс у кодера гео, а эту сеть кодер
     * стенда знает. Остальные -- в 198.18/15, и бан подсети их не задевает.
     */
    actors: {
      buyer: {},
      crawler: {},
      scraper: {},
      direct: {},
      carder: { within: "1.1.1.0/24" },
      neighbor: { within: "1.1.1.0/24" },
    },
    needs: {
      datasets: [
        /*
         * Оба набора живые и объявлены краю (`in_nginx`): по первому узел
         * зовёт капчу условием вызова, по второму режет локальной проверкой.
         * Вечных записей у живого набора нет: срок у набора и у каждой записи.
         *
         * Лимит записей явный: край держит набор в общей зоне waf по 128 байт на
         * запись, и умолчательный миллион на набор в поставочную зону (8 МБ) не
         * влезает -- nginx -t на крае отвергает поколение целиком.
         */
        {
          name: "e2e-sft-suspects",
          description: "Подозреваемые: ловушка, выкачка, касса в обход витрины",
          limit: 10000,
          type: "ip",
          active: true,
          in_nginx: true,
          ttl: "10m",
        },
        {
          name: "e2e-sft-banned",
          description: "Бан подсети за перебор заказов",
          limit: 10000,
          type: "ip",
          active: true,
          in_nginx: true,
          ttl: "10m",
        },
      ],
      actionProfiles: [
        {
          name: "e2e-sft-trap",
          description: "Ловушка: кто пришёл по скрытой ссылке -- в подозреваемые",
          rules: [
            {
              /* Без условий: сюда не приходят люди, пришедший -- уже улика. */
              name: "trap",
              actions: [
                { list: "e2e-sft-suspects", write: "addr", ttlS: 300, code: "E2E_SFT_HONEYPOT" },
                { verb: "mark", axis: "request", marker: "honeypot", code: "E2E_SFT_HONEYPOT" },
              ],
            },
          ],
        },
      ],
      counterShared: {
        /* Кредит: страница витрины -- единица, заказ -- минус две. Утечка мала: единица живёт минуты. */
        "e2e-sft-browse": { unit: "page", axes: { ip: { max: 20, loss: 0.03 } } },
        /* Выкачка: карточки каталога на адрес. */
        "e2e-sft-harvest": { unit: "obj", axes: { ip: { max: 100, loss: 0.1 } } },
        /* Провалы оформления: ответ 400 кассы. */
        "e2e-sft-fails": { unit: "fail", axes: { ip: { max: 5, loss: 0.1 } } },
      },
      counterProfiles: [
        {
          name: "e2e-sft-front",
          description: "Витрина: копит кредит и считает выкачку",
          request: {
            judge: [],
            outcomes: [
              {
                on: "level",
                if: { counter: "e2e-sft-harvest", axis: "ip" },
                at: 60,
                list: "e2e-sft-suspects",
                write: "addr",
                ttlS: 300,
                code: "E2E_SFT_HARVEST",
              },
              {
                on: "level",
                if: { counter: "e2e-sft-harvest", axis: "ip" },
                at: 60,
                verb: "mark",
                axis: "request",
                marker: "harvester",
                code: "E2E_SFT_HARVEST",
              },
            ],
          },
          response: {
            measure: [
              /* Страница витрины, отданная в браузер, -- единица кредита. */
              {
                if: { status: [200], contentType: ["text/html"], methods: ["GET"] },
                source: "const",
                counter: "e2e-sft-browse",
                axes: ["ip"],
              },
              /* Карточка каталога -- одно вхождение obj=<id>. */
              { if: { status: [200] }, source: "regex_count", regex: "obj=\\d+", counter: "e2e-sft-harvest", axes: ["ip"] },
            ],
          },
        },
        {
          name: "e2e-sft-till",
          description: "Касса: тратит кредит, судит обход витрины, считает провалы",
          /* Проверенного человека касса не судит: skip от капчи, поимённо и по одному поводу. */
          prior: [{ from: "e2e-sft-cap", accept: ["skip"], apply: [], codes: ["E2E_SFT_HUMAN"], counter: "" }],
          request: {
            judge: [],
            outcomes: [
              /*
               * Кредита нет: сотня очков при пороге маршрута в сотню -- отказ
               * по сумме, а не вердиктом счётчика. Опоздавший покупатель
               * получает отказ, но не клеймо: для клейма есть порог ниже.
               */
              {
                on: "level",
                if: { counter: "e2e-sft-browse", axis: "ip" },
                at: 8,
                below: true,
                verb: "score",
                axis: "request",
                value: 100,
                code: "E2E_SFT_NO_BROWSE",
              },
              /* Витрину не открывали вовсе -- это не опоздание, а обход: в подозреваемые. */
              {
                on: "level",
                if: { counter: "e2e-sft-browse", axis: "ip" },
                at: 1,
                below: true,
                list: "e2e-sft-suspects",
                write: "addr",
                ttlS: 300,
                code: "E2E_SFT_FUNNEL_SKIP",
              },
              {
                on: "level",
                if: { counter: "e2e-sft-browse", axis: "ip" },
                at: 1,
                below: true,
                verb: "mark",
                axis: "request",
                marker: "funnel-skip",
                code: "E2E_SFT_FUNNEL_SKIP",
              },
              /* Перебор заказов: провалы за порогом -- в бан весь анонс адреса. */
              {
                on: "level",
                if: { counter: "e2e-sft-fails", axis: "ip" },
                at: 70,
                list: "e2e-sft-banned",
                write: "net",
                ttlS: 120,
                code: "E2E_SFT_CARDING",
              },
            ],
          },
          response: {
            measure: [
              /* Оформленный заказ тратит две страницы кредита. */
              { if: { status: [201] }, source: "const", per: -2, counter: "e2e-sft-browse", axes: ["ip"] },
              /* Отказ приложения в заказе -- провал. */
              { if: { status: [400] }, source: "const", counter: "e2e-sft-fails", axes: ["ip"] },
            ],
          },
        },
      ],
      rewriteProfiles: [
        {
          name: "e2e-sft-rw",
          description: "Приманка на витрине, маска карты на кассе",
          groups: [
            {
              /*
               * Приложение не трогается: ссылка вставляется в тело ответа
               * перед </body>, который есть у любой страницы. Людям она не
               * видна (hidden), чтению экрана тоже (aria-hidden), с клавиатуры
               * до неё не дойти (tabindex), вежливым роботам -- nofollow.
               */
              name: "bait",
              default: true,
              on: "response",
              status: [200],
              contentType: ["text/html"],
              body: [
                {
                  op: "insert_before",
                  pattern: "</body>",
                  text: '<a href="/price-list/all.csv" hidden aria-hidden="true" tabindex="-1" rel="nofollow">price list</a>',
                  maxMatches: 1,
                },
              ],
            },
            {
              /* Номер карты в ответе кассы: только JSON и только оформленный заказ. */
              name: "pci",
              default: true,
              on: "response",
              status: [201],
              contentType: ["application/json", "+json"],
              body: [{ op: "replace", pattern: "\\b(\\d{4})[ -]?\\d{4}[ -]?\\d{4}[ -]?(\\d{4})\\b", to: "$1 **** **** $2" }],
            },
          ],
        },
      ],
      upstreams: [
        APP,
        /* Виджет обслуживает свой процесс, не приложение: у капчи два контейнера. */
        { name: "e2e-cap-http", peers: [{ host: "captcha-http", port: 8080 }] },
      ],
      declarations: {
        "e2e-sft-trap": { process: "action", profileFrom: "e2e-sft-trap" },
        /* Два имени одного процесса: у витрины и кассы разные правила, а корзины общие. */
        "e2e-sft-front": { process: "counter", profileFrom: "e2e-sft-front" },
        "e2e-sft-till": { process: "counter", profileFrom: "e2e-sft-till" },
        "e2e-sft-rw": { process: "rewrite", profileFrom: "e2e-sft-rw" },
        /* Профиль капчи заводится позже маршрутов -- объявление зовёт его по имени. */
        "e2e-sft-cap": { process: "captcha", profile: "e2e-sft-cap" },
      },
      servers: [
        {
          ...SERVER_SPEC,
          waf: {
            ...SERVER_SPEC.waf,
            /* Без этого модуль не выпустит редирект капчи: цель обязана быть названа. */
            redirectAllow: ["/waf/captcha"],
            /* Бан подсети -- на сервере: режет все маршруты до волн, ни одного сообщения на шину. */
            localChecks: [{ dataset: "e2e-sft-banned", variable: "$binary_remote_addr", action: "block", response: "blocked" }],
          },
        },
      ],
      routes: [
        {
          /* Витрина: каталог, карточка товара, форма заказа -- одним маршрутом. */
          server: SERVER,
          match: "regex",
          path: "^/(catalog|item/|order/)",
          position: 100,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            requestInspectors: [
              { name: "e2e-sft-front", wave: 0 },
              { name: "e2e-sft-cap", wave: 1, conds: SFT_SUSPECT },
            ],
            responseInspectors: [
              { name: "e2e-sft-rw", wave: 0, timeoutMs: 2500 },
              { name: "e2e-sft-front", wave: 1 },
            ],
          },
        },
        {
          /*
           * Касса. Капча раньше счётчика: её `skip` доезжает только тем, кого
           * спросят позже. Порог суммы -- ровно та сотня, что просит счётчик.
           */
          server: SERVER,
          match: "prefix",
          path: "/api/orders",
          position: 100,
          upstream: APP.name,
          waf: {
            ...BEHAVIOUR_WAF,
            scoreDeny: { response: "blocked", threshold: 100 },
            requestInspectors: [
              { name: "e2e-sft-cap", wave: 0, conds: SFT_SUSPECT },
              { name: "e2e-sft-till", wave: 1 },
            ],
            responseInspectors: [
              { name: "e2e-sft-rw", wave: 0, timeoutMs: 2500 },
              { name: "e2e-sft-till", wave: 1 },
            ],
          },
        },
        {
          /* Ловушка: ссылка на неё есть только в скрытом теге. */
          server: SERVER,
          match: "prefix",
          path: "/price-list/",
          position: 100,
          upstream: APP.name,
          waf: { ...ROUTE_WAF, requestInspectors: [{ name: "e2e-sft-trap", wave: 0 }] },
        },
        {
          /* Страница виджета: инспекторов нет, и снимок с превью и архивом сняты с ними. */
          server: SERVER,
          match: "prefix",
          path: "/waf/captcha",
          position: 90,
          upstream: "e2e-cap-http",
          waf: {
            requestInspectors: "none",
            responseInspectors: "none",
            capture: ["request none"],
            preview: ["request none"],
            archive: ["request none"],
          },
        },
      ],
      captchaProfiles: [
        {
          name: "e2e-sft-cap",
          server: SERVER,
          path: "/waf/captcha",
          /* Кого спрашивать, решает условие вызова; позванная, капча требует проверку всегда. */
          when: "always",
          gate: { redirectMethods: ["GET"], denyResponse: "captcha_required", htmlOnly: true },
          rules: [
            /* Предъявил клиренс -- кассе не судить: человек уже проверен. */
            { on: "cleared", to: "e2e-sft-till", verb: "skip", axis: "request", code: "E2E_SFT_HUMAN" },
          ],
        },
      ],
    },
    target: { host: SERVER, path: "/catalog" },
    probes: [
      /* --- покупатель: кредит зарабатывается на витрине, тратится на кассе --- */
      {
        name: "покупатель открыл каталог: в теле ссылка-приманка, капчу не звали",
        path: "/catalog?per=12",
        ip: "@ip.buyer",
        headers: { Accept: "text/html" },
        expect: { status: 200, bodyHas: 'href="/price-list/all.csv"', asked: "e2e-sft-front", notAsked: "e2e-sft-cap" },
      },
      {
        name: "... карточку товара",
        path: "/item/7",
        ip: "@ip.buyer",
        headers: { Accept: "text/html" },
        expect: { status: 200, bodyHas: 'href="/price-list/all.csv"' },
      },
      {
        name: "... и форму заказа: на счету три страницы",
        path: "/order/7",
        ip: "@ip.buyer",
        headers: { Accept: "text/html" },
        expect: { status: 200 },
      },
      {
        name: "заказ: кредит есть -- касса пропускает, номер карты в ответе замаскирован",
        path: "/api/orders",
        method: "POST",
        body: SFT_ORDER,
        ip: "@ip.buyer",
        expect: {
          status: 201,
          verdict: "allow",
          notAsked: "e2e-sft-cap",
          answers: { "e2e-sft-till": "allow" },
          bodyHas: "4111 **** **** 1111",
          bodyLacks: "4111 1111 1111 1111",
        },
      },
      {
        name: "второй заказ подряд: кредит потрачен -- отказ по сумме очков",
        path: "/api/orders",
        method: "POST",
        body: SFT_ORDER,
        ip: "@ip.buyer",
        expect: { deny: "blocked", verdict: "deny", by: "score" },
      },
      { name: "покупатель не в подозреваемых: витрину он открывал", list: "e2e-sft-suspects", expect: { lacks: "@ip.buyer" } },
      {
        name: "покупатель открыл ещё товар: капчи нет, кредит пополнился",
        path: "/item/8",
        ip: "@ip.buyer",
        headers: { Accept: "text/html" },
        expect: { status: 200, notAsked: "e2e-sft-cap" },
      },
      {
        name: "и заказ снова проходит",
        path: "/api/orders",
        method: "POST",
        body: SFT_ORDER,
        ip: "@ip.buyer",
        expect: { status: 201, verdict: "allow" },
      },

      /* --- обходчик: пошёл по ссылке, которой человек не видит --- */
      {
        name: "обходчик открыл каталог: ссылка-приманка в теле",
        path: "/catalog?per=12",
        ip: "@ip.crawler",
        headers: { Accept: "text/html" },
        expect: { status: 200, bodyHas: 'href="/price-list/all.csv"' },
      },
      {
        name: "... и пошёл по ней: ловушка молча записала адрес, ответ -- обычный 404",
        path: "/price-list/all.csv",
        ip: "@ip.crawler",
        expect: { status: 404, answers: { "e2e-sft-trap": "allow" } },
      },
      { name: "обходчик в подозреваемых, срок пять минут", list: "e2e-sft-suspects", expect: { has: "@ip.crawler", ttlMax: 300 } },
      {
        name: "подозреваемый на витрине: капча требует проверку",
        path: "/catalog?per=12",
        ip: "@ip.crawler",
        headers: { Accept: "text/html" },
        expect: { status: 303, answers: { "e2e-sft-cap": "redirect" } },
      },
      {
        name: "подозреваемый на кассе: машинный отказ телом, счётчик не спрошен",
        path: "/api/orders",
        method: "POST",
        body: SFT_ORDER,
        ip: "@ip.crawler",
        expect: { deny: "captcha_required", answers: { "e2e-sft-cap": "deny" }, notAsked: "e2e-sft-till" },
      },
      { solve: "подозреваемый прошёл виджет на витрине", from: "/catalog?per=12", ip: "@ip.crawler" },
      {
        name: "с клиренсом касса пропускает без кредита: капча попросила счётчик не судить",
        path: "/api/orders",
        method: "POST",
        body: SFT_ORDER,
        ip: "@ip.crawler",
        cleared: true,
        expect: { status: 201, answers: { "e2e-sft-cap": "allow", "e2e-sft-till": "allow/COUNTER_SKIPPED" } },
      },
      {
        name: "с клиренсом открыта и витрина",
        path: "/catalog?per=12",
        ip: "@ip.crawler",
        headers: { Accept: "text/html" },
        cleared: true,
        expect: { status: 200, answers: { "e2e-sft-cap": "allow" } },
      },

      /* --- парсер: выкачка по 48 карточек --- */
      {
        name: "парсер берёт каталог по 48 карточек: три страницы проходят",
        path: "/catalog?per=48",
        ip: "@ip.scraper",
        headers: { Accept: "text/html" },
        times: 3,
        expect: { status: 200 },
      },
      { name: "на третьей корзина выкачки за 60%: парсер в подозреваемых", list: "e2e-sft-suspects", expect: { has: "@ip.scraper" } },
      {
        name: "следующая страница каталога -- капча",
        path: "/catalog?per=48&page=2",
        ip: "@ip.scraper",
        headers: { Accept: "text/html" },
        expect: { status: 303, answers: { "e2e-sft-cap": "redirect" } },
      },

      /* --- кардер в обход витрины --- */
      {
        name: "кардер бьёт в кассу, минуя витрину: кредита нет -- отказ по сумме",
        path: "/api/orders",
        method: "POST",
        body: SFT_ORDER,
        ip: "@ip.direct",
        expect: { deny: "blocked", verdict: "deny", by: "score" },
      },
      { name: "витрину он не открывал вовсе: в подозреваемых", list: "e2e-sft-suspects", expect: { has: "@ip.direct" } },
      {
        name: "кредит теперь не заработать: витрина требует капчу",
        path: "/catalog?per=12",
        ip: "@ip.direct",
        headers: { Accept: "text/html" },
        expect: { status: 303, answers: { "e2e-sft-cap": "redirect" } },
      },

      /* --- осторожный кардер: витрину смотрит, заказы перебирает --- */
      {
        name: "осторожный кардер открыл каталог",
        path: "/catalog?per=12",
        ip: "@ip.carder",
        headers: { Accept: "text/html" },
        expect: { status: 200 },
      },
      {
        name: "... и карточку: кредит на две страницы",
        path: "/item/9",
        ip: "@ip.carder",
        headers: { Accept: "text/html" },
        expect: { status: 200 },
      },
      {
        name: "перебирает заказы на товар, которого нет: касса пускает, приложение отвечает 400",
        path: "/api/orders",
        method: "POST",
        body: SFT_BAD_ORDER,
        ip: "@ip.carder",
        times: 5,
        expect: { status: 400, notAsked: "e2e-sft-cap" },
      },
      { name: "пятый провал: в бан уехал весь анонс адреса", list: "e2e-sft-banned", expect: { has: "1.1.1.0/24", ttlMax: 120 } },
      {
        name: "кардера узел режет до всех проверок",
        path: "/catalog?per=12",
        ip: "@ip.carder",
        expect: { deny: "blocked", by: "local" },
      },
      {
        name: "соседа по сети -- тоже: бан на подсеть, а не на адрес",
        path: "/catalog?per=12",
        ip: "@ip.neighbor",
        expect: { deny: "blocked", by: "local" },
      },
      {
        name: "покупатель из другой сети не задет",
        path: "/catalog?per=12",
        ip: "@ip.buyer",
        headers: { Accept: "text/html" },
        expect: { status: 200, notAsked: "e2e-sft-cap" },
      },
    ],
  },
];

export function caseById(id) {
  return cases.find((row) => row.id === id) ?? null;
}
