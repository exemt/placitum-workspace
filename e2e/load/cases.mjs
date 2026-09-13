/*
 * Каталог нагрузочных кейсов.
 *
 * Кейс автономен: он описывает ВСЁ, что нужно завести на пустом стенде, и
 * ничего не предполагает существующим. Раннер (`run.mjs`) заводит это через
 * API, гоняет нагрузку и сносит заведённое в обратном порядке. Ручных правок
 * конфигов, записей в базу и отдельно поднятых процессов нет нигде.
 *
 * Файл читают трое, и ни у кого из них нет зависимостей -- поэтому здесь
 * только данные и чистые функции, без импортов:
 *   - tests/load/run.mjs        -- заводит `needs`, гоняет, сносит;
 *   - deploy/loadgen/server.mjs -- отдаёт кейсы панели и судит ступени;
 *   - панель /traffic           -- клик по кейсу выставляет форму.
 *
 * Имена всех заводимых сущностей начинаются с `e2e-`: так снос не заденет
 * чужое, а совпадение имени на живом стенде видно сразу как отказ заведения.
 */

/** Апстрим у всех кейсов один: витрина, площадка /load/** (testapp/README.md). */
const APP = { name: "e2e-app", peers: [{ host: "app", port: 8080 }] };

const SERVER = "e2e-load.waf.test";

/** Превью не может быть шире снимка; маршрут без тела -- свой набор. */
const PREVIEW_NO_BODY = ["headers=16k/2k", "args=8k/1k"];

/** Общая часть документа маршрута: снимаем заголовки, отказы -- страницей error. */
const ROUTE_WAF = {
  capture: ["request headers args"],
  preview: PREVIEW_NO_BODY,
  deadlineMs: 2000,
  /*
   * Все классы исключений -- deny страницей error. Умолчание у `bus` -- pass,
   * и отказ шины прошёл бы в приложение молча, видимый только в debug.
   */
  exception: ["request deny response=error"],
  scoreDeny: { response: "blocked", threshold: 100 },
  responseInspectors: "none",
};

/** Лестница: start × factor^i, count ступеней по duration_s секунд. */
export function ladder(start, factor, count, duration_s) {
  const steps = [];
  let rate = start;

  for (let i = 0; i < count; i += 1) {
    steps.push({ rate: Math.round(rate), duration_s });
    rate *= factor;
  }

  return steps;
}

/** Ровный темп: count одинаковых ступеней по duration_s секунд. */
export function plateau(rate, count, duration_s) {
  const steps = [];

  for (let i = 0; i < count; i += 1) {
    steps.push({ rate, duration_s });
  }

  return steps;
}

/**
 * Файл правил, который прогон правит прямо под нагрузкой.
 *
 * `gen` -- поколение: 0 -- только сторож, N -- сторож плюс N правил волн.
 * Сторож живёт во всех поколениях и обязан отказывать в любой момент прогона:
 * им и проверяется главное утверждение кейса -- пока новый набор собирается,
 * трафик судится старым, а не проваливается в дыру между ними.
 *
 * Счёт наращивается тем же способом, что у самого CRS: +10 в
 * `tx.inbound_anomaly_score_pl1` на фазе 1, а 949059/949060 на фазе 2 обнуляют
 * сводный счёт и пересобирают его по уровням паранойи. Писать
 * `tx.blocking_inbound_anomaly_score` напрямую поэтому бесполезно: фаза 2
 * затрёт написанное.
 *
 * Десять, а не пять: инспектор отдаёт модулю `100 * счёт / порог / 2`, порог
 * CRS у профиля 5, а маршрут отказывает при 100.
 */
export function swapRules(gen) {
  const bump = "pass,nolog,t:none,setvar:'tx.inbound_anomaly_score_pl1=+10'";
  const out = [
    `# Поколение ${gen}. Файл правится прогоном прямо во время нагрузки.`,
    `SecRule REQUEST_HEADERS:X-E2E-Swap "@streq guard" "id:9300001,phase:1,${bump}"`,
  ];

  for (let i = 1; i <= gen; i += 1) {
    out.push(
      `SecRule REQUEST_HEADERS:X-E2E-Swap "@streq gen-${i}" "id:${9300001 + i},phase:1,${bump}"`,
    );
  }

  return `${out.join("\n")}\n`;
}

/** n объявлений одного процесса: hop-01 … hop-NN. */
function hops(n, prefix, decl) {
  const out = {};

  for (let i = 1; i <= n; i += 1) {
    out[`${prefix}-${String(i).padStart(2, "0")}`] = { ...decl };
  }

  return out;
}

/** Те же имена в вызове: волна = порядковый номер, каждый ждёт предыдущего. */
function chain(names) {
  return names.map((name, wave) => ({ name, wave }));
}

/** Заведомо непубличные адреса для списка: TEST-NET-1..3 по /32. */
function testnet(count) {
  const out = ["203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"];

  for (let i = 0; i < count; i += 1) {
    out.push(`198.18.${Math.floor(i / 256) % 256}.${i % 256}/32`);
  }

  return out;
}

/**
 * Корзина нагрузочного кейса: та же ось «человек», но ёмкость неприличная и
 * потери большие -- порог под нагрузкой не берётся. Меряется цена пути, а не
 * срабатывание: у сработавшего отказа цена другая (фазы ответа нет вовсе), и
 * ступени пришлось бы читать как две разные величины.
 */
const LOAD_COUNTER = {
  "e2e-load-objects": {
    unit: "obj",
    axes: { user: { max: 100_000_000, loss: 5 } },
    from: "session:user",
  },
};

/*
 * Профиль правил кейса о горячей замене: куски CRS берутся из каталога
 * пространства (их кладёт сид 012, и копировать их сюда незачем -- это тысячи
 * строк, и предмет проверки не в них), свой у прогона только последний файл,
 * тот самый, который правится под нагрузкой.
 */
const SWAP_FILE = "e2e-swap-rules";
const SWAP_PROFILE = "e2e-swap";
const SWAP_CRS = [
  "engine",
  "setup-pl1",
  "crs-init",
  "crs-934",
  "crs-941",
  "crs-942",
  "crs-943",
  "crs-944",
  "crs-949",
];

const BUS_HOPS = hops(10, "e2e-hop", { process: "action", profile: "default" });
const IP_HOPS = hops(10, "e2e-ipx", { process: "ip", profileFrom: "e2e-load-ip" });
const IPL_HOPS = hops(10, "e2e-ipl", { process: "ip", profileFrom: "e2e-load-ip" });

/* --- кейс ip-ban: списки, эндпоинты, правила ----------------------------- */

/** Списков каждого рода: восемь активных и восемь статических. */
const IPB_N = 8;

const IPB_LIVE = Array.from({ length: IPB_N }, (_, i) => `e2e-ipb-live-${i + 1}`);
const IPB_STATIC = Array.from({ length: IPB_N }, (_, i) => `e2e-ipb-st-${i + 1}`);

/** Сколько записей загружено в каждый список до нагрузки. */
const IPB_LOAD = 20_000;

/**
 * Состав статического списка: `count` подсетей /24 из своего `/8`.
 *
 * Куски взяты из того, что генератор не выдаёт никогда (`reserved()` в
 * wrk/script.lua): статические сидят в 240.0.0.0/4, активные -- в 10.0.0.0/8.
 * Так загруженный состав не ловит ни одного запроса нагрузки, и все
 * шестнадцать проверок честно промахиваются -- меряется промах, а не попадание.
 */
function ipbNets(first, count) {
  const out = [];

  for (let i = 0; i < count; i += 1) {
    out.push(`${first}.${Math.floor(i / 256)}.${i % 256}.0/24`);
  }

  return out;
}

/**
 * Состав активного списка -- адреса /32, как их пишет автобан: номер записи
 * раскладывается по трём младшим октетам 10.0.0.0/8. Загрузку льёт прогон
 * прямо в keeper (tests/lib/ban.mjs): контроллер пишет в активный набор по
 * одной записи с ответом, и восемь списков по двадцать тысяч он наливал бы
 * полчаса.
 */
export function ipbAddrs(list, count) {
  const out = [];

  for (let i = 0; i < count; i += 1) {
    const g = list * count + i;

    out.push(`10.${(g >> 16) & 255}.${(g >> 8) & 255}.${g & 255}`);
  }

  return out;
}

/**
 * Три эндпоинта: свой профиль и объявление, свой охват записи и свой активный
 * список, куда уходит бан. Проверяют все трое одно и то же -- все шестнадцать
 * списков, -- поэтому бан с одного эндпоинта закрывает адрес и на остальных.
 */
const IPB_ENDPOINTS = [
  { id: "addr", write: "addr", path: "/load/ip-ban/addr/", name: "e2e-ipb-addr", list: IPB_LIVE[0] },
  { id: "net", write: "net", path: "/load/ip-ban/net/", name: "e2e-ipb-net", list: IPB_LIVE[3] },
  { id: "asn", write: "asn", path: "/load/ip-ban/asn/", name: "e2e-ipb-asn", list: IPB_LIVE[6] },
];

/**
 * Шестнадцать проверок подряд: четыре белых списка, четыре чёрных, восемь
 * активных. Порядок тот же, что у оператора: белое раньше чёрного, иначе
 * белый список не спасёт от чёрного.
 */
function ipbRules() {
  const out = [];

  for (let i = 1; i <= 4; i += 1) {
    out.push({ action: "allow", set: `e2e-ipb-set-st-${i}` });
  }

  for (let i = 5; i <= IPB_N; i += 1) {
    out.push({ action: "deny", set: `e2e-ipb-set-st-${i}`, response: "blocked", code: `E2E_IPB_BLACK_${i}` });
  }

  for (let i = 1; i <= IPB_N; i += 1) {
    out.push({ action: "deny", set: `e2e-ipb-set-live-${i}`, response: "blocked", code: `E2E_IPB_BAN_${i}` });
  }

  return out;
}

export const cases = [
  {
    id: "bus-chain",
    section: "load",
    title: "Отказ шины: десять лёгких инспекторов подряд",
    about: [
      "Маршрут зовёт десять объявлений инспектора действий по одному на волну: каждый",
      "запрос -- десять последовательных обменов по шине, работы у инспектора почти",
      "нет (профиль default без правил, вердикт allow). Ступени растут, пока модуль",
      "не начнёт докладывать отказы: fail_bus -- кончились слоты ожидания или",
      "публикация не прошла, fail_timeout -- цепочка не уложилась в дедлайн 2 с.",
      "",
      "Что смотреть. Чистая ступень: коды только 200, отказов модуля нет, p99 ниже",
      "секунды. Потолок -- последняя чистая ступень. На отказе маршрут отвечает",
      "страницей error (500) по waf_exception, а не зависает и не пропускает.",
    ].join("\n"),
    needs: {
      upstreams: [APP],
      declarations: BUS_HOPS,
      servers: [
        {
          name: SERVER,
          server_names: [SERVER],
          port: "http-8080",
          nginx: { realIpFrom: ["0.0.0.0/0", "::/0"], realIpHeader: "X-Forwarded-For" },
          waf: { enabled: true, debugHeader: true },
        },
      ],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/load/bus-chain/",
          position: 100,
          upstream: APP.name,
          waf: { ...ROUTE_WAF, requestInspectors: chain(Object.keys(BUS_HOPS)) },
        },
      ],
      publish: ["nginx"],
    },
    traffic: {
      host: SERVER,
      method: "GET",
      path: "/load/bus-chain/",
      headers: [],
      body: "",
      expect: 200,
      flags: { random_ip: "public", unique: true },
      sizes: { body: ["orig"], headers: ["orig"], args: ["orig"] },
      steps: ladder(100, 1.5, 8, 10),
    },
    clean: { unexpected_pct: 1, fails: 0, sockets: 0, p99_ms: 1000 },
  },

  {
    id: "ip-lists",
    section: "load",
    title: "Десять проверок адреса подряд, каждая по своему списку",
    about: [
      "То же построение цепочки, но проверки настоящие: прогон заводит свой набор",
      "адресов, кладёт в него TEST-NET целиком плюс триста /32, собирает из набора",
      "составной набор адресов и профиль, у которого одно терминальное правило --",
      "deny по этому набору, иначе allow. Все десять объявлений смотрят в этот",
      "профиль, то есть каждый запрос десять раз ищется в живом списке.",
      "",
      "Трафик идёт со случайных публичных адресов и обязан проходить: ответ 200.",
      "Появление 403 означает, что генератор выдал адрес из списка -- это не",
      "поломка контура, а повод сузить пул.",
      "",
      "Что смотреть. Ту же чистую ступень, что и у соседнего кейса, плюс то, что",
      "заведение и снос списка целиком укладываются в прогон: стенд до и после",
      "одинаково пуст.",
    ].join("\n"),
    needs: {
      datasets: [
        {
          name: "e2e-load-block",
          description: "Список адресов нагрузочного прогона",
          kind: "list",
          type: "ip",
          active: false,
          addresses: testnet(300),
        },
      ],
      ipSets: [{ name: "e2e-load-set", lists: ["e2e-load-block"] }],
      ipProfiles: [
        {
          name: "e2e-load-ip",
          default: "allow",
          rules: [{ action: "deny", set: "e2e-load-set", response: "blocked", code: "E2E_LOAD_BLOCK" }],
        },
      ],
      upstreams: [APP],
      declarations: IP_HOPS,
      servers: [
        {
          name: SERVER,
          server_names: [SERVER],
          port: "http-8080",
          nginx: { realIpFrom: ["0.0.0.0/0", "::/0"], realIpHeader: "X-Forwarded-For" },
          waf: { enabled: true, debugHeader: true },
        },
      ],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/load/ip-lists/",
          position: 100,
          upstream: APP.name,
          waf: { ...ROUTE_WAF, requestInspectors: chain(Object.keys(IP_HOPS)) },
        },
      ],
      publish: ["ip", "nginx"],
    },
    traffic: {
      host: SERVER,
      method: "GET",
      path: "/load/ip-lists/",
      headers: [],
      body: "",
      expect: 200,
      flags: { random_ip: "public", unique: true },
      sizes: { body: ["orig"], headers: ["orig"], args: ["orig"] },
      steps: ladder(250, 1.5, 6, 10),
    },
    clean: { unexpected_pct: 1, fails: 0, sockets: 0, p99_ms: 1000 },
  },

  {
    id: "ip-loaded",
    section: "load",
    title: "Проверка адреса под нагрузкой: загруженные списки, очки и управление соседом",
    about: [
      "Статика, целиком загруженная заранее. Прогон заводит два своих набора",
      "адресов, собирает из них и из готовых данных пространства составные наборы",
      "-- список плюс страны плюс ASN -- и профиль, в котором четыре строки:",
      "терминальный deny по «плохому» набору, выключение последнего инспектора",
      "цепочки на дешёвом списке и метка события на подозрительном. Ничего в",
      "наборы во время прогона не пишется:",
      "предмет проверки -- цена поиска по загруженным спискам, а не их мутация.",
      "",
      "Адреса не случайные. Пул собран из настоящих префиксов стран и ASN, взятых",
      "у контроллера, и генератор обходит его по порядку, поэтому прогон",
      "повторяем: один и тот же набор адресов в одном и том же порядке.",
      "",
      "До нагрузки прогон проверяет каждое правило поимённо одиночными запросами:",
      "что deny действительно отвечает 403 и по своему списку, и по активному, и",
      "что выключенный просьбой инспектор отмечен в отладочном заголовке как",
      "пропущенный. Только потом меряется темп.",
    ].join("\n"),
    needs: {
      datasets: [
        {
          name: "e2e-ip-bad",
          description: "Заведомо плохие адреса нагрузочного прогона",
          addresses: ["203.0.113.0/24", "198.51.100.0/24"],
        },
        {
          name: "e2e-ip-suspect",
          description: "Подозрительные: дают очки, но не отказ",
          addresses: ["192.0.2.0/25"],
        },
        {
          name: "e2e-ip-cheap",
          description: "Дешёвые: последний инспектор цепочки на них выключается",
          addresses: ["192.0.2.128/25"],
        },
        {
          /* Активный список: живёт темой, а не телом пака. Во время прогона не мутирует. */
          name: "e2e-ip-live",
          description: "Активный список, загруженный до прогона",
          active: true,
          addresses: ["100.64.0.0/16"],
        },
      ],
      ipSets: [
        {
          name: "e2e-ip-deny",
          description: "Плохое: свой список плюс две страны плюс ASN",
          lists: ["e2e-ip-bad", "e2e-ip-live"],
          countries: ["kp", "sy"],
          /* Настоящий ASN из данных пространства; в пул адресов он не входит. */
          asns: [9009],
        },
      ],
      ipProfiles: [
        {
          name: "e2e-load-ip",
          default: "allow",
          /*
           * Списки, которые профиль просит упаковать. Сюда идут ВСЕ, что он
           * трогает: и сырые из накопительных строк, и те, из которых собран
           * составной набор терминальной. Не названный здесь список до
           * инспектора не доедет, и правило по нему молча не сработает.
           */
          datasets: ["e2e-ip-bad", "e2e-ip-live", "e2e-ip-suspect", "e2e-ip-cheap"],
          rules: [
            { action: "deny", set: "e2e-ip-deny", response: "blocked", code: "E2E_IP_DENY" },
            /*
             * Очки на маршруте (`score`) отсюда пока не просятся: контроллер,
             * поднятый на стенде, отвергает такую строку у канала адреса
             * (invalid_rule) при том, что в исходниках запрета нет. Это
             * расхождение непересобранного контроллера, а не замысла кейса --
             * вернуть строку, когда контроллер пересоберут.
             */
            { action: "request", dataset: "e2e-ip-cheap", verb: "off", axis: "request", to: "e2e-ipl-10", code: "E2E_IP_CHEAP" },
            { action: "request", dataset: "e2e-ip-suspect", verb: "mark", axis: "request", marker: "e2e-suspect", code: "E2E_IP_MARK" },
          ],
        },
      ],
      upstreams: [APP],
      declarations: IPL_HOPS,
      servers: [
        {
          name: SERVER,
          server_names: [SERVER],
          port: "http-8080",
          nginx: { realIpFrom: ["0.0.0.0/0", "::/0"], realIpHeader: "X-Forwarded-For" },
          waf: { enabled: true, debugHeader: true },
        },
      ],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/load/ip-loaded/",
          position: 100,
          upstream: APP.name,
          waf: { ...ROUTE_WAF, requestInspectors: chain(Object.keys(IPL_HOPS)) },
        },
      ],
      publish: ["ip", "nginx"],
    },
    /* Настоящие префиксы для повторяемого обхода. Порядок фиксирован. */
    pool: {
      count: 100000,
      from: [
        { country: "de", limit: 200 },
        { country: "fr", limit: 200 },
        { country: "nl", limit: 100 },
        { asn: 3320, limit: 50 },
      ],
    },
    /* Проверки до нагрузки: каждое правило поимённо. */
    probes: [
      { name: "чистый адрес проходит", ip: "8.8.8.8", expect: { status: 200, verdict: "allow" } },
      { name: "свой список отказывает", ip: "203.0.113.7", expect: { deny: "blocked", verdict: "deny" } },
      { name: "активный список отказывает", ip: "100.64.7.7", expect: { deny: "blocked", verdict: "deny" } },
      { name: "подозрительный помечает запись", ip: "192.0.2.10", expect: { status: 200, verdict: "allow" } },
      { name: "чистый адрес спрашивает всех", ip: "1.1.1.1", expect: { status: 200, asked: "e2e-ipl-10" } },
      { name: "дешёвый выключает последнего", ip: "192.0.2.200", expect: { status: 200, notAsked: "e2e-ipl-10" } },
    ],
    traffic: {
      host: SERVER,
      method: "GET",
      path: "/load/ip-loaded/",
      headers: [],
      body: "",
      expect: 200,
      flags: { unique: true },
      sizes: { body: ["orig"], headers: ["orig"], args: ["orig"] },
      steps: ladder(250, 1.5, 6, 10),
    },
    clean: { unexpected_pct: 1, fails: 0, sockets: 0, p99_ms: 1000 },
  },

  {
    id: "counter-user",
    section: "load",
    title: "Счёт на человека: калитка, две фазы счётчика и одна корзина на всю нагрузку",
    about: [
      "Поведенческий конвейер целиком, в самой дорогой его сборке. На каждый",
      "запрос: калитка проверяет подпись токена (RS256) и называет личность,",
      "счётчик фазы запроса читает уровень корзины этой личности, приложение",
      "отдаёт двенадцать объектов, счётчик фазы ответа поднимает тело из",
      "обменника и считает в нём метки. Ответ держится до вердикта фазы ответа",
      "(`waf_hold response gate`), то есть цена обеих фаз попадает в задержку",
      "клиента.",
      "",
      "Главное здесь -- ключ корзины. Адреса у нагрузки случайные, а человек",
      "один, и корзина у него одна: весь темп ступени бьёт в одну точку Redis.",
      "Это не изъян постановки, а свойство счёта по личности -- корзина на",
      "человека и есть общая точка всех его устройств. Ради этого кейс и",
      "написан: осями `ip` и `sess` такой точки не бывает.",
      "",
      "Порог не берётся: ёмкость корзины неприлично велика, потери огромны.",
      "Меряется цена пути, а не срабатывание отказа -- у отказавшего запроса",
      "фазы ответа нет вовсе, и ступень пришлось бы читать как смесь двух",
      "разных величин.",
      "",
      "Что смотреть. Чистая ступень: коды только 200 (значит, калитка приняла",
      "токен и порог не взят), отказов модуля нет, p99 ниже секунды. Потолок --",
      "последняя чистая ступень.",
      "",
      "Из панели этот пресет сам по себе не поедет: в заголовке Authorization",
      "стоит имя, а не токен. Значение подставляет прогон -- пара ключей и токен",
      "живут один запуск, и записать их в файл нельзя.",
    ].join("\n"),
    identity: { logins: ["alice"] },
    needs: {
      counterShared: LOAD_COUNTER,
      counterProfiles: [
        {
          name: "e2e-load-counter",
          description: "Нагрузка: объекты на человека, порог недостижим",
          request: {
            judge: [
              {
                counter: "e2e-load-objects",
                axis: "user",
                at: 90,
                action: "deny",
                code: "E2E_LOAD_CNT",
              },
            ],
            denyResponse: "counter_limit",
          },
          response: {
            measure: [
              {
                if: { status: [200], contentType: ["application/json", "+json"] },
                source: "regex_count",
                regex: "obj=\\d+",
                counter: "e2e-load-objects",
                axes: ["user"],
              },
            ],
          },
        },
      ],
      authSources: [
        {
          name: "e2e-load-jwt",
          provider: "jwt",
          providers: {
            jwt: {
              header: "authorization",
              prefix: "Bearer",
              verify: { alg: "RS256", key: "@jwt.public", leeway_s: 30 },
              claims: { user: "sub", session: "sid" },
            },
          },
        },
      ],
      authProfiles: [{ name: "e2e-load-gate", sourceFrom: "e2e-load-jwt" }],
      upstreams: [APP],
      declarations: {
        "e2e-gate": { process: "auth", profileFrom: "e2e-load-gate" },
        "e2e-cnt": { process: "counter", profileFrom: "e2e-load-counter" },
      },
      servers: [
        {
          name: SERVER,
          server_names: [SERVER],
          port: "http-8080",
          nginx: { realIpFrom: ["0.0.0.0/0", "::/0"], realIpHeader: "X-Forwarded-For" },
          waf: { enabled: true, debugHeader: true },
        },
      ],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/load/counter-user/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...ROUTE_WAF,
            /* Тело ответа снимается целиком: по нему счётчик и считает объекты. */
            capture: ["request headers args", "response headers body"],
            bodyLimit: "response 4m",
            bodyLimitPolicy: "pass",
            responseHold: "gate",
            responseDeadlineMs: 3000,
            exception: ["request deny response=error", "response deny response=error"],
            /* Калитка обязана высказаться раньше счётчика: иначе личности в сообщении нет. */
            requestInspectors: [
              { name: "e2e-gate", wave: 0 },
              { name: "e2e-cnt", wave: 1 },
            ],
            responseInspectors: [{ name: "e2e-cnt", wave: 0 }],
          },
        },
      ],
    },
    probes: [
      {
        name: "гость: калитка отказывает, счётчика не спрашивают",
        expect: { deny: "auth_required", verdict: "deny", notAsked: "e2e-cnt" },
      },
      {
        name: "вошедший проходит, спрошены оба",
        headers: { Authorization: "@bearer.alice" },
        expect: { status: 200, verdict: "allow", asked: ["e2e-gate", "e2e-cnt"] },
      },
    ],
    traffic: {
      host: SERVER,
      method: "GET",
      path: "/load/counter-user/?objects=12",
      /* Значение подставляет прогон: токен живёт один запуск. */
      headers: [{ name: "Authorization", value: "@bearer.alice" }],
      body: "",
      expect: 200,
      flags: { random_ip: "public", unique: true },
      sizes: { body: ["orig"], headers: ["orig"], args: ["orig"] },
      steps: ladder(100, 1.5, 8, 10),
    },
    clean: { unexpected_pct: 1, fails: 0, sockets: 0, p99_ms: 1000 },
  },

  {
    id: "modsec-swap",
    section: "load",
    title: "Горячая замена набора правил под трафиком",
    about: [
      "Единственный кейс, где конфигурация меняется прямо во время нагрузки.",
      "Маршрут зовёт инспектор правил со своим профилем: куски CRS из каталога",
      "плюс один файл прогона. Темп ровный -- ступени одинаковые, лестницы нет:",
      "меряется не потолок, а то, что происходит с трафиком в момент правки.",
      "",
      "В середине каждой ступени, кроме первой, прогон дописывает в свой файл",
      "ещё одно правило и издаёт канал. Инспектор забирает поколение, собирает",
      "набор целиком у себя и подменяет указатель одним присваиванием",
      "(inspectors/modsec/internal/rules). Пока идёт сборка, запросы судит",
      "прежний набор -- и ровно это кейс и проверяет.",
      "",
      "Во время смены прогон щупает край четыре раза в секунду двумя запросами.",
      "Сторож (`X-E2E-Swap: guard`) стоит во всех поколениях и обязан получать",
      "отказ в каждой пробе без единого исключения: одна проскочившая проба --",
      "это и есть дыра между наборами. Свежий (`X-E2E-Swap: gen-N`) до правки",
      "обязан проходить, после применения -- получать отказ; расстояние между",
      "правкой и устойчивым отказом и есть время горячей замены.",
      "",
      "Что смотреть. Чистыми обязаны быть ВСЕ ступени, а не последняя перед",
      "грязной: просадка ищется сравнением с отсчётным прогоном (`--no-swap`),",
      "а не соседней ступени с соседней. У сторожа ноль пропусков, у копий",
      "инспектора -- одинаковый отпечаток поколения к концу каждой смены.",
      "Столбцы пульса отстают на такт heartbeat и временем замены не являются:",
      "их дело -- показать копию, которая поколение не взяла вовсе.",
      "",
      "Из панели поедет только ровный темп: смены заводит раннер, форма про них",
      "не знает. Ради них кейс и написан, поэтому мерить его надо прогоном.",
    ].join("\n"),
    needs: {
      ruleFiles: [
        {
          name: SWAP_FILE,
          description: "Правила прогона: сторож и волны, правится под нагрузкой",
          text: swapRules(0),
        },
      ],
      ruleSets: [
        {
          name: SWAP_PROFILE,
          description: "CRS из каталога плюс правила прогона",
          files: [...SWAP_CRS, SWAP_FILE],
        },
      ],
      upstreams: [APP],
      declarations: { "e2e-crs": { process: "modsec", profileFrom: SWAP_PROFILE } },
      servers: [
        {
          name: SERVER,
          server_names: [SERVER],
          port: "http-8080",
          nginx: { realIpFrom: ["0.0.0.0/0", "::/0"], realIpHeader: "X-Forwarded-For" },
          waf: { enabled: true, debugHeader: true },
        },
      ],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/load/modsec-swap/",
          position: 100,
          upstream: APP.name,
          waf: { ...ROUTE_WAF, requestInspectors: [{ name: "e2e-crs", wave: 0 }] },
        },
      ],
      publish: ["rules", "nginx"],
    },
    /*
     * Правка на ходу: что править, чем щупать и как часто. Всё остальное --
     * когда бить и в какую ступень попадёт удар -- раннер считает по ступеням
     * трафика, поэтому `--steps` не разъезжается с расписанием смен.
     */
    swap: {
      file: SWAP_FILE,
      profile: SWAP_PROFILE,
      /* Имя процесса в пульсе: по нему считаются копии, догнавшие поколение. */
      process: "modsec",
      header: "X-E2E-Swap",
      guard: "guard",
      denyResponse: "blocked",
      /* Со второй ступени: первая -- отсчёт, с которым сравнивают остальные. */
      fromStep: 2,
      sampleMs: 250,
      /* Сколько отказов подряд считать устойчивым применением. */
      stable: 3,
      /* Сколько щупать после применения: замена не должна «моргать» обратно. */
      tailMs: 3000,
      timeoutMs: 60_000,
    },
    probes: [
      {
        name: "обычный запрос проходит, инспектор спрошен",
        expect: { status: 200, verdict: "allow", asked: ["e2e-crs"] },
      },
      {
        name: "сторож отказывает с нулевого поколения",
        headers: { "X-E2E-Swap": "guard" },
        expect: { deny: "blocked", verdict: "deny" },
      },
      {
        name: "правила первой волны ещё нет",
        headers: { "X-E2E-Swap": "gen-1" },
        expect: { status: 200, verdict: "allow" },
      },
    ],
    traffic: {
      host: SERVER,
      method: "GET",
      path: "/load/modsec-swap/",
      headers: [],
      body: "",
      expect: 200,
      flags: { random_ip: "public", unique: true },
      sizes: { body: ["orig"], headers: ["orig"], args: ["orig"] },
      /* Ровно и заведомо ниже потолка стенда: ищется просадка, а не предел. */
      steps: plateau(400, 6, 20),
    },
    clean: { unexpected_pct: 1, fails: 0, sockets: 0, p99_ms: 1000 },
  },

  {
    id: "hot-list",
    section: "load",
    title: "Горячий список на миллион: капча банит случайные адреса, keeper раскидывает записи по зеркалам",
    about: [
      "Не потолок конвейера, а судьба одной записи, умноженной на миллион.",
      "Каждый запрос приходит с нового случайного публичного адреса; инспектор",
      "действий на первой волне наливает корзину капчи доверху одной просьбой",
      "`note`, капча на второй волне срабатывает `bucket_ban` и пишет запись в",
      "горячий список на час. Адреса не повторяются, поэтому темп записей равен",
      "темпу запросов, а список растёт до своего потолка -- миллиона записей.",
      "",
      "Список читают все, кто умеет: keeper держит истину и издаёт дельты, три",
      "копии инспектора адреса зеркалят его в памяти и режут повторный визит,",
      "края зеркалят его в общей памяти (`in_nginx`) и режут локальной проверкой",
      "ещё до инспекторов, две капчи помнят, кого уже записали. Прогон смотрит",
      "за всеми сразу: размер списка у контроллера, счётчики keeper (записи,",
      "отказы, дельты, снапшоты, время склада), размер зеркала у каждой копии",
      "инспектора адреса, память контейнеров и журнал краёв по этому набору.",
      "",
      "Смертью считается: отказ keeper (`rejects`, `store_err`), зеркало, которое",
      "отстало и не догнало после нагрузки, край без места в зоне, контейнер у",
      "предела памяти, отказы модуля в трафике. И «лишнее»: контрольный адрес,",
      "которого в трафике не было, обязан проходить после прогона, а выборка из",
      "списка -- получать отказ, и видно, кто отказал: край или инспектор.",
      "",
      "Режим записи -- `--write addr|net|net_all|asn` (умолчание `addr`: адрес",
      "по /32). Для `net` и дальше кодеру гео нужен полный каталог: `--geo full`",
      "выгружает его из базы контроллера в каталог кодера на время прогона.",
      "Случайные адреса ложатся в настоящие анонсы неравномерно: широкие ловят",
      "большинство адресов, и число разных записей растёт много медленнее числа",
      "запросов. `--no-edge` снимает зеркало с краёв: набор без `in_nginx` и",
      "маршрут без локальной проверки.",
    ].join("\n"),
    needs: {
      datasets: [
        {
          name: "e2e-hot",
          description: "Горячий список: пишет капча, срок час",
          kind: "list",
          type: "ip",
          active: true,
          ttl: "1h",
          /* Зеркало на краях: без объявления в nginx локальная проверка не соберётся. */
          in_nginx: true,
          limit: 1_000_000,
        },
      ],
      ipSets: [{ name: "e2e-hot-set", lists: ["e2e-hot"] }],
      ipProfiles: [
        {
          name: "e2e-hot-prof",
          default: "allow",
          datasets: ["e2e-hot"],
          rules: [{ action: "deny", set: "e2e-hot-set", response: "blocked", code: "E2E_HOT_BAN" }],
        },
      ],
      actionProfiles: [
        {
          name: "e2e-hot-act",
          description: "Наливает корзину капчи доверху одной просьбой: каждый адрес -- бан",
          rules: [
            {
              name: "fill",
              pathPrefix: "/load/hot-list/",
              actions: [{ to: "e2e-cap", verb: "note", axis: "ip", value: 100, counter: "ip", code: "E2E_HOT_FILL" }],
            },
          ],
        },
      ],
      upstreams: [
        APP,
        { name: "e2e-cap-http", peers: [{ host: "captcha-http", port: 8080 }] },
      ],
      declarations: {
        "e2e-ip": { process: "ip", profileFrom: "e2e-hot-prof" },
        "e2e-act": { process: "action", profileFrom: "e2e-hot-act" },
        "e2e-cap": { process: "captcha", profile: "e2e-cap" },
      },
      servers: [
        {
          name: SERVER,
          server_names: [SERVER],
          port: "http-8080",
          nginx: { realIpFrom: ["0.0.0.0/0", "::/0"], realIpHeader: "X-Forwarded-For" },
          waf: { enabled: true, debugHeader: true, redirectAllow: ["/waf/captcha"] },
        },
      ],
      routes: [
        {
          server: SERVER,
          match: "prefix",
          path: "/load/hot-list/",
          position: 100,
          upstream: APP.name,
          waf: {
            ...ROUTE_WAF,
            /* Край сам режет по зеркалу списка -- раньше любого инспектора. */
            localChecks: [
              { action: "block", dataset: "e2e-hot", response: "blocked", variable: "$binary_remote_addr" },
            ],
            /*
             * Инспектор адреса первым: повторный визит забаненного обрывает
             * фазу. Действия раньше капчи -- просьба должна доехать. Капча в
             * vote: под нагрузкой никто не ходит на виджет, ответ 200.
             */
            requestInspectors: [
              { name: "e2e-ip", wave: 0 },
              { name: "e2e-act", wave: 1 },
              { name: "e2e-cap", wave: 2, mode: "vote" },
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
          prior: [{ from: "e2e-act", accept: ["note"], codes: ["E2E_HOT_FILL"] }],
          /*
           * Просьба на сто процентов: порог бана на первом же запросе. Порог
           * виджета нулевой -- не срабатывает: без Accept в запросе гейт
           * считает клиента навигационным, в vote это очки, а очки на
           * маршруте -- отказ вместо 200.
           */
          buckets: { ip: { max: 100, loss: 2, captchaAt: 0, banAt: 100 } },
          gate: { redirectMethods: ["GET"], denyResponse: "captcha_required", htmlOnly: true },
          /* Режим записи подставляет раннер: --write addr|net|net_all|asn. */
          rules: [{ on: "bucket_ban", bucket: "ip", list: "e2e-hot", write: "@hot.write", ttlS: 3600, code: "E2E_HOT_BAN" }],
        },
      ],
    },
    /*
     * Наблюдение за списком: что растёт, кто отстаёт, кто умирает. Планов
     * подряд `rounds`: у генератора один план не длиннее десяти минут, а
     * миллион за них может и не набраться.
     */
    hot: {
      list: "e2e-hot",
      target: 1_000_000,
      /* Планов до цели: при темпе ниже потолка записи миллион набирается за час. */
      rounds: 7,
      sampleMs: 5000,
      /* Из бенчмарочного диапазона: генератор его не выдаёт, в списке ему неоткуда взяться. */
      control: "198.18.7.7",
      /*
       * Затравка: раннер сам заходит с этих адресов до нагрузки, и они
       * ложатся в список первыми. После нагрузки по ним видно, что самые
       * ранние записи дожили до конца на каждом зеркале. Все из учебного
       * каталога гео -- чтобы и `net`, и `asn` их разрешили.
       */
      samples: ["8.8.8.8", "1.1.1.1", "5.8.8.10", "133.1.2.3", "210.173.160.5"],
      /* Сколько ждать, пока зеркала догонят keeper после нагрузки. */
      settleMs: 60_000,
    },
    traffic: {
      host: SERVER,
      method: "GET",
      path: "/load/hot-list/",
      headers: [],
      body: "",
      expect: 200,
      flags: { random_ip: "public", unique: true },
      sizes: { body: ["orig"], headers: ["orig"], args: ["orig"] },
      /*
       * Ровно, десять минут (план генератора длиннее не бывает), и темп
       * подобран под путь записи, а не под путь запроса. Каждый запрос здесь
       * -- одна запись в keeper, синхронная и с ответом; на этом стенде
       * дорога упирается около 400 в секунду, и на 1500 больше половины
       * запросов получали 500 по таймауту капчи (`fail_timeout` на её волне),
       * то есть меряли бы отказ, а не раскидку. Потолок пути записи ищется
       * отдельно: `--steps 800,1200,1600`.
       */
      steps: plateau(380, 5, 120),
    },
    clean: { unexpected_pct: 1, fails: 0, sockets: 0, p99_ms: 1000 },
  },
  {
    id: "ip-ban",
    section: "load",
    title: "Три эндпоинта, шестнадцать списков, бан инспектором адреса на пять секунд",
    about: [
      "Автобан адресом, подсетью и системой -- и цена этого бана. Три эндпоинта,",
      "у каждого свой профиль инспектора адреса; профиль ищет адрес в шестнадцати",
      "списках подряд -- восемь активных (их состав держит keeper) и восемь",
      "статических (состав едет паком): четыре белых и четыре чёрных. Списки у всех",
      "трёх одни и те же, поэтому бан, поставленный на одном эндпоинте, виден и на",
      "двух других.",
      "",
      "Кто не нашёлся ни в одном списке (`on: none`), тот и банится -- строкой по",
      "исходу самого инспектора адреса, а не модулем: у наборов нет `in_nginx`, у",
      "маршрутов -- локальной проверки, и отказ выносит инспектор. Охват записи у",
      "каждого эндпоинта свой: `/addr` пишет адрес, `/net` -- эффективный анонс,",
      "`/asn` -- систему целиком, пачкой всех её префиксов. Срок записи -- пять",
      "секунд: список живёт на обороте, а не копится, и видно установившийся размер.",
      "",
      "Адреса нагрузки случайные и публичные, а загруженный заранее состав лежит в",
      "кусках, которые генератор не выдаёт (10/8 и 240/4): все шестнадцать проверок",
      "честно промахиваются, и цена ступени -- это цена промаха по шестнадцати",
      "спискам плюс запись.",
      "",
      "Что смотреть. Реакцию -- сколько миллисекунд от запроса, поставившего бан, до",
      "первого отказа и до устойчивого отказа на всех копиях инспектора (меряется до",
      "нагрузки и под нагрузкой). Установившийся размер списков, темп записи и",
      "отказы keeper. Память keeper, внутреннего Redis, кодера и копий инспектора --",
      "до заведения, после загрузки списков и на пике.",
      "",
      "Отказ в трафике здесь не поломка, а предмет: `net` и `asn` закрывают не один",
      "адрес, а целый анонс и целую систему, и доля 403 показывает, как быстро бан",
      "накрывает случайный поток. Поэтому порог «не тот код» у кейса снят.",
    ].join("\n"),
    needs: {
      datasets: [
        ...IPB_LIVE.map((name, i) => ({
          name,
          description: `Активный список банов ${i + 1}: пишет инспектор адреса, срок 5 с`,
          kind: "list",
          type: "ip",
          active: true,
          /* Умолчание набора -- час: с ним ложится загрузка, у бана срок свой. */
          ttl: "1h",
          /* Состав льёт прогон прямо в keeper -- см. ipbAddrs. */
        })),
        ...IPB_STATIC.map((name, i) => ({
          name,
          description: `Статический ${i < 4 ? "белый" : "чёрный"} список ${i + 1}`,
          kind: "list",
          type: "ip",
          active: false,
          addresses: ipbNets(240 + i, IPB_LOAD),
        })),
      ],
      ipSets: [
        ...IPB_LIVE.map((name, i) => ({ name: `e2e-ipb-set-live-${i + 1}`, lists: [name] })),
        ...IPB_STATIC.map((name, i) => ({ name: `e2e-ipb-set-st-${i + 1}`, lists: [name] })),
      ],
      ipProfiles: IPB_ENDPOINTS.map((ep) => ({
        name: ep.name,
        description: `Шестнадцать списков, запись ${ep.write} на пять секунд`,
        default: "allow",
        rules: ipbRules(),
        /*
         * Строка по исходу: адрес, не найденный ни в одном из шестнадцати
         * списков, уходит в свой активный набор. Это и есть бан -- его ставит
         * инспектор адреса сам, никого не прося.
         */
        outcomes: [{ on: "none", list: ep.list, ttl: 5, write: ep.write, code: `E2E_IPB_${ep.id.toUpperCase()}` }],
      })),
      upstreams: [APP],
      declarations: Object.fromEntries(
        IPB_ENDPOINTS.map((ep) => [ep.name, { process: "ip", profileFrom: ep.name }]),
      ),
      servers: [
        {
          name: SERVER,
          server_names: [SERVER],
          port: "http-8080",
          nginx: { realIpFrom: ["0.0.0.0/0", "::/0"], realIpHeader: "X-Forwarded-For" },
          waf: { enabled: true, debugHeader: true },
        },
      ],
      routes: IPB_ENDPOINTS.map((ep, i) => ({
        server: SERVER,
        match: "prefix",
        path: ep.path,
        position: 100 + i,
        upstream: APP.name,
        /* Ни локальной проверки, ни зеркала на краях: отказ выносит инспектор. */
        waf: { ...ROUTE_WAF, requestInspectors: [{ name: ep.name, wave: 0 }] },
      })),
      publish: ["ip", "nginx"],
    },
    /*
     * Наблюдение и пробы реакции. Полный каталог у кодера обязателен: без него
     * случайный адрес кодеру неизвестен, `net` и `asn` записи не делают вовсе
     * (пропуск с предупреждением), и два эндпоинта из трёх меряли бы пустоту.
     */
    ban: {
      geo: "full",
      endpoints: IPB_ENDPOINTS,
      live: IPB_LIVE,
      static: IPB_STATIC,
      loaded: IPB_LOAD,
      /* Проб на эндпоинт в каждой фазе: до нагрузки и на второй ступени. */
      rounds: 5,
      /* Подряд отказов, после которых бан считается устойчивым на всех копиях. */
      stable: 15,
      /* Сколько ждать отказа в одной пробе. */
      timeoutMs: 8000,
      /* Между пробами: записи живут 5 с, следующий раунд начинается с чистого. */
      gapMs: 7000,
      sampleMs: 5000,
      settleMs: 30_000,
      /*
       * Адреса проб -- бенчмарочные 198.18/15 и 198.19/16: генератор их не
       * выдаёт, в загруженном составе их нет, и чужой бан попасть туда не
       * может. Адресу `net` и `asn` нужен анонс, поэтому прогон дописывает
       * кодеру свои системы под эти же адреса (`probeGeo` в tests/lib/ban.mjs):
       * у `net` -- один /24, у `asn` -- система из одного анонса, кроме первого
       * адреса: 198.19.0.7 сидит в системе из 250 анонсов, и его бан уезжает
       * пачкой в 250 записей.
       */
      probes: {
        addr: ["198.18.11.1", "198.18.11.2", "198.18.11.3", "198.18.11.4", "198.18.11.5"],
        net: ["198.18.20.7", "198.18.21.7", "198.18.22.7", "198.18.23.7", "198.18.24.7"],
        asn: ["198.19.0.7", "198.18.30.7", "198.18.31.7", "198.18.32.7", "198.18.33.7"],
      },
    },
    traffic: {
      host: SERVER,
      method: "GET",
      /* Путь -- первый эндпоинт, `paths` -- все три по очереди, поровну. */
      path: IPB_ENDPOINTS[0].path,
      paths: IPB_ENDPOINTS.map((ep) => ep.path),
      headers: [],
      body: "",
      expect: 200,
      flags: { random_ip: "public", unique: true },
      sizes: { body: ["orig"], headers: ["orig"], args: ["orig"] },
      /* Разогрев и рабочая ступень: тысяча в секунду на три эндпоинта. */
      steps: [{ rate: 300, duration_s: 30 }, { rate: 1000, duration_s: 120 }],
    },
    /*
     * Отказ -- предмет кейса, а не грязь: `net` и `asn` банят анонс и систему
     * целиком, и доля 403 растёт сама. Судим по отказам модуля, сокетам и p99.
     */
    clean: { unexpected_pct: 100, fails: 1, sockets: 0, p99_ms: 2000 },
  },
];

export function caseById(id) {
  return cases.find((row) => row.id === id) ?? null;
}
