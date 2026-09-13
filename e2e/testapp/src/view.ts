/*
 * Разметка. Страницы собираются строками и отдаются сервером целиком: ни SPA,
 * ни сборки здесь нет намеренно. Модификатор правит ТЕЛО ОТВЕТА, и за бандлом
 * ему было бы нечего искать -- всё содержимое приехало бы потом, отдельными
 * запросами XHR, мимо той же страницы.
 *
 * Опорные точки для модификатора расставлены парами «цель и контроль»:
 *
 *   <!-- waf:ads -->…<!-- /waf:ads -->     цель `remove`
 *   <!-- waf:keep -->…<!-- /waf:keep -->   контроль: обязан пережить правку
 *   <!-- waf:anchor:head -->               якорь `insert_before` / `insert_after`
 *   <!-- waf:anchor:body -->               второй якорь, ниже по документу
 *   canary-<hex>                           цель `replace` -> `masked-$1`
 *   заголовок X-App-Secret                 цель `unset` (ставится в main.ts)
 *
 * Если контрольный блок пропал вместе с рекламным -- группа бьёт шире, чем
 * написано, и это ошибка правила, а не приложения.
 */

import { canaryOf, PER_ALLOWED } from "./data.ts";
import type { Item, Page } from "./data.ts";

export function esc(value: unknown): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export interface Viewer {
  /** логин, подставленный калиткой в X-WAF-User; пусто -- гость */
  user: string;
  /** группы из X-WAF-Groups */
  groups: string[];
  /** логин сессии приложения (кука sid), если она есть */
  appLogin: string;
}

const NAV: [string, string][] = [
  ["/", "Витрина"],
  ["/catalog", "Каталог"],
  ["/socket", "Сокет"],
  ["/account", "Личное"],
  ["/admin", "Админка"],
  ["/profile", "Профиль"],
  ["/leak", "Утечка"],
  ["/whoami", "Кто я"],
];

export function layout(title: string, viewer: Viewer, path: string, content: string): string {
  const nav = NAV.map(
    ([href, label]) =>
      `<a href="${href}"${href === path ? ' class="here"' : ""}>${esc(label)}</a>`,
  ).join("");

  const who =
    viewer.user === ""
      ? viewer.appLogin === ""
        ? "гость"
        : `${esc(viewer.appLogin)} (сессия приложения)`
      : `${esc(viewer.user)}${viewer.groups.length > 0 ? ` [${esc(viewer.groups.join(", "))}]` : ""}`;

  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — Витрина</title>
<link rel="stylesheet" href="/static/style.css">
<!-- waf:anchor:head -->
</head>
<body>
<header>
  <strong>Витрина</strong>
  <nav>${nav}</nav>
  <span class="who">${who}</span>
</header>

<!-- waf:ads -->
<aside class="ad" id="ad-slot">
  <b>РЕКЛАМА.</b> Баннер, который модификатор должен вырезать целиком.
  Метка баннера: ${canaryOf(`ads:${path}`)}
</aside>
<!-- /waf:ads -->

<!-- waf:keep -->
<aside class="keep" id="keep-slot">
  Контрольный блок. Обязан пережить правку: если исчез вместе с рекламным —
  правило бьёт шире, чем написано.
</aside>
<!-- /waf:keep -->

<main>
${content}
</main>

<footer>
  <span>Метка страницы: ${canaryOf(`page:${path}`)}</span>
  <span>Приложение честное: полезная нагрузка отражается в ответ, но не исполняется.</span>
</footer>
<script src="/static/app.js"></script>
<!-- waf:anchor:body -->
</body>
</html>
`;
}

/* --- страницы ----------------------------------------------------------- */

export function home(viewer: Viewer, sample: Item[]): string {
  return layout(
    "Главная",
    viewer,
    "/",
    `<h1>Витрина</h1>
<p>Защищаемое приложение стенда. Оно ничего не знает про контур: принимает запрос,
отдаёт ответ и показывает заголовки, которые ему подставили.</p>

<h2>Свежее</h2>
${cards(sample)}
<p><a href="/catalog">Весь каталог →</a></p>`,
  );
}

export function cards(items: Item[]): string {
  if (items.length === 0) {
    return `<p class="empty">Ничего не нашлось.</p>`;
  }

  /*
   * data-obj -- ровно одно вхождение `obj=<id>` на карточку. По нему счётчик
   * меряет выдачу: `source: regex_count, regex: obj=\d+`. Второе вхождение в
   * той же карточке сломало бы счёт вдвое, поэтому метка тут одна.
   */
  return `<ul class="cards">
${items
  .map(
    (item) => `  <li class="card" data-obj="${item.obj}">
    <a href="/item/${item.id}"><h3>${esc(item.title)}</h3></a>
    <p class="tag">${esc(item.tag)}</p>
    <p class="price">${item.priceRub} ₽</p>
    <p class="blurb">${esc(item.blurb)}</p>
    <p class="canary">${item.canary}</p>
  </li>`,
  )
  .join("\n")}
</ul>`;
}

export function catalog(viewer: Viewer, page: Page, q: string, tag: string): string {
  const link = (n: number): string => {
    const params = new URLSearchParams({ page: String(n), per: String(page.per) });

    if (q !== "") {
      params.set("q", q);
    }

    if (tag !== "") {
      params.set("tag", tag);
    }

    return `/catalog?${params.toString()}`;
  };

  const numbers = Array.from({ length: page.pages }, (_, i) => i + 1)
    .filter((n) => n === 1 || n === page.pages || Math.abs(n - page.page) <= 2)
    .map((n) =>
      n === page.page
        ? `<span class="page here">${n}</span>`
        : `<a class="page" href="${link(n)}">${n}</a>`,
    )
    .join(" ");

  const sizes = PER_ALLOWED.map((size) => {
    const params = new URLSearchParams({ page: "1", per: String(size) });

    if (q !== "") {
      params.set("q", q);
    }

    return size === page.per
      ? `<span class="per here">${size}</span>`
      : `<a class="per" href="/catalog?${params.toString()}">${size}</a>`;
  }).join(" ");

  /* Запрос отражается экранированным: видно, что он дошёл, и он не исполняется. */
  const echo =
    q === ""
      ? ""
      : `<p class="query">Искали: <code>${esc(q)}</code> — отражено как текст, не исполнено.</p>`;

  return layout(
    "Каталог",
    viewer,
    "/catalog",
    `<h1>Каталог</h1>
<form class="search" method="get" action="/catalog">
  <input type="text" name="q" value="${esc(q)}" placeholder="поиск по названию">
  <input type="hidden" name="per" value="${page.per}">
  <button type="submit">Искать</button>
</form>
${echo}
<p class="counts">Найдено ${page.total}, страница ${page.page} из ${page.pages}. На странице: ${sizes}</p>
${cards(page.items)}
<nav class="pager">
  ${page.page > 1 ? `<a href="${link(page.page - 1)}">← назад</a>` : `<span class="off">← назад</span>`}
  ${numbers}
  ${page.page < page.pages ? `<a href="${link(page.page + 1)}">вперёд →</a>` : `<span class="off">вперёд →</span>`}
</nav>`,
  );
}

export function item(viewer: Viewer, one: Item): string {
  return layout(
    one.title,
    viewer,
    "/item",
    `<h1>${esc(one.title)}</h1>
<p class="tag">${esc(one.tag)}</p>
<p class="price">${one.priceRub} ₽</p>
<p class="blurb">${esc(one.blurb)}</p>
<p class="canary">Метка позиции: ${one.canary}</p>
<p class="obj" data-obj="${one.obj}">Объект: ${one.obj}</p>
<form method="post" action="/order" class="order">
  <input type="hidden" name="itemId" value="${one.id}">
  <label>Количество <input type="number" name="qty" value="1" min="1" max="10"></label>
  <label>Карта <input type="text" name="card" value="4111111111111111"></label>
  <button type="submit">Заказать</button>
</form>
<p><a href="/order/${one.id}">Чек по этой позиции →</a></p>`,
  );
}

export function order(viewer: Viewer, one: Item, qty: number): string {
  /*
   * Чек -- витрина для маскирования: номер карты, служебный токен и метка.
   * Всё это модификатор обязан заменить в ответе, а контрольный блок в шапке
   * -- оставить.
   */
  return layout(
    "Чек",
    viewer,
    "/order",
    `<h1>Чек</h1>
<table class="receipt">
  <tr><th>Позиция</th><td>${esc(one.title)}</td></tr>
  <tr><th>Количество</th><td>${qty}</td></tr>
  <tr><th>Итого</th><td>${one.priceRub * qty} ₽</td></tr>
  <tr><th>Карта</th><td class="pan">4111 1111 1111 1111</td></tr>
  <tr><th>Служебный токен</th><td>debug-token=${canaryOf(`order:${one.id}`).slice(7)}</td></tr>
  <tr><th>Метка</th><td>${one.canary}</td></tr>
</table>
<p>Ничего не списано: заказов приложение не хранит.</p>`,
  );
}

export function leak(viewer: Viewer): string {
  return layout(
    "Утечка",
    viewer,
    "/leak",
    `<h1>Ответ, который нельзя отдавать как есть</h1>
<p>Страница существует, чтобы модификатору было что вычищать. Всё ниже — выдумка.</p>
<ul class="leak">
  <li>Карта: <span class="pan">4111 1111 1111 1111</span></li>
  <li>Вторая карта: <span class="pan">5555 5555 5555 4444</span></li>
  <li>Служебный токен: debug-token=${canaryOf("leak:token").slice(7)}</li>
  <li>Секрет: secret-42</li>
  <li>Внутренний путь: /var/lib/waf/store/pages</li>
  <li>Метка: ${canaryOf("leak:page")}</li>
</ul>`,
  );
}

export function socketPage(viewer: Viewer): string {
  return layout(
    "Сокет",
    viewer,
    "/socket",
    `<h1>Сокет</h1>
<p>Две стороны разом: <code>/socket/chat</code> отвечает на присланное,
<code>/socket/feed</code> шлёт сам, без действий клиента — это поток s2c.</p>

<section class="ws">
  <h2>Чат — c2s и s2c</h2>
  <form id="chat-form">
    <input id="chat-text" value='{"type":"say","text":"привет"}' size="46">
    <button type="submit">Отправить</button>
  </form>
  <p>
    <button type="button" id="chat-binary">Бинарный кадр</button>
    <button type="button" id="chat-big">Крупный кадр (64 КБ)</button>
    <button type="button" id="chat-split">Два кадра подряд</button>
  </p>
  <pre id="chat-log"></pre>
</section>

<section class="ws">
  <h2>Поток — только s2c</h2>
  <pre id="feed-log"></pre>
</section>`,
  );
}

export function gated(viewer: Viewer, path: string, title: string, note: string): string {
  const rows =
    viewer.user === ""
      ? `<tr><td colspan="2">Калитка ничего не подставила: либо запрос идёт мимо контура, либо инспектор на маршруте не стоит.</td></tr>`
      : `<tr><th>X-WAF-User</th><td>${esc(viewer.user)}</td></tr>
  <tr><th>X-WAF-Groups</th><td>${viewer.groups.length > 0 ? esc(viewer.groups.join(", ")) : "—"}</td></tr>`;

  return layout(
    title,
    viewer,
    path,
    `<h1>${esc(title)}</h1>
<p>${esc(note)}</p>
<table class="kv">
${rows}
</table>
<p class="canary">Метка раздела: ${canaryOf(`gated:${path}`)}</p>`,
  );
}

export function profile(viewer: Viewer, sid: boolean): string {
  return layout(
    "Профиль",
    viewer,
    "/profile",
    sid
      ? `<h1>Профиль</h1>
<p>Вход держит само приложение: кука <code>sid</code>, выданная <code>POST /api/login</code>.
Калитка эту сессию только подсматривает на фазе ответа.</p>
<table class="kv"><tr><th>Логин</th><td>${esc(viewer.appLogin)}</td></tr></table>
<form method="post" action="/api/logout"><button type="submit">Выйти</button></form>`
      : `<h1>Профиль</h1>
<p>Сессии приложения нет. Вход — <code>POST /api/login</code> с полями
<code>username</code> и <code>password</code>.</p>
<form method="post" action="/api/login" class="login">
  <label>Логин <input name="username" value="alice"></label>
  <label>Пароль <input name="password" type="password" value="alice-pw"></label>
  <button type="submit">Войти</button>
</form>`,
  );
}

export function files(viewer: Viewer, name: string): string {
  return layout(
    "Файлы",
    viewer,
    "/files",
    `<h1>Файлы</h1>
<p>Приложение не читает диск вовсе. Имя отражается, чтобы было видно, что
запрос дошёл до апстрима, — и только.</p>
<table class="kv">
  <tr><th>Запрошено</th><td><code>${esc(name)}</code></td></tr>
  <tr><th>Отдано</th><td>нет</td></tr>
</table>`,
  );
}

export function notice(viewer: Viewer, title: string, text: string, path = "/"): string {
  return layout(title, viewer, path, `<h1>${esc(title)}</h1><p>${esc(text)}</p>`);
}
