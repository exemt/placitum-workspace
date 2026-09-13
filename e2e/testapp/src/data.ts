/*
 * Набор витрины. Всё выводится из номера карточки, а не из случайности: после
 * перезапуска приложение отдаёт ровно те же данные, иначе e2e не смог бы
 * ждать конкретный `canary-` в теле ответа или конкретную страницу пагинации.
 *
 * Пароли здесь лежат в открытую и лежат в git намеренно: это фикстура стенда,
 * а не боевой каталог. Свои учётки калитки (провайдер `local`) живут не тут, а
 * в наборе данных контроллера -- приложение о них не знает вовсе.
 */

import { createHash } from "node:crypto";

export interface Item {
  id: number;
  title: string;
  tag: string;
  priceRub: number;
  /** метка объекта в ответе: по ней счётчик считает выдачу (`regex_count` на `obj=\d+`) */
  obj: string;
  /** цель маскирования у модификатора: `canary-(\w+)` -> `masked-$1` */
  canary: string;
  blurb: string;
}

export interface User {
  login: string;
  password: string;
  groups: string[];
}

/* Предмет и раздел ходят парой: иначе «Ноутбук» попадал бы в «телефоны», и
 * фильтр по тегу выглядел бы сломанным, хотя работает. */
const KINDS: [noun: string, tag: string][] = [
  ["Кресло", "мебель"],
  ["Ноутбук", "ноутбуки"],
  ["Смартфон", "телефоны"],
  ["Камера", "камеры"],
  ["Наушники", "аудио"],
  ["Стол", "мебель"],
  ["Монитор", "ноутбуки"],
  ["Клавиатура", "ноутбуки"],
  ["Лампа", "мебель"],
  ["Полка", "мебель"],
  ["Планшет", "телефоны"],
  ["Колонка", "аудио"],
];

export const TAGS = [...new Set(KINDS.map(([, tag]) => tag))];

/* Названия моделей, а не прилагательные: они не склоняются и не спорят с родом
 * существительного -- «Ноутбук Про», «Камера Про», «Кресло Про». */
const MODELS = [
  "Лайт", "Про", "Мини", "Макси", "Эко",
  "Плюс", "Нео", "Дуо", "Соло", "Флекс",
];

/** Устойчивый короткий маркер: одинаковый на всех машинах и после рестарта. */
export function canaryOf(seed: string): string {
  return `canary-${createHash("sha256").update(seed).digest("hex").slice(0, 8)}`;
}

function itemAt(id: number): Item {
  const [noun, tag] = KINDS[id % KINDS.length];
  const model = MODELS[(id * 7) % MODELS.length];

  return {
    id,
    title: `${noun} ${model} №${id}`,
    tag,
    priceRub: 500 + ((id * 137) % 90) * 100,
    obj: `obj=${id}`,
    canary: canaryOf(`item:${id}`),
    blurb: `${noun} ${model}. Позиция ${id} из набора витрины.`,
  };
}

export function buildItems(count: number): Item[] {
  return Array.from({ length: count }, (_, i) => itemAt(i + 1));
}

export const USERS: User[] = [
  { login: "alice", password: "alice-pw", groups: ["users"] },
  { login: "bob", password: "bob-pass", groups: ["users", "admins"] },
];

export function findUser(login: string, password: string): User | undefined {
  return USERS.find((u) => u.login === login && u.password === password);
}

/* --- выборка ------------------------------------------------------------ */

export interface Page {
  page: number;
  per: number;
  total: number;
  pages: number;
  items: Item[];
}

/** Размеры страницы фиксированы: скребок на `per=48` жжёт корзину счётчика вчетверо быстрее. */
export const PER_ALLOWED = [12, 24, 48] as const;

export function selectPage(all: Item[], rawPage: unknown, rawPer: unknown, q: string, tag: string): Page {
  const per = PER_ALLOWED.includes(Number(rawPer) as (typeof PER_ALLOWED)[number])
    ? Number(rawPer)
    : PER_ALLOWED[0];

  /*
   * Поиск нарочно наивный -- подстрока без разбора запроса. Приложение честное:
   * что бы ни пришло в `q`, оно не исполняется и не идёт ни в какую базу, а
   * только сравнивается и отражается в ответ. Предмет проверки -- вердикт
   * контура на этом `q`, а не дыра в приложении.
   */
  const needle = q.trim().toLowerCase();
  const filtered = all.filter(
    (item) =>
      (needle === "" || item.title.toLowerCase().includes(needle) || item.blurb.toLowerCase().includes(needle)) &&
      (tag === "" || item.tag === tag),
  );

  const total = filtered.length;
  const pages = Math.max(1, Math.ceil(total / per));
  const page = Math.min(Math.max(1, Math.floor(Number(rawPage)) || 1), pages);
  const from = (page - 1) * per;

  return { page, per, total, pages, items: filtered.slice(from, from + per) };
}
