/*
 * Проверки одиночными запросами: общая часть нагрузочных и логических кейсов.
 *
 * Проверка описывается данными, а не кодом, потому что кейс обязан оставаться
 * читаемым без импортов (его читает ещё и генератор). Здесь только исполнение
 * описанного: послать запрос через край, разобрать отладочный заголовок и
 * сказать, что не сошлось.
 */

import { probe } from "./stand.mjs";

/*
 * Между «канал сошёлся» и «инспектор сменил набор» есть щель в секунды: первое
 * про доставку поколения, второе про его применение. Одиночный запрос сразу
 * после издания попадает в неё и краснеет на ровном месте, поэтому проверка
 * повторяется до срока.
 */
export const SETTLE_MS = Number(process.env.WAF_E2E_SETTLE_MS ?? 15_000);

/** Коды отказов из каталога: имя записи -> статус. */
export async function denyStatuses(ctx) {
  const rows = (await ctx.get("/deny-responses")).deny_responses ?? [];
  return Object.fromEntries(rows.map((r) => [r.name, r.spec?.status ?? 403]));
}

/** Что не сошлось в одной проверке. Пустой список -- всё сошлось. */
export function check(p, got, denyStatus) {
  const bad = [];
  const want = p.expect;
  /*
   * Код отказа берётся из каталога по имени записи, а не пишется в кейс
   * числом: у `blocked` на разных стендах разный статус, и прибитое 403
   * сделало бы прогон ложно красным.
   */
  const wantStatus = want.deny !== undefined ? denyStatus[want.deny] : want.status;

  if (wantStatus !== undefined && got.status !== wantStatus) {
    bad.push(`код ${got.status}, ждали ${wantStatus}${want.deny ? ` (запись ${want.deny})` : ""}`);
  }

  if (want.verdict !== undefined && got.verdict !== want.verdict) {
    bad.push(`вердикт ${got.verdict || "нет"}, ждали ${want.verdict}`);
  }

  if (want.by !== undefined && got.by !== want.by) {
    bad.push(`решил ${got.by || "инспектор"}, ждали ${want.by}`);
  }

  if (want.scoreAtLeast !== undefined && got.score < want.scoreAtLeast) {
    bad.push(`очков ${got.score}, ждали не меньше ${want.scoreAtLeast}`);
  }

  /*
   * Выключенного просьбой инспектора модуль не печатает вовсе: в отладочном
   * заголовке он не «skip», а отсутствует. Поэтому и проверяем отсутствие.
   */
  if (want.notAsked !== undefined && got.inspectors[want.notAsked] !== undefined) {
    bad.push(`${want.notAsked} = ${got.inspectors[want.notAsked]}, а его должны были выключить`);
  }

  for (const name of [].concat(want.asked ?? [])) {
    if (got.inspectors[name] === undefined) {
      bad.push(`${name} не спрошен, а должен был`);
    }
  }

  /*
   * Тело ответа: им проверяется работа модификатора (метка на месте или
   * замаскирована) и что приложение отдало столько объектов, сколько просили.
   * Подстрока, а не регулярное выражение: кейс -- данные, и выражения в нём
   * пришлось бы возить строкой.
   */
  for (const text of [].concat(want.bodyHas ?? [])) {
    if (!got.body.includes(text)) {
      bad.push(`в теле нет «${text}»`);
    }
  }

  for (const text of [].concat(want.bodyLacks ?? [])) {
    if (got.body.includes(text)) {
      bad.push(`в теле осталось «${text}», а его должны были убрать`);
    }
  }

  /* Кто что ответил: значение в заголовке начинается с вердикта. */
  for (const [name, verdict] of Object.entries(want.answers ?? {})) {
    const value = got.inspectors[name];

    if (value === undefined) {
      bad.push(`${name} не спрошен, а должен был ответить ${verdict}`);
    } else if (!value.startsWith(verdict)) {
      bad.push(`${name} ответил ${value.split("/")[0]}, ждали ${verdict}`);
    }
  }

  return bad;
}

const send = (target, p, extra = {}) =>
  probe(p.path ?? target.path, {
    host: target.host,
    method: p.method ?? "GET",
    headers: { ...(p.ip ? { "X-Forwarded-For": p.ip } : {}), ...(p.headers ?? {}), ...extra },
    /* Тело: объект -- JSON, строка -- как есть. У GET его нет. */
    body: p.body ?? null,
  });

/**
 * Одна проверка с повторами до срока. Возвращает список несовпадений.
 *
 * `times` -- сколько раз послать запрос; проверяется последний ответ.
 * Поведенческому инспектору одного запроса мало: корзину сперва надо
 * наполнить, и наполняет её тот же запрос, которым потом проверяют. Повтор
 * после несовпадения шлёт один запрос, а не всю пачку: пачка уже ушла.
 */
export async function settle(target, p, denyStatus, settleMs = SETTLE_MS, extra = {}) {
  const until = Date.now() + settleMs;
  let times = Math.max(1, p.times ?? 1);

  for (;;) {
    let got;

    for (let i = 0; i < times; i += 1) {
      got = await send(target, p, extra);
    }

    const bad = check(p, got, denyStatus);

    if (bad.length === 0 || Date.now() > until) {
      return { bad, got };
    }

    times = 1;
    await new Promise((r) => setTimeout(r, 1000));
  }
}

/**
 * Прогнать все проверки кейса по порядку. Первая несошедшаяся -- исключение:
 * дальше идти незачем, состояние уже не то, что описывал кейс.
 *
 * Шаг с полем `solve` -- не проверка, а действие: пройти виджет капчи. Делает
 * его `hooks.solve`, а возвращённые им заголовки достаются пробам, помеченным
 * `cleared: true`. Метка обязательна и по умолчанию ложна: клиент с пройденной
 * капчей и клиент без неё -- два разных клиента, и путать их в одном списке
 * проверок нельзя.
 */
export async function runProbes(ctx, target, probes, say, hooks = {}) {
  const denyStatus = await denyStatuses(ctx);
  let carry = {};

  for (const p of probes) {
    if (p.solve !== undefined) {
      if (hooks.solve === undefined) {
        throw new Error(`шаг «${p.solve}» просит пройти виджет, а этот прогон так не умеет`);
      }

      carry = { ...carry, ...(await hooks.solve(p, say)) };
      say(`ok  ${p.solve}`);
      continue;
    }

    /*
     * Шаг с полем `list` -- взгляд в набор после трафика, а не запрос через
     * край: что туда записало правило и с каким сроком. Сам взгляд делает
     * `hooks.list` -- набор заведён кейсом, и его uuid знает только прогон.
     */
    if (p.list !== undefined) {
      if (hooks.list === undefined) {
        throw new Error(`шаг «${p.name}» смотрит в набор, а этот прогон так не умеет`);
      }

      await hooks.list(p, say);
      say(`ok  ${p.name}`);
      continue;
    }

    /*
     * Свой срок у пробы -- для ожиданий, которые дольше щели сходимости:
     * протухание записи бана, остывание корзины. Умолчание -- общее.
     */
    const { bad } = await settle(target, p, denyStatus, p.settleMs ?? SETTLE_MS, p.cleared === true ? carry : {});

    if (bad.length > 0) {
      throw new Error(`проверка «${p.name}»${p.ip ? ` (${p.ip})` : ""}: ${bad.join("; ")}`);
    }

    say(`ok  ${p.name}${p.ip ? ` (${p.ip})` : ""}`);
  }
}
