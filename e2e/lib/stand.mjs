/*
 * Заведение и снос стенда для e2e: тест приносит описание нужных сущностей
 * (`needs` кейса) и получает их живыми, а в конце -- пустоту.
 *
 * Два правила, из которых всё остальное следует.
 *
 * 1. Ничего не предполагается заранее. Апстрим, сервер, слушатель, наборы
 *    адресов, профили, объявления инспекторов и маршруты заводит сам прогон.
 *    Ручных правок конфигов, записей в базу и отдельно поднятых процессов нет.
 *
 * 2. Сносится ровно то, что завёл этот прогон. Порядок сноса -- обратный
 *    порядку заведения, и его ведёт журнал: чужие сущности прогон не трогает
 *    даже при совпадении имён (такое имя -- ошибка кейса, и она видна сразу).
 *
 * Имена сущностей кейс задаёт сам и должен держать их в своём пространстве
 * имён (`e2e-…`), иначе прогон на живом стенде наступит на чужое.
 */

import http from "node:http";

import { connect } from "./api.mjs";

export { connect };

/* Порядок заведения. Снос идёт по нему же, задом наперёд. */
const ORDER = [
  "datasets",
  /*
   * Файлы правил раньше наборов, наборы раньше объявлений: набор ссылается на
   * файлы по uuid, объявление -- на набор по имени. Снос идёт обратным
   * порядком, и это единственный порядок, в котором контроллер не отвечает
   * in_use.
   */
  "ruleFiles",
  "ruleSets",
  "ipSets",
  "ipProfiles",
  "actionProfiles",
  "counterShared",
  "counterProfiles",
  "rewriteProfiles",
  /*
   * Источник входа с формой (`login.uri`) требует уже заведённого маршрута, а
   * маршрут -- объявления, профиля и источника: круг. Здесь заводятся только
   * источники внешних провайдеров (`jwt`, `app`) с пустым `login.uri` -- у них
   * этой связи нет, и круга не возникает. Форму входа автономный кейс пока не
   * поднимает.
   */
  "authSources",
  "authProfiles",
  "upstreams",
  "declarations",
  "servers",
  "routes",
  /*
   * Профиль капчи -- последним, и это не прихоть порядка, а круг, который иначе
   * не разорвать: профиль требует `server_id` и уже заведённой локации виджета
   * (контроллер сверяет `path` со списком локаций сервера), а маршруты требуют
   * объявлений, которые называют профиль. Круг рвётся тем, что объявление
   * зовёт профиль **по имени** (`profile:`, а не `profileFrom:`) и наличия его
   * при записи никто не проверяет: профиль обязан существовать к изданию, а не
   * к объявлению.
   */
  "captchaProfiles",
];

/* --- журнал созданного -------------------------------------------------- */

export function ledger() {
  const rows = [];

  return {
    rows,
    add(kind, name, undo) {
      rows.push({ kind, name, undo });
    },
    /**
     * Снос в обратном порядке. Ошибку одного шага не глотаем, но и не бросаем:
     * остальное надо снять.
     *
     * Проходов два. Строгий обратный порядок разматывает не всякую связь:
     * профиль капчи заводится последним (ему нужны сервер и локация виджета),
     * а снимать его надо после объявления, которое его зовёт, -- то есть
     * позже, а не раньше. Общий второй проход дешевле особого случая в
     * порядке и закрывает весь этот класс кругов разом.
     */
    async unwind(say = () => {}) {
      let left = [...rows].reverse();

      rows.length = 0;

      for (let pass = 0; pass < 2 && left.length > 0; pass += 1) {
        const failed = [];

        for (const row of left) {
          try {
            await row.undo();
            say(`снят ${row.kind} ${row.name}`);
          } catch (err) {
            failed.push({ ...row, error: err.message });
          }
        }

        left = failed;
      }

      for (const row of left) {
        say(`НЕ СНЯТ ${row.kind} ${row.name}: ${row.error}`);
      }

      return left;
    },
  };
}

/* --- поиск существующего ------------------------------------------------ */

const listOf = async (ctx, path, key) => (await ctx.get(path))[key] ?? [];

const byName = (rows, name) => rows.find((r) => r.name === name) ?? null;

export async function findServer(ctx, name) {
  return byName(await listOf(ctx, "/servers", "servers"), name);
}

export async function findUpstream(ctx, name) {
  return byName(await listOf(ctx, "/upstreams", "upstreams"), name);
}

export async function findDataset(ctx, name) {
  return byName(await listOf(ctx, "/datasets", "datasets"), name);
}

export async function findPort(ctx, name) {
  return byName(await listOf(ctx, "/ports", "ports"), name);
}

export async function findRuleFile(ctx, name) {
  return byName(await listOf(ctx, "/rule-files", "rule_files"), name);
}

export async function findRuleSet(ctx, name) {
  return byName(await listOf(ctx, "/rule-sets", "rule_sets"), name);
}

/* --- общее -------------------------------------------------------------- */

/** Заголовки прокси: имя хоста и адрес клиента доезжают до приложения. */
export function proxyNginx(extra = []) {
  return {
    proxySetHeaders: [
      { name: "Host", value: "$host" },
      { name: "X-Forwarded-For", value: "$proxy_add_x_forwarded_for" },
      { name: "X-Forwarded-Proto", value: "$scheme" },
      ...extra,
    ],
    proxyHttpVersion: "1.1",
  };
}

/**
 * Подстановка значений, которых у кейса быть не может: открытый ключ прогона,
 * готовый заголовок Authorization, логин с меткой запуска. Кейс -- данные, и
 * такие места он называет именем (`"@jwt.public"`), а значение приносит
 * прогон.
 *
 * Заменяется только строка, целиком равная имени: подстроки не трогаются,
 * иначе описание маршрута зависело бы от того, что где-то встретилась собачка.
 */
export function substitute(value, subst) {
  if (typeof value === "string") {
    return Object.prototype.hasOwnProperty.call(subst, value) ? subst[value] : value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => substitute(item, subst));
  }

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, substitute(item, subst)]),
    );
  }

  return value;
}

function must(map, kind, name) {
  const row = map[kind]?.[name];

  if (row === undefined) {
    throw new Error(`кейс ссылается на ${kind} «${name}», а он не заведён этим же кейсом`);
  }

  return row;
}

/* --- заведение по описанию ---------------------------------------------- */

/**
 * Завести всё, что просит кейс. Возвращает журнал и карту созданного
 * (`made.servers["e2e-load"] = {uuid, ...}`), по которой раннер строит адреса.
 *
 * Имя, уже занятое на стенде, -- отказ, а не молчаливое переиспользование:
 * иначе снос в конце снёс бы чужое.
 */
export async function apply(ctx, needs, say = () => {}, { subst = {} } = {}) {
  const log = ledger();
  const made = {};
  const filled = Object.keys(subst).length === 0 ? needs : substitute(needs, subst);

  try {
    for (const kind of ORDER) {
      const spec = filled[kind];

      if (spec === undefined) {
        continue;
      }

      made[kind] = {};
      await CREATE[kind](ctx, spec, made, log, say);
    }
  } catch (err) {
    say(`заведение сорвалось: ${err.message}`);
    await log.unwind(say);
    throw err;
  }

  return { ledger: log, made };
}

const CREATE = {
  async datasets(ctx, rows, made, log, say) {
    const types = (await ctx.get("/content-types")).content_types ?? [];

    for (const row of rows) {
      if (await findDataset(ctx, row.name)) {
        throw new Error(`набор «${row.name}» уже есть на стенде`);
      }

      const body = {
        name: row.name,
        description: row.description ?? "Заведён нагрузочным прогоном",
        kind: row.kind ?? "list",
        type: row.type ?? "ip",
        active: row.active ?? false,
      };

      if (row.ttl) body.ttl = row.ttl;
      if (row.in_nginx) body.in_nginx = true;
      /* Потолок записей: умолчание контроллера -- миллион; кейс называет своё явно. */
      if (row.limit) body.limit = row.limit;
      /* hash=md5: набор строк хранит md5 значений; контроллер хеширует сам. */
      if (row.hash) body.hash = true;
      if (row.contentType) {
        body.content_type_id = byName(types, row.contentType)?.uuid;
      }

      await ctx.post("/datasets", body);
      const made1 = await findDataset(ctx, row.name);

      if (made1 === null) {
        throw new Error(`набор «${row.name}» не создался`);
      }

      log.add("набор", row.name, () => ctx.del(`/datasets/${made1.uuid}`));
      made.datasets[row.name] = made1;
      say(`набор ${row.name} заведён`);

      if (row.addresses?.length) {
        /*
         * Пачкой: по одному адресу на запрос это сотни вызовов на список.
         *
         * У активного набора запись идёт через keeper, а он монтирует набор не
         * мгновенно после создания: первые секунды контроллер отвечает
         * keeper_unavailable. Это не поломка, а щель между «набор создан» и
         * «набор смонтирован», поэтому запись повторяется до срока.
         */
        const until = Date.now() + 30_000;

        for (;;) {
          const res = await ctx.call(
            "POST",
            `${ctx.base}/datasets/${made1.uuid}/addresses`,
            { addresses: row.addresses },
            { allow: [503] },
          );

          if (res.status !== 503) {
            break;
          }

          if (Date.now() > until) {
            throw new Error(`набор ${row.name}: keeper не смонтировал его за 30 с`);
          }

          await new Promise((r) => setTimeout(r, 1000));
        }

        say(`  адресов внесено: ${row.addresses.length}`);
      }
    }
  },

  /**
   * Файл правил SecLang. Текст кейс приносит целиком: правки во время прогона
   * идут тем же PUT, что и из панели, -- поэтому uuid запоминается.
   */
  async ruleFiles(ctx, rows, made, log, say) {
    for (const row of rows) {
      if (await findRuleFile(ctx, row.name)) {
        throw new Error(`файл правил «${row.name}» уже есть на стенде`);
      }

      const file = await ctx.post("/rule-files", {
        name: row.name,
        description: row.description ?? "Заведён прогоном e2e",
        text_raw: row.text ?? "",
      });
      const uuid = file.uuid ?? file.rule_file?.uuid;

      log.add("файл правил", row.name, () => ctx.del(`/rule-files/${uuid}`));
      made.ruleFiles[row.name] = { ...file, uuid, name: row.name };
      say(`файл правил ${row.name} заведён`);
    }
  },

  /**
   * Набор правил -- профиль инспектора modsec: упорядоченный список файлов.
   *
   * Файл ищется сперва среди заведённых этим прогоном, потом в каталоге
   * пространства: куски CRS (`engine`, `crs-941`, …) приходят сидом, копировать
   * их в кейс незачем -- их тысячи строк, и предмет проверки не в них.
   */
  async ruleSets(ctx, rows, made, log, say) {
    const catalog = (await ctx.get("/rule-files")).rule_files ?? [];

    for (const row of rows) {
      if (await findRuleSet(ctx, row.name)) {
        throw new Error(`набор правил «${row.name}» уже есть на стенде`);
      }

      const files = (row.files ?? []).map((name) => {
        const own = made.ruleFiles?.[name];
        const shipped = byName(catalog, name);

        if (own === undefined && shipped === null) {
          throw new Error(`набор правил «${row.name}» зовёт файл «${name}», а его нет ни в кейсе, ни в каталоге`);
        }

        return (own ?? shipped).uuid;
      });

      const set = await ctx.post("/rule-sets", {
        name: row.name,
        description: row.description ?? "Заведён прогоном e2e",
        files,
      });
      const uuid = set.uuid ?? set.rule_set?.uuid;

      log.add("набор правил", row.name, () => ctx.del(`/rule-sets/${uuid}`));
      made.ruleSets[row.name] = { ...set, uuid, name: row.name };
      say(`набор правил ${row.name} заведён, файлов ${files.length}`);
    }
  },

  async ipSets(ctx, rows, made, log, say) {
    for (const row of rows) {
      const body = {
        name: row.name,
        description: row.description ?? "Заведён нагрузочным прогоном",
        inverse: row.inverse ?? false,
        lists: (row.lists ?? []).map((n) => must(made, "datasets", n).uuid),
        countries: row.countries ?? [],
        asns: row.asns ?? [],
      };
      const set = await ctx.post("/ip-sets", body);
      const uuid = set.uuid ?? set.id ?? set.ip_set?.uuid;

      log.add("набор адресов", row.name, () => ctx.del(`/ip-sets/${uuid}`));
      made.ipSets[row.name] = { ...set, uuid };
      say(`набор адресов ${row.name} заведён`);
    }
  },

  async ipProfiles(ctx, rows, made, log, say) {
    for (const row of rows) {
      const rules = (row.rules ?? []).map((r, i) => ({
        position: i,
        action: r.action,
        /* Терминальная строка спрашивает про составной набор, накопительная -- про сырой список. */
        set: r.set ? must(made, "ipSets", r.set).uuid : undefined,
        dataset: r.dataset ? must(made, "datasets", r.dataset).uuid : undefined,
        response: r.response ?? "",
        code: r.code ?? "",
        not: r.not ?? false,
        /*
         * Просьба соседу или модулю: адресат, глагол, ось и параметр. У очков
         * и управляющих глаголов адресата нет -- их исполняет модуль.
         */
        to: r.to ?? "",
        /* На проводе глагол называется do, ось -- apply; verb/axis это поля модели. */
        do: r.verb ?? "",
        apply: r.axis ?? "",
        delta: r.delta ?? null,
        value: r.value ?? null,
        counter: r.counter ?? "",
        marker: r.marker ?? "",
        /* list: куда, кого (адрес, подсеть, система) и на сколько вносить. */
        list: r.list ? must(made, "datasets", r.list).uuid : undefined,
        write: r.write ?? "addr",
        ttl: r.listTtlS ?? 0,
        enabled: true,
      }));
      const body = {
        name: row.name,
        description: row.description ?? "Заведён нагрузочным прогоном",
        default: row.default ?? "allow",
        default_code: row.defaultCode ?? "",
        datasets: (row.datasets ?? []).map((n) => must(made, "datasets", n).uuid),
        rules,
        /* Строка по исходу называет живой набор именем -- как и всё остальное в кейсе. */
        outcomes: (row.outcomes ?? []).map((o) => (
          o.list ? { ...o, list: must(made, "datasets", o.list).uuid } : o
        )),
      };
      const prof = await ctx.post("/ip-profiles", body);
      const uuid = prof.uuid ?? prof.ip_profile?.uuid;

      log.add("профиль адреса", row.name, () => ctx.del(`/ip-profiles/${uuid}`));
      made.ipProfiles[row.name] = { ...prof, uuid };
      say(`профиль адреса ${row.name} заведён`);
    }
  },

  /**
   * Профиль инспектора действий: документ целиком, как его печатает панель.
   * Условия -- имя и строки по И (`all`) либо по ИЛИ (`any`); строкой бывает
   * ссылка на другое условие (`cond` + `is` / `is_not`). Правило -- совпадение
   * по запросу, «когда» (`if` / `unless` -- имя условия) плюс список просьб.
   */
  async actionProfiles(ctx, rows, made, log, say) {
    const clauseOf = (cl) => ({
      value: cl.value ?? "",
      op: cl.op,
      dataset: cl.dataset ?? "",
      text: cl.text ?? "",
      cond: cl.cond ?? "",
    });

    for (const row of rows) {
      const doc = {
        mode: "enforce",
        conditions: (row.conditions ?? []).map((c) => ({
          name: c.name,
          any: c.any !== undefined,
          rows: (c.any ?? c.all ?? c.rows ?? []).map(clauseOf),
        })),
        rules: (row.rules ?? []).map((r) => ({
          name: r.name,
          match: {
            path_prefix: r.pathPrefix ?? "",
            suffixes: r.suffixes ?? [],
            static: r.static ?? false,
            methods: r.methods ?? [],
          },
          ...(r.if ? { if: r.if } : {}),
          ...(r.unless ? { unless: r.unless } : {}),
          actions: (r.actions ?? []).map((a) =>
            a.list
              ? {
                  /*
                   * Запись в набор: не просьба -- ни адресата, ни глагола, ни
                   * оси; кого писать и на сколько. Набор -- по имени: так его
                   * адресует keeper.
                   */
                  list: must(made, "datasets", a.list).name,
                  write: a.write ?? "addr",
                  ttl_s: a.ttlS ?? 0,
                  code: a.code ?? "",
                }
              : {
                  to: a.to ?? "",
                  do: a.verb,
                  apply: a.axis ?? "request",
                  delta: a.delta ?? null,
                  value: a.value ?? null,
                  counter: a.counter ?? "",
                  marker: a.marker ?? "",
                  code: a.code ?? "",
                },
          ),
        })),
      };
      const prof = await ctx.post("/action/profiles", {
        name: row.name,
        description: row.description ?? "Заведён прогоном e2e",
        doc,
      });
      const uuid = prof.uuid ?? prof.profile?.uuid;

      log.add("профиль действий", row.name, () => ctx.del(`/action/profiles/${uuid}`));
      made.actionProfiles[row.name] = { ...prof, uuid, name: row.name };
      say(`профиль действий ${row.name} заведён`);
    }
  },

  /**
   * Объявления счётчиков -- общая секция инспектора, одна на пространство:
   * не создание записи, а правка общего документа, как у объявлений
   * инспекторов. Дописываются свои счётчики, снимаются в конце тоже свои;
   * `subjects` пространства кейс не трогает вовсе -- источник ключа оси
   * `user` каждый счётчик называет у себя (`from`), и тогда правка одного
   * прогона не меняет поведения чужих.
   */
  async counterShared(ctx, spec, made, log, say) {
    const before = (await ctx.get("/counter/shared")).shared ?? { counters: {}, subjects: {} };
    const mine = {};

    for (const [name, decl] of Object.entries(spec)) {
      if (before.counters?.[name] !== undefined) {
        throw new Error(`счётчик «${name}» уже объявлен на стенде`);
      }

      mine[name] = {
        unit: decl.unit ?? "obj",
        fill: decl.fill ?? "measure",
        axes: decl.axes,
        ...(decl.from ? { subjects: { user: { from: decl.from } } } : {}),
      };
    }

    await ctx.put("/counter/shared", {
      shared: { ...before, counters: { ...(before.counters ?? {}), ...mine } },
    });

    made.counterShared = mine;
    log.add("счётчики", Object.keys(mine).join(", "), async () => {
      const now = (await ctx.get("/counter/shared")).shared ?? { counters: {} };
      const left = { ...(now.counters ?? {}) };

      for (const name of Object.keys(mine)) delete left[name];

      await ctx.put("/counter/shared", { shared: { ...now, counters: left } });
    });
    say(`объявлены счётчики: ${Object.keys(mine).join(", ")}`);
  },

  /**
   * Профиль счётчика: документ целиком, как его печатает панель. Умолчания
   * достраиваются здесь, чтобы кейс писал только то, что важно ему, --
   * контроллер требует полную форму.
   */
  async counterProfiles(ctx, rows, made, log, say) {
    for (const row of rows) {
      const doc = {
        description: row.description ?? "Заведён прогоном e2e",
        trigger: { prior: row.prior ?? [] },
        request: {
          enabled: row.request !== undefined,
          judge: judgeOf(row.request?.judge),
          denyResponse: row.request?.denyResponse ?? "counter_limit",
          outcomes: outcomesOf(row.request?.outcomes),
        },
        response: {
          enabled: row.response !== undefined,
          measure: measureOf(row.response?.measure),
        },
        frame: {
          enabled: row.frame !== undefined,
          measure: measureOf(row.frame?.measure),
          judge: judgeOf(row.frame?.judge),
          denyResponse: row.frame?.denyResponse ?? "ws_policy",
          outcomes: outcomesOf(row.frame?.outcomes),
        },
      };
      const prof = await ctx.post("/counter/profiles", {
        name: row.name,
        description: doc.description,
        doc,
      });
      const uuid = prof.uuid ?? prof.profile?.uuid;

      log.add("профиль счётчика", row.name, () => ctx.del(`/counter/profiles/${uuid}`));
      made.counterProfiles[row.name] = { ...prof, uuid, name: row.name };
      say(`профиль счётчика ${row.name} заведён`);
    }
  },

  /** Профиль модификатора: группы правок и правила приёма просьб mutate. */
  async rewriteProfiles(ctx, rows, made, log, say) {
    for (const row of rows) {
      const doc = {
        description: row.description ?? "Заведён прогоном e2e",
        denyResponse: row.denyResponse ?? "rewrite_failed",
        groups: (row.groups ?? []).map((g) => ({
          name: g.name,
          /* Выключенную группу включает просьба mutate соседа. */
          default: g.default ?? false,
          on: g.on ?? "response",
          status: g.status ?? [],
          contentType: g.contentType ?? [],
          direction: g.direction ?? [],
          opcode: g.opcode ?? [],
          body: (g.body ?? []).map((op) => ({
            op: op.op,
            pattern: op.pattern ?? "",
            to: op.to ?? "",
            text: op.text ?? "",
            maxMatches: op.maxMatches ?? null,
          })),
          headers: g.headers ?? [],
        })),
        prior: (row.prior ?? []).map((p) => ({
          from: p.from,
          accept: p.accept ?? ["mutate"],
          codes: p.codes ?? [],
        })),
      };
      const prof = await ctx.post("/rewrite/profiles", {
        name: row.name,
        description: doc.description,
        doc,
      });
      const uuid = prof.uuid ?? prof.profile?.uuid;

      log.add("профиль модификатора", row.name, () => ctx.del(`/rewrite/profiles/${uuid}`));
      made.rewriteProfiles[row.name] = { ...prof, uuid, name: row.name };
      say(`профиль модификатора ${row.name} заведён`);
    }
  },

  /**
   * Источник входа. Только внешние провайдеры: у них нет ни формы, ни билета,
   * ни своего маршрута, поэтому источник заводится до сервера и ничего за
   * собой не тянет. Подпись токена проверяет калитка -- ключ приносит кейс.
   */
  async authSources(ctx, rows, made, log, say) {
    for (const row of rows) {
      const src = await ctx.post("/auth/sources", {
        name: row.name,
        description: row.description ?? "Заведён прогоном e2e",
        doc: {
          login: { uri: "" },
          provider: row.provider ?? "jwt",
          providers: row.providers,
        },
      });
      const uuid = src.uuid ?? src.source?.uuid;

      log.add("источник входа", row.name, () => ctx.del(`/auth/sources/${uuid}`));
      made.authSources[row.name] = { ...src, uuid, name: row.name };
      say(`источник входа ${row.name} заведён (${row.provider ?? "jwt"})`);
    }
  },

  /** Профиль калитки: политика допуска одного маршрута поверх источника. */
  async authProfiles(ctx, rows, made, log, say) {
    for (const row of rows) {
      const prof = await ctx.post("/auth/profiles", {
        name: row.name,
        description: row.description ?? "Заведён прогоном e2e",
        doc: {
          source: must(made, "authSources", row.sourceFrom).name,
          gate: {
            /* Пусто -- редиректа нет вовсе: гость получает 401, а не форму. */
            redirectMethods: row.redirectMethods ?? [],
            redirectStatus: 303,
            denyResponse: row.denyResponse ?? "auth_required",
            htmlOnly: row.htmlOnly ?? false,
            groups: row.groups ?? [],
            forbiddenResponse: row.forbiddenResponse ?? "auth_forbidden",
            inline: false,
          },
          trigger: { prior: row.prior ?? [], reauthAfterS: row.reauthAfterS ?? 0 },
        },
      });
      const uuid = prof.uuid ?? prof.profile?.uuid;

      log.add("профиль калитки", row.name, () => ctx.del(`/auth/profiles/${uuid}`));
      made.authProfiles[row.name] = { ...prof, uuid, name: row.name };
      say(`профиль калитки ${row.name} заведён`);
    }
  },

  async upstreams(ctx, rows, made, log, say) {
    for (const row of rows) {
      if (await findUpstream(ctx, row.name)) {
        throw new Error(`апстрим «${row.name}» уже есть на стенде`);
      }

      const up = await ctx.post("/upstreams", {
        name: row.name,
        method: row.method ?? "round_robin",
        peers: row.peers.map((p) => ({ host: p.host, port: p.port, weight: p.weight ?? 1 })),
      });

      log.add("апстрим", row.name, () => ctx.del(`/upstreams/${up.uuid}`));
      made.upstreams[row.name] = up;
      say(`апстрим ${row.name} -> ${row.peers.map((p) => `${p.host}:${p.port}`).join(", ")}`);
    }
  },

  /**
   * Объявления инспекторов живут одним jsonb на пространстве, поэтому здесь
   * не создание записи, а правка общего документа: дописываем свои имена и
   * запоминаем, что снять. Имя, уже занятое, -- отказ.
   */
  async declarations(ctx, spec, made, log, say) {
    const http = await ctx.get("/http");
    const current = { ...(http.waf?.inspectors ?? {}) };
    const mine = {};

    for (const [name, decl] of Object.entries(spec)) {
      if (current[name] !== undefined) {
        throw new Error(`объявление «${name}» уже есть на стенде`);
      }

      const from = decl.profileFrom;
      /*
       * Профиль ищется среди заведённых этим же кейсом, в каком бы канале он
       * ни жил: имя в объявлении одно, а документы у каналов разные.
       */
      const kinds = ["ipProfiles", "actionProfiles", "counterProfiles", "rewriteProfiles", "authProfiles", "ruleSets"];
      const found = from ? kinds.map((kind) => made[kind]?.[from]).find((row) => row !== undefined) : undefined;

      if (from && found === undefined) {
        throw new Error(`объявление «${name}» зовёт профиль «${from}», а он не заведён этим же кейсом`);
      }

      const profile = from ? found.name : decl.profile;
      mine[name] = { process: decl.process, ...(profile ? { profile } : {}) };
    }

    await writeInspectors(ctx, { ...current, ...mine });
    made.declarations = mine;
    log.add("объявления", Object.keys(mine).join(", "), async () => {
      const now = await ctx.get("/http");
      const left = { ...(now.waf?.inspectors ?? {}) };
      for (const name of Object.keys(mine)) delete left[name];
      await writeInspectors(ctx, left);
    });
    say(`объявлены: ${Object.keys(mine).join(", ")}`);
  },

  async servers(ctx, rows, made, log, say) {
    for (const row of rows) {
      if (await findServer(ctx, row.name)) {
        throw new Error(`сервер «${row.name}» уже есть на стенде`);
      }

      const srv = await ctx.post("/servers", {
        name: row.name,
        server_names: row.server_names ?? [row.name],
        enabled: true,
        nginx: row.nginx ?? {},
        waf: row.waf ?? {},
      });

      log.add("сервер", row.name, () => ctx.del(`/servers/${srv.uuid}`));
      made.servers[row.name] = srv;
      say(`сервер ${row.name} заведён`);

      const portName = row.port ?? "http-8080";
      const port = await findPort(ctx, portName);

      if (port === null) {
        throw new Error(`слушателя «${portName}» нет в пространстве`);
      }

      /*
       * default_server не ставим: на стенде им может владеть чужой сервер, а
       * второй умолчательный на том же порту -- отказ сборки. Нам хватает
       * различения по имени хоста.
       */
      await ctx.post(`/servers/${srv.uuid}/ports`, { port_id: port.uuid, default_server: false });
      say(`  слушатель ${portName} привязан`);
    }
  },

  /**
   * Профиль капчи: документ целиком, как его печатает панель, плюс привязка к
   * серверу. Умолчания достраивает контроллер (`normalizeDoc`), поэтому кейс
   * пишет только значащее -- корзины, события и калитку.
   *
   * `path` -- адрес виджета, и он обязан быть заведённой локацией этого же
   * сервера: контроллер сверяет его со списком и отвечает `unknown_location`.
   * Поэтому маршрут виджета кейс заводит сам, обычной строкой в `routes`.
   */
  async captchaProfiles(ctx, rows, made, log, say) {
    for (const row of rows) {
      const server = must(made, "servers", row.server);
      const doc = {
        path: row.path,
        title: row.title ?? "Подтвердите, что вы не робот",
        trigger: {
          when: row.when ?? "buckets",
          prior: (row.prior ?? []).map((p) => ({
            from: p.from,
            accept: p.accept ?? ["note"],
            codes: p.codes ?? [],
          })),
        },
        buckets: row.buckets ?? {},
        rules: (row.rules ?? []).map((r) => ({
          on: r.on,
          bucket: r.bucket ?? "",
          /* Решение лестницы: пропустила или показала виджет; пусто -- любое. */
          next: r.next ?? "",
          /* На проводе глагол называется do, ось -- apply; verb/axis это поля модели. */
          to: r.to ?? "",
          do: r.verb ?? "",
          apply: r.axis ?? "",
          value: r.value ?? null,
          delta: r.delta ?? null,
          counter: r.counter ?? "",
          marker: r.marker ?? "",
          group: r.group ?? "",
          set: r.set ?? "",
          /* Запись субъекта в живой набор. */
          list: r.list ? must(made, "datasets", r.list).name : "",
          ttlS: r.ttlS ?? 0,
          write: r.write ?? "addr",
          /* Заряд своей корзины: вид и ±% ёмкости. */
          charge: r.charge ?? "",
          percent: r.percent ?? 0,
          code: r.code ?? "",
        })),
        gate: {
          /* Пусто -- редиректа нет вовсе: клиент получает отказ телом. */
          redirectMethods: row.gate?.redirectMethods ?? [],
          redirectStatus: row.gate?.redirectStatus ?? 303,
          denyResponse: row.gate?.denyResponse ?? "captcha_required",
          htmlOnly: row.gate?.htmlOnly ?? false,
          inline: row.gate?.inline ?? false,
        },
        provider: row.provider ?? { kind: "image", length: 5, audio: false },
        clearance: row.clearance ?? {},
      };
      const prof = await ctx.post("/captcha/profiles", {
        name: row.name,
        description: row.description ?? "Заведён прогоном e2e",
        server_id: server.uuid,
        doc,
      });
      const uuid = prof.uuid ?? prof.profile?.uuid;

      log.add("профиль капчи", row.name, () => ctx.del(`/captcha/profiles/${uuid}`));
      made.captchaProfiles[row.name] = { ...prof, uuid, name: row.name };
      say(`профиль капчи ${row.name} заведён, виджет на ${row.path}`);
    }
  },

  async routes(ctx, rows, made, log, say) {
    for (const row of rows) {
      const server = must(made, "servers", row.server);
      const upstream = row.upstream ? must(made, "upstreams", row.upstream) : null;
      const doc = {
        handler: row.handler ?? "proxy",
        protocol: row.protocol ?? "http",
        upstream_id: upstream?.uuid ?? null,
        upstream_uri: null,
        return_status: null,
        return_page: null,
        return_url: null,
        enabled: true,
        raw: false,
        raw_nginx: "",
        match: row.match,
        path: row.path,
        position: row.position ?? 100,
        nginx: row.nginx ?? proxyNginx(),
        waf: row.waf ?? {},
      };
      const loc = await ctx.post(`/servers/${server.uuid}/locations`, doc);
      const uuid = loc.uuid ?? loc.location?.uuid;

      log.add("маршрут", `${row.match} ${row.path}`, () => ctx.del(`/locations/${uuid}`));
      made.routes[row.path] = { ...loc, uuid, server };
      say(`маршрут ${row.match} ${row.path} заведён`);
    }
  },
};

/* --- формы документа счётчика ------------------------------------------- */

/*
 * Три достройки до полной формы. Кейс пишет только значащее -- «корзина, ось,
 * порог, что делать», -- а контроллер требует все ключи документа, включая
 * пустые. Держать эту разницу в кейсе значило бы утопить смысл правила в
 * двадцати `null`.
 */

function judgeOf(rows = []) {
  return rows.map((r) => ({
    counter: r.counter,
    axis: r.axis,
    at: r.at,
    action: r.action ?? "score",
    score: r.score ?? 0,
    code: r.code ?? "",
  }));
}

function measureOf(rows = []) {
  return rows.map((r) => ({
    if: {
      status: r.if?.status ?? [],
      contentType: r.if?.contentType ?? [],
      methods: r.if?.methods ?? [],
      direction: r.if?.direction ?? [],
      opcode: r.if?.opcode ?? [],
    },
    source: r.source,
    regex: r.regex ?? "",
    per: r.per ?? null,
    counter: r.counter,
    axes: r.axes ?? [],
  }));
}

function outcomesOf(rows = []) {
  return rows.map((o) => ({
    on: o.on ?? "score",
    at: o.at ?? null,
    below: o.below ?? false,
    eq: false,
    /* Только у on: level -- какую корзину смотреть. */
    if: o.if ?? null,
    to: o.to ?? "",
    /* На проводе глагол называется do, ось -- apply; verb/axis это поля модели. */
    do: o.verb ?? "",
    apply: o.axis ?? "",
    delta: null,
    value: o.value ?? null,
    counter: o.counter ?? "",
    marker: o.marker ?? "",
    group: o.group ?? "",
    set: o.set ?? "",
    headers: null,
    args: null,
    body: null,
    when: [],
    list: o.list ?? "",
    write: o.write ?? "",
    ttlS: o.ttlS ?? 0,
    code: o.code ?? "",
  }));
}

async function writeInspectors(ctx, inspectors) {
  const http = await ctx.get("/http");

  await ctx.put("/http", {
    nginx_main: http.nginx_main,
    nginx: http.nginx,
    waf_http: http.waf_http,
    waf: { ...(http.waf ?? {}), inspectors },
    raw: http.raw,
    raw_nginx: http.raw_nginx,
  });
}

/* --- пул адресов -------------------------------------------------------- */

/**
 * Развернуть описание пула в список настоящих префиксов.
 *
 * Кейс называет источники (`{country: "de", limit: 60}`, `{list: "имя"}`,
 * `{asn: 3320, limit: 20}`), а прогон достаёт их через API. Пул нужен
 * повторяемый, поэтому порядок фиксирован: источники идут как в кейсе, внутри
 * источника -- как отдаёт контроллер, и лишнее отрезается по `limit`.
 */
export async function resolvePool(ctx, spec, made) {
  const cidrs = [];

  /* Страница у контроллера не больше 200 записей: берём столько, сколько просят. */
  const pages = async (path, want) => {
    const out = [];

    for (let page = 0; out.length < want; page += 1) {
      const size = Math.min(200, want - out.length);
      const row = await ctx.get(`${path}?page=${page}&page_size=${size}`);
      const got = (row.addresses ?? []).map((a) => a.address);

      out.push(...got);

      if (got.length < size) {
        break;
      }
    }

    return out;
  };

  for (const src of spec.from ?? []) {
    if (src.country) {
      const rows = (await ctx.get("/ip-countries")).ip_countries ?? [];
      const row = rows.find((r) => r.code === src.country && r.type === (src.type ?? "v4"));

      if (row === undefined) {
        throw new Error(`страны ${src.country} нет в пространстве`);
      }

      cidrs.push(...(await pages(`/ip-countries/${row.uuid}/addresses`, src.limit ?? 500)));
      continue;
    }

    if (src.asn !== undefined) {
      const rows = (await ctx.get("/ip-asns")).ip_asns ?? [];
      const row = rows.find((r) => Number(r.asn) === Number(src.asn) && r.type === (src.type ?? "v4"));

      if (row === undefined) {
        throw new Error(`ASN ${src.asn} нет в пространстве`);
      }

      cidrs.push(...(await pages(`/ip-asns/${row.uuid}/addresses`, src.limit ?? 500)));
      continue;
    }

    if (src.list) {
      const ds = made?.datasets?.[src.list] ?? (await findDataset(ctx, src.list));

      if (ds === null || ds === undefined) {
        throw new Error(`набора ${src.list} нет`);
      }

      cidrs.push(...(await pages(`/datasets/${ds.uuid}/addresses`, src.limit ?? 500)));
      continue;
    }

    if (src.cidrs) {
      cidrs.push(...src.cidrs);
    }
  }

  /* Только IPv4: обход в генераторе считает адрес числом. */
  const v4 = cidrs.filter((c) => /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(c));

  if (v4.length === 0) {
    throw new Error("пул пуст: ни одного пригодного префикса");
  }

  const size = v4.reduce((n, c) => n + 2 ** (32 - Number(c.split("/")[1])), 0);

  return { cidrs: v4, count: Math.min(spec.count ?? size, size), size };
}

/* --- проверка до нагрузки ----------------------------------------------- */

export const EDGE = process.env.WAF_E2E_EDGE ?? "http://127.0.0.1:8081";

/**
 * Один запрос через край. Возвращает код и разобранный X-WAF-Debug, чтобы шаг
 * мог проверить не только ответ клиенту, но и что решил модуль.
 */
export async function probe(url, { host, headers = {}, method = "GET", body: sent = null } = {}) {
  /*
   * node:http, а не fetch: undici считает Host запрещённым заголовком и молча
   * его выбрасывает, после чего запрос уходит на сервер по умолчанию, а не на
   * наш. Симптом -- 200 от чужого маршрута там, где ждали отказ.
   */
  const target = new URL(EDGE);
  /*
   * Тело запроса: объект уезжает JSON-ом, строка -- как есть. Длина
   * проставляется явно: без неё node шлёт тело кусками, и что у запроса есть
   * тело, край узнаёт только по первому куску.
   */
  const payload = sent === null ? null : typeof sent === "string" ? sent : JSON.stringify(sent);
  const bodyHeaders = payload === null ? {} : {
    "content-type": typeof sent === "string" ? "text/plain" : "application/json",
    "content-length": Buffer.byteLength(payload),
  };
  const { res, body } = await new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: target.hostname,
        port: target.port || 80,
        path: url,
        method,
        headers: { Host: host, ...bodyHeaders, ...headers },
        timeout: 15_000,
      },
      (r) => {
        /*
         * Тело читается, а не отбрасывается: по нему видно работу модификатора
         * (замаскирована ли метка) и сколько объектов отдало приложение.
         * Ответы кейсов мелкие, поэтому предела здесь нет.
         */
        const chunks = [];

        r.on("data", (chunk) => chunks.push(chunk));
        r.on("end", () => resolve({ res: r, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );

    req.on("timeout", () => req.destroy(new Error("проверка не уложилась в срок")));
    req.on("error", reject);

    if (payload !== null) {
      req.write(payload);
    }

    req.end();
  });

  const raw = res.headers["x-waf-debug"] ?? "";
  const insp = {};

  /*
   * Заголовок модуль пишет на каждой фазе, и у запроса с фазой ответа их два:
   * node склеивает повторы через запятую, запись фазы запроса -- первой. Имя,
   * стоящее на обеих фазах, встречается дважды, и прав первый токен: кейсы
   * спрашивают о решении на запросе, а поздний токен того же имени -- учёт
   * фазы ответа, и он молча затирал бы суд (`allow/COUNTER_SKIPPED` запроса
   * превращался в `allow` ответа). Имена только фазы ответа остаются как были.
   */
  for (const m of raw.matchAll(/ ([\w-]+)=([^\s,]+)/g)) {
    /* Не инспекторы: служебные ключи и объекты снимка (headers=hot:redis/…). */
    if (
      !["rid", "ray", "v", "score", "shadow", "wave", "by", "fail", "rewrite", "body", "headers", "args"].includes(m[1]) &&
      insp[m[1]] === undefined
    ) {
      insp[m[1]] = m[2];
    }
  }

  return {
    status: res.statusCode,
    body,
    debug: raw,
    verdict: /v=(\w+)/.exec(raw)?.[1] ?? "",
    /* Кто решил: score -- сумма очков маршрута, local -- локальный слой. */
    by: / by=(\w+)/.exec(raw)?.[1] ?? "",
    score: Number(/score=(-?\d+)/.exec(raw)?.[1] ?? 0),
    fail: / fail=([\w_]+)/.exec(raw)?.[1] ?? "",
    inspectors: insp,
  };
}

/* --- издание и сходимость ----------------------------------------------- */

const SEND = {
  nginx: "/config/send",
  ip: "/ip-profiles/send",
  auth: "/auth/send",
  captcha: "/captcha/send",
  counter: "/counter/send",
  rewrite: "/rewrite/send",
  json: "/json/send",
  action: "/action/send",
  vlai: "/vlai/send",
  /*
   * Канал правил зовётся `rules` -- так он назван в снимке сходимости
   * (controller/src/convergence/channels.ts), а этими же именами ждут
   * сходимости. Инспектор при этом называется modsec: имя канала и имя
   * процесса тут не совпадают, и совпадать не обязаны.
   */
  rules: "/rules/send",
};

/**
 * Какие каналы нужно издать для этого кейса. Выводится из состава, а не
 * перечисляется руками: забытый канал не роняет заведение, а всплывает потом
 * ошибкой инспектора вроде IP_UNKNOWN_PROFILE, и искать её долго.
 */
export function channelsFor(needs) {
  if (Array.isArray(needs.publish)) {
    return needs.publish;
  }

  const out = [];

  if (needs.ipProfiles?.length || needs.ipSets?.length) out.push("ip");
  if (needs.actionProfiles?.length) out.push("action");
  /* Общая секция едет тем же каналом, что и профили: псевдопрофилем _shared. */
  if (needs.counterProfiles?.length || needs.counterShared !== undefined) out.push("counter");
  if (needs.rewriteProfiles?.length) out.push("rewrite");
  if (needs.authSources?.length || needs.authProfiles?.length) out.push("auth");
  if (needs.ruleSets?.length || needs.ruleFiles?.length) out.push("rules");
  if (needs.captchaProfiles?.length) out.push("captcha");

  /* Конфигурация краёв нужна всегда: без неё маршрута не существует. */
  out.push("nginx");

  return out;
}

export async function publish(ctx, channels, say = () => {}) {
  for (const name of channels) {
    const path = SEND[name];

    if (path === undefined) {
      throw new Error(`неизвестный канал «${name}»`);
    }

    await ctx.post(path, {});
    say(`канал ${name} издан`);
  }
}

/**
 * Ждать, пока названные каналы сойдутся. `ok` и `no_effect` -- доехало;
 * `failed` и `broken` -- отказ, ждать бессмысленно.
 */
export async function converge(ctx, channels, { timeoutMs = 90_000, say = () => {} } = {}) {
  const started = Date.now();
  const left = new Set(channels);
  let last = {};

  while (Date.now() - started < timeoutMs) {
    const snap = await ctx.get("/convergence");

    for (const id of [...left]) {
      const row = (snap.channels ?? []).find((c) => c.id === id);

      if (row === undefined) {
        throw new Error(`канала ${id} нет в снимке сходимости`);
      }

      last[id] = row.state;

      if (row.state === "ok" || row.state === "no_effect" || row.state === "nobody") {
        left.delete(id);
        say(`канал ${id}: ${row.state}`);
        continue;
      }

      if (row.state === "failed" || row.state === "broken") {
        throw new Error(`канал ${id}: ${row.state} ${JSON.stringify(row.draft?.errors ?? "").slice(0, 600)}`);
      }
    }

    if (left.size === 0) {
      return last;
    }

    await new Promise((r) => setTimeout(r, 1000));
  }

  throw new Error(`не сошлись за ${timeoutMs} мс: ${JSON.stringify(last)}`);
}
