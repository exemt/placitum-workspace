# Сообщения при блокировке

Целевой каталог вынесен в [messages/](messages/README.md):
модуль → [инспекторы](messages/module-inspectors.md),
модуль → [агент](messages/module-agent.md).

Рабочий конспект: что сейчас уходит при локальном отказе, при отказе
инспектора и что агент кладёт в `WAF_AUDIT`. Отсюда перерабатываем конверт.
`rid` в reply-to волны не трогаем — это адрес слота, не id запроса.

`ray` — UUID v4 на каждый запрос (`getrandom` / urandom). Счётчик нельзя:
соседние значения палят RPS. Сквозным ключом обменника ещё не стал.

## Коды якоря (`code`)

Поле ставит **модуль** в дамп агенту. Это причина итогового `verdict`, не
строка инспектора и не имя списка. Закрытый набор, snake_case, стабилен
для фильтра в CH. Детали (какой список, какой rule) — в других полях:
`inspectors`, `score`, `vars`, позже `list` / `rule`.

| `code` | Кто решил | `local` | Когда |
| --- | --- | --- | --- |
| `local_list` | модуль | `true` | `waf_local_check` action=block |
| `local_rate` | модуль | `true` | `waf_local_rate` action=block |
| `inspector` | инспектор | `false` | решающий ответил `deny` или `redirect` |
| `score` | модуль | `false` | сумма ≥ `deny_at`, никто не сказал `deny` |
| `fail` | политика | `false` | волна сорвалась, отказ по политике `waf_deadline` / absent |

Сейчас в сокете вместо этого: имя набора, `LOCAL_RATE`, `SCORE_THRESHOLD`
или `reason.code` инспектора (`CRS_ANOMALY`). В целевом якоре этого нет.

`allow` кода не несёт — секции нет или пустая строка. `shadow` код не меняет:
тот же `inspector` / `score`, плюс флаг когда дойдём.

Инспекторский код причины живёт в `kind=inspector`, не дублируется в якоре;
номер правила и текст находки на провод ответа вообще не выходят. В
`inspectors` только вердикт волны.

```
локальный бан          инспекторский бан
─────────────          ─────────────────
модуль → сокет         модуль → waf.req.*  (+ reply-to с rid)
                       инспектор → inbox
                       инспектор → waf.audit.inspector.*
модуль → сокет         модуль → сокет
агент  → WAF_AUDIT     агент  → WAF_AUDIT
```

---

## 1. Локальная блокировка

Список (`waf_local_check`) или rate. Волны нет, слота нет, инспекторам ничего
не уходит. Автобан (`rate` + `list=` + `ttl=`) — отдельное событие keeper
(`waf.sets.<набор>.event`), не в аудит.

### Модуль → unix-сокет агента (цель)

`sendto` / `MSG_DONTWAIT` на `waf_agent_socket`. Без `v` / `kind` / `ts` —
их по-прежнему ставит агент. `rid` в теле нет.

```json
{
  "ray": "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
  "node": "nginx-1",
  "phase": "request",
  "client": {
    "ip": "203.0.113.77",
    "port": 54233
  },
  "inspectors": {},
  "verdict": "deny",
  "code": "local_list",
  "local": true,
  "vars": {
    "ua": "curl/8.5.0"
  },
  "request": {
    "http": {
      "method": "GET",
      "host": "shop.example.com",
      "uri": "/lists/",
      "status": 403
    },
    "headers": null,
    "cookies": null,
    "body": null
  },
  "waf_latency_us": 400
}
```

Rate вместо списка: `"code": "local_rate"`, `inspectors` тот же `{}`.
Имя набора / ключ rate в `code` не пишем.

`vars` — стандартный набор модуля и объявленные `waf_var`, непустые, значение
по-прежнему режется (сейчас 256 байт). Это не все заголовки и не весь запрос.

`request.http.status` — код, который модуль отдал клиенту, не upstream.

`headers` / `cookies` / `body` — указатели на обменник, не содержимое.
`cookies` всегда `null`: разобранных cookie нет, сырой `Cookie` внутри
headers-объекта. После волны `headers` и `body` — те же локаторы, что у
инспектора; локальный бан волны не открывал, оба `null`.

Чего в наброске не хватало, если якорь один и на инспектора:

- `score` — сумма и порог; без него отказ по score не отличить от `deny`
- кто решил и каким правилом — либо в `code`, либо отдельными полями
  (`inspector`, `rule`). Строка `code` удобна человеку, для фильтра в CH
  лучше парсить или дублировать полями
- `shadow` — иначе теневой отказ выглядит как настоящий
- `redirect` — при `verdict=redirect` нужен URL
- `fail` — волна сорвалась (timeout / absent), вердикт всё равно вынесли

Агент на шину: тот же объект плюс `"v": 1, "kind": "request", "ts": "…"`.
Публиковать, если есть `ray`, `node`, `verdict` — не `rid`.

### Агент → `waf.audit.request.<node>` (цель)

Копия сокета плюс конверт. Поля не перекладывает и не выкидывает.

```json
{
  "v": 1,
  "kind": "request",
  "ts": "2026-08-15T21:40:00.123Z",
  "ray": "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
  "node": "nginx-1",
  "phase": "request",
  "client": {
    "ip": "203.0.113.77",
    "port": 54233
  },
  "inspectors": {},
  "verdict": "deny",
  "code": "local_list",
  "local": true,
  "vars": {
    "ua": "curl/8.5.0"
  },
  "request": {
    "http": {
      "method": "GET",
      "host": "shop.example.com",
      "uri": "/lists/",
      "status": 403
    },
    "headers": null,
    "cookies": null,
    "body": null
  },
  "waf_latency_us": 400
}
```

Публиковать, если есть `ray`, `node`, `verdict`. Логгер под этот конверт
ещё не заточен: ключ обменника по-прежнему `(node, rid)`.

### Автобан (не аудит)

Только если rate создал запись в overlay. Модуль сам, не агент:

```
PUB waf.sets.<набор>.event
```

```json
{
  "v": 1,
  "dataset": "ratelimited",
  "uuid": "…",
  "op": "add",
  "value": "203.0.113.7",
  "ttl": 300,
  "origin": "nginx-1",
  "reason": "LOCAL_RATE",
  "ray": "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03"
}
```

Попадание в уже существующий список этого не шлёт.

---

## 2. Блокировка инспектором

Локальный слой пропустил. Модуль берёт слот, появляется настоящий `rid`,
публикует волну.

### Модуль → инспектор (как сейчас)

Это не дамп агенту. Отдельное сообщение на каждого инспектора волны.
Локальный бан сюда не доходит.

```
PUB waf.req.<имя>  _INBOX.waf.<node>.<pid>.<nonce>.v.<ray>.<ii>
```

Id запроса — `ray`. Им же модуль находит слот (карта `ray → слот`).
В JSON и в reply-to — только он. `rid` нигде в сообщениях нет.

Сейчас на проводе ещё не так: в subject и в теле волны торчит `rid` слота.
Это то, что выкидываем.

```json
{
  "v": 2,
  "ray": "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
  "phase": "request",
  "wave": 0,
  "inspector": "modsec",
  "deadline_ms": 20,
  "audit_subject": "waf.audit.inspector.modsec",
  "node": "nginx-1",
  "conn": {
    "client_ip": "203.0.113.77",
    "client_port": 54233,
    "server_ip": "10.0.0.8",
    "server_port": 8080,
    "tls": {
      "version": "TLSv1.3",
      "sni": "shop.example.com"
    }
  },
  "http": {
    "method": "POST",
    "scheme": "https",
    "host": "shop.example.com",
    "uri": "/api/orders",
    "args_size": 4,
    "version": "HTTP/1.1"
  },
  "vars": {
    "ua": "curl/8.5.0"
  },
  "needs": ["headers", "args"],
  "store": {
    "headers": {
      "store": "hot",
      "driver": "redis",
      "key": "nginx-1:480000013b000000:req:hdr",
      "size": 96
    },
    "args": {
      "store": "hot",
      "driver": "redis",
      "key": "nginx-1:480000013b000000:req:arg",
      "size": 4
    },
    "body": null
  },
  "route": {
    "server_name": "shop.example.com",
    "location": "/api/",
    "id": "6a0b6d6e-1c2d-4e3f-8a9b-0c1d2e3f4a5b",
    "profile": "default"
  },
  "score": {
    "total": 0,
    "deny_at": 100
  }
}
```

`tls` только на HTTPS. `args_size` нулевой, если query пустой, и тогда
`store.args` — `null`. `prior` на первой волне нет; на следующей — кто уже
ответил, кроме адресата:

```json
"prior": [
  { "inspector": "modsec", "verdict": "score", "score": 50 }
]
```

| Поле | Зачем |
| --- | --- |
| `v` | версия протокола волны, сейчас `2` |
| `ray` | id запроса; инспектор эхоит его в `kind=inspector` |
| `phase` | `request` / `response` / `frame` |
| `wave` | номер волны, с нуля |
| `inspector` | кому адресовано (тот же, что в subject) |
| `deadline_ms` | остаток бюджета фазы, не полный timeout инспектора |
| `audit_subject` | куда публиковать подробности; `null` — деталей не ждут |
| `node` | `waf_node_id` |
| `conn` | клиент после realip, локальный bind, опционально TLS |
| `http` | метод, scheme, host, uri без query, версия и `args_size` |
| `needs` | объекты `waf_capture` маршрута, одинаковые у всех инспекторов вызова |
| `store` | три локатора одной формы: `headers`, `args`, `body`; содержимого в сообщении нет |
| `vars` | поля по `vars=` объявления инспектора: стандартный набор модуля и `waf_var`, значение до 256 байт — тем же пределом, что в аудите; без `vars=` секции нет |
| `route.profile` | непрозрачная строка для инспектора, иначе `"default"` |
| `score` | уже накопленное и порог маршрута — чтобы не жечь дедлайн впустую |
| `prior` | вердикты предыдущих в этой фазе |

Содержимого запроса в сообщении нет вовсе. Типичный обменник, когда тело, заголовки
и строка запроса в Redis:

```json
"store": {
  "headers": { "size": 412, "store": "redis", "driver": "redis", "key": "nginx-1:48…:req:hdr" },
  "args":    { "size": 23,  "store": "redis", "driver": "redis", "key": "nginx-1:48…:req:arg" },
  "body": {
    "size": 4096,
    "sha256": "…",
    "complete": true,
    "truncated": false,
    "encoding": "identity",
    "store": "redis",
    "driver": "redis",
    "key": "nginx-1:48…:req",
    "expires_at": 1723753200
  }
}
```

`null` вместо локатора означает одно из трёх: инспектор не просил объект,
маршрут его не снимает, класть было нечего. Различать незачем — содержимого нет
во всех трёх случаях.

Это сообщение инспектор **читает**. В дамп агенту оно не копируется: там
только итог и карта `inspectors`.

### Инспектор → inbox

Тот же reply-to. Модуль сверяет `rid` в теле со слотом. В ответе только решение:

```json
{
  "v": 2,
  "rid": "480000013b000000",
  "inspector": "modsec",
  "verdict": "deny",
  "score": 50,
  "reason": { "code": "CRS_ANOMALY" }
}
```

Ни текста находки, ни номера правила, ни секции `audit` здесь нет: модуль их не
применял, а на горячем пути они раздували ответ. Всё это — в событии ниже.

### Инспектор → `waf.audit.inspector.<name>`

После inbox, fire-and-forget. Subject приезжает в `audit_subject` сообщения
волны, а не зашит в сервисе. Схема —
[messages/inspector-audit.schema.ts](messages/inspector-audit.schema.ts).

```json
{
  "v": 1,
  "kind": "inspector",
  "ts": "2026-08-15T21:40:00.120Z",
  "ray": "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
  "node": "nginx-1",
  "phase": "request",
  "inspector": "modsec",
  "profile": "default",
  "verdict": "deny",
  "engine_ms": 1.2,
  "findings": [
    { "code": "crs-913100", "severity": "critical", "target": "header:user-agent",
      "rule": "913100", "evidence": "sqlmap/1.7" }
  ],
  "engine": { "matched": [{ "id": 913100, "msg": "…" }] }
}
```

Логгер это не читает. Живой UX склеивает с якорем по `ray`.

### Модуль → unix-сокет агента (цель)

Тот же каркас, что у локального. `rid` в теле нет — слот живёт только в
reply-to волны.

Отказ инспектора (`verdict=deny` у решающего):

```json
{
  "ray": "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
  "node": "nginx-1",
  "phase": "request",
  "client": {
    "ip": "203.0.113.77",
    "port": 54233
  },
  "inspectors": {
    "modsec": "deny"
  },
  "verdict": "deny",
  "code": "inspector",
  "local": false,
  "vars": {
    "ua": "curl/8.5.0"
  },
  "request": {
    "http": {
      "method": "POST",
      "host": "shop.example.com",
      "uri": "/api/orders",
      "status": 403
    },
    "headers": null,
    "cookies": null,
    "body": null
  },
  "score": {
    "total": 50,
    "deny_at": 100
  },
  "waf_latency_us": 8300
}
```

Отказ по порогу (`by_score`): никто не сказал `deny`, сумма перешла `deny_at`.

```json
{
  "ray": "11d4ea9c-80b2-4c7e-9f01-6a5b4c3d2e10",
  "node": "nginx-1",
  "phase": "request",
  "client": {
    "ip": "203.0.113.77",
    "port": 54233
  },
  "inspectors": {
    "modsec": "score",
    "probe": "score"
  },
  "verdict": "deny",
  "code": "score",
  "local": false,
  "vars": {
    "ua": "curl/8.5.0"
  },
  "request": {
    "http": {
      "method": "POST",
      "host": "shop.example.com",
      "uri": "/api/orders",
      "status": 403
    },
    "headers": null,
    "cookies": null,
    "body": null
  },
  "score": {
    "total": 80,
    "deny_at": 50,
    "by": {
      "modsec": 50,
      "probe": 30
    }
  },
  "waf_latency_us": 9100
}
```

`inspectors` — карта имя → вердикт волны (`allow` / `deny` / `score` /
`redirect`). Пустая `{}` значит «волну не звали», не «все allow».

`score.by` — вклады инспекторов; на локальном бане секции `score` нет.
`code` — токен из таблицы выше, не rule и не имя инспектора. Кто сказал
`deny`, видно по `"inspectors": { "modsec": "deny" }`.

---

## 3. Агент → шина логов

Один subject, один вид. Модуль отдал итог в сокет — агент публикует, если
есть `ray`, `node`, `verdict`.

```
PUB waf.audit.request.<node>
поток WAF_AUDIT, subject waf.audit.>
```

| Поле | Кто |
| --- | --- |
| `v` | агент, всегда `1` |
| `kind` | агент, всегда `request` |
| `ts` | агент, UTC milli в момент `PUB` |
| всё остальное | как пришло с сокета |

Локальный якорь — §1. Инспекторский `deny` на шине:

```json
{
  "v": 1,
  "kind": "request",
  "ts": "2026-08-15T21:40:00.123Z",
  "ray": "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
  "node": "nginx-1",
  "phase": "request",
  "client": {
    "ip": "203.0.113.77",
    "port": 54233
  },
  "inspectors": {
    "modsec": "deny"
  },
  "verdict": "deny",
  "code": "inspector",
  "local": false,
  "vars": {
    "ua": "curl/8.5.0"
  },
  "request": {
    "http": {
      "method": "POST",
      "host": "shop.example.com",
      "uri": "/api/orders",
      "status": 403
    },
    "headers": null,
    "cookies": null,
    "body": null
  },
  "score": {
    "total": 50,
    "deny_at": 100
  },
  "waf_latency_us": 8300
}
```

Порог — тот же конверт с `"code": "score"` из §2. Логгер этот конверт
пока не читает.

---

## Что перерабатываем

Цель: `ray` — id запроса во всех JSON. `rid` остаётся только в reply-to слота.

Сейчас мешает:

1. Логгер и `waf.audit` ключ `(node, rid)` — локальные баны затираются.
2. Инспектор требует `rid` в теле и эхоит его в inbox.
3. `by_local` / `deny_code` обменник не хранит.

`kind=inspector` уже склеивается по `ray`: модуль шлёт его в сообщении волны,
инспектор эхоит в событии.

Порядок: ключ обменника и эхо `ray` у инспекторов, потом вычищать `rid` из тел.
Reply-to не менять.
