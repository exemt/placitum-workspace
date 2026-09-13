# Сообщения контура

| Куда | Писатель | Схема | Статус |
| --- | --- | --- | --- |
| Инспектор, `PUB waf.req.<имя>` | `nginx/module/src/codec/ngx_http_waf_msg_req.c` | [inspector.schema.json](inspector.schema.json) | снято с сериализатора, кроме `prior` — там договор, см. [inspector-actions.md](../inspector-actions.md) |
| Модуль, ответ в `reply-to` | инспектор | [inspector-module.md](inspector-module.md) | формы реплая по секциям, схема — структуры `Reply` инспекторов |
| Агент, unix dgram | `nginx/module/src/runtime/ngx_http_waf_audit.c` | [agent.schema.ts](agent.schema.ts) | снято с сериализатора |
| JetStream, `PUB waf.audit.inspector.<имя>` | инспектор | [inspector-audit.schema.ts](inspector-audit.schema.ts) | договор, реализации нет |
| JetStream, `PUB waf.log.<писатель>` | агент ноды и всякий процесс контура | [logger/logs.md](../logger/logs.md) | пачка строк журнала, `kind=log` |
| Шина, `PUB WAF_STATUS.<…>` | все сервисы контура | [fleet-pulse.md](fleet-pulse.md) | кадр есть, секции `io` ещё нет |

Словарь действий между инспекторами — глаголы, оси, допустимые пары и параметры с границами —
отдаётся ручкой `GET /api/actions`; реестр за ней —
[controller/src/model/actions.ts](../../controller/src/model/actions.ts), и он сверяется тестом с
`$defs/action` этой схемы. Панель берёт списки оттуда, а не из своего файла.

Рабочий конспект, из которого это выросло, —
[audit-messages.md](../audit-messages.md); его конверт (`local`,
`client: {ip}`, `inspectors` строками) отменён.

Локатор обменника — одна форма во всех трёх записях аудита: `{store, driver, key, size}` плюс, у
тела, `sha256` / `complete` / `truncated` / `encoding`. Находка — одна форма в
последнем: `{code, severity, target, rule?, confidence?, evidence?}`. Это и
есть смысл каталога: два разбора на весь контур вместо разбора на сообщение.

## Инспектор

`rid` 16 hex — слот, в reply-to и в теле. `ray` — UUID v4 запроса, ключ
склейки со всем остальным. Секции `response` модуль не пишет.

Содержимого запроса в сообщении нет: заголовки, строка запроса и тело едут
локаторами в секции `store`. Подробности — [module-inspectors.md](module-inspectors.md).

| Файл | Что |
| --- | --- |
| [inspector-wave0.json](examples/inspector-wave0.json) | первая волна, тела ещё нет |
| [inspector-wave1.json](examples/inspector-wave1.json) | есть `prior`, в `needs` только заголовки |
| [inspector-body-store.json](examples/inspector-body-store.json) | все три локатора |
| [inspector-body-meta.json](examples/inspector-body-meta.json) | `body=meta`: длина и хеш, адресации нет |
| [inspector-body-unavailable.json](examples/inspector-body-unavailable.json) | тело недоступно |

## Агент

`rid` в сокете нет. Что сделали — `verdict`, почему — `code`, кто — `by`,
ключ в карте `inspectors`. Итог модуля лежит в той же карте под ключом
`module`, форма записи одна на всех.

Единственный источник данных о запросе: `kind=inspector` описывает только
самого инспектора. Отсюда же адрес, маршрут, размеры, тайминги и локаторы
обменника. Подробности и примеры — [module-agent.md](module-agent.md).

Агент дописывает `v` и `kind` в начало записи и публикует её на
`waf.audit.request.<node>`. Разбирать сообщение в структуру и собирать заново
он не имеет права: это значило бы держать схему в двух местах и терять всё,
чего в структуре не оказалось.

Одно исключение — `store.archive`. Названные в нём объекты модуль оставил
жить, и владение их ключами перешло агенту: он перекладывает содержимое в
архив, вырезает из записи пролёт значения `"store"` и вставляет на его место
собранный заново — с архивными локаторами. Остальная запись при этом остаётся
байт в байт исходной.

## Подробности инспектора

`kind=inspector` публикует сам инспектор, на subject из `audit_subject`
сообщения модуля и **после** ответа в inbox: деталями отчёта дедлайн волны
двигать нельзя. Агент к этому потоку не прикасается — разбирать его ему незачем.

Ответ инспектора модулю деталей не содержит вовсе: `{verdict, score?,
reason:{code}?}` и переопределения — их формы в
[inspector-module.md](inspector-module.md). Всё, чем инспектор объясняет вердикт, живёт
здесь, в `findings[]` одной формы на всех — правило CRS у `modsec`, совпадение
списка у `ip`, класс уязвимости у `vlai`, нарушение контракта у `json`.

Ключевое поле — `target`: где именно нашли (`uri`, `args`, `body`,
`header:<имя>`, `cookie:<имя>`, при возможности со смещением). Ровно это нужно
логеру, чтобы подсветить место в запросе, и ровно этого нет больше нигде.

Склейка — по `ray`. Инвариант: `score` события совпадает с
`inspectors[<имя>].score` в `kind=request`.

## Пульс

Кадр присутствия на `WAF_STATUS.<…>` стоит в каталоге особняком: он не про
запрос и склейки по `ray` у него нет. Общего с аудитом у него ровно принцип —
темп работы описан одной формой на все сервисы, как здесь локатор и находка.
Разбор — [fleet-pulse.md](fleet-pulse.md).
