# план: фаза ответа и кадры

Круг 1 — [plan.md](plan.md): фаза первым словом в конфиге, рантайм только
`request`. Этот круг — сами фазы: язык кадров, протокол обеих сторон,
рантайм ответа, инспектор на фазах 3–4.

Источник языка — `list/`. Модель — [streaming.md](../streaming.md),
[modsecurity-inspector.md](../research/modsecurity-inspector.md),
[verdict-protocol.md](../verdict-protocol.md). Расходится с кодом — правим код.
Расходится между собой — правим тот документ, который здесь назван.

---

# 0. разрыв

| | сейчас |
| --- | --- |
| `waf_capture response` | `nginx -t`, «phase is not implemented yet» |
| `waf_inspect response` | разбирается, слот есть, никто не бежит |
| фильтры | не подключены, в `ngx_http_waf_module.c` маркер «этап 7» |
| `ctx` | накопитель на фазу (`phases[NPHASE]`, текущий -- `ctx->ph`) |
| `capture` / `archive` / `preview` в `wlcf` | по фазе (`shoot[NPHASE]`), рантайм читает слот `ctx->phase` |
| кадры | четыре слота фазы, `frame:c2s` / `frame:s2c` разбираются |
| кадры в языке | [streaming.md](../streaming.md): `waf_frame_inspectors_c2s`, `waf_frame_mode`, `waf_frame_deadline` — словарь до правила «фаза первым словом» |
| сообщение фазы ответа | в [verdict-protocol.md](../verdict-protocol.md) заголовки ответа инлайном, контекста запроса в обменнике нет |
| modsec | сделано и проверено на живом Coraza: липкая транзакция (`ApplyKeep` + `Resume`), откат через `ApplyResponse`, один набор `profiles/http/*` на фазы 1–5, исходящий счёт считается |

---

# 1. язык

Ничего нового там, где хватает фазового слова. Своё имя — только у механики
протокола, которая к фазам отношения не имеет.

## 1.1 направление кадра — часть первого слова

```
request | response | frame | frame:c2s | frame:s2c
```

`frame` без суффикса — обе стороны одной строкой. Внутри четыре слота:
`NGX_HTTP_WAF_NPHASE` = 4. На проводе `phase: "frame"`, направление — в
`stream.direction`: у инспектора одна форма сообщения, а не две фазы.

Так пишутся все фазовые семьи: `waf_inspect`, `waf_deadline`, `waf_on_*`,
`waf_deny_mode`, `waf_score_deny`, `waf_capture`, `waf_archive`,
`waf_preview`, `waf_body_limit`, `waf_hold`.

## 1.2 waf_hold — держим или смотрим вслед

`waf_frame_mode gate|monitor` из streaming.md — не про кадры, а про фазу:

```
waf_hold request|response|frame[:dir] gate|monitor;
```

Умолчание `gate`. `waf_hold request monitor` — `nginx -t`: наблюдение без
гейта на запросе — это `mode=passive` у инспектора, а не отпущенный запрос.

## 1.3 словарь объектов по фазам

| фаза | объекты |
| --- | --- |
| `request` | `headers` `args` `body` |
| `response` | `headers` `body` |
| `frame[:dir]` | `body` — полезная нагрузка кадра, при `waf_frame_reassemble on` собранного сообщения |

`args` на `response` / `frame`, `headers` на `frame` — `nginx -t`. Третьего
словаря не заводим: `body` у кадра — тот же объект обменника и то же `store.body`
в сообщении.

## 1.4 waf_body_limit получает фазу

```
waf_body_limit request|response|frame[:dir] <size> [block|trim|pass];
```

Закрывает `waf_frame_max_size` и `waf_message_max` из streaming.md. Сверка с
`client_max_body_size` — только на `request`: у ответа и у кадра такого
потолка нет. Нет строки фазы — берёт `request`, как дедлайн.

## 1.5 keep= и resume= на вызове

```
waf_inspect request           <name> wave=<n> [keep=on|off];
waf_inspect response|frame[:dir] <name> wave=<n> [resume=off|prefer|require];
```

`keep=on` — фаза запроса держит состояние после ответа (инспектору едет
`resume.want`). `resume=`: `off` — умолчание, инспектор инициализируется
заново; `prefer` — публикуем в личный subject экземпляра, на 503 no-responders
сразу перепубликация в групповой, без состояния переигрываем; `require` — без
отката, 503 → `waf_exception … absent` этой фазы, без состояния инспектор отказывает.
`resume=` на `request` и `keep=` на потребляющей фазе — `nginx -t`; пара без
второй половины на эффективном маршруте — `nginx -t`.

## 1.6 механика протокола — свои имена

Не обобщается, потому что это RFC 6455 и HTTP, а не политика фазы.

```
waf_frame_reassemble on|off;
waf_frame_control_rate <rate>;
waf_frame_sample <fraction>;
waf_ws_strip_extensions <name>,...;
waf_strip_accept_encoding on|off;
```

`waf_strip_accept_encoding` — та же мысль, что снятие `permessage-deflate`:
не согласовывать то, что придётся распаковывать в воркере. Умолчание `on`
там, где маршрут снимает тело ответа.

## 1.7 архив и превью на ответе

Объекты те же, что у снимка фазы: заголовки и тело ответа. Строка запроса на
этой фазе не архивируется и не срезается — она объект фазы запроса и уезжает
в свою запись, связанную тем же `ray`.

**Исход один на маршрут.** `when=deny` у архива фазы запроса срабатывает и
тогда, когда отказала фаза ответа: запрос-улика нужен ровно в этом случае.
Решение по `when=` откладывается до последней фазы, вынесшей исход; объекты
фазы запроса и так живут до конца фазы ответа ради `request_store`.

**`reload` шире capture на ответе — `nginx -t`.** У запроса тело прочитано
целиком и оригинал кладётся из готового буфера. У ответа держим ровно то, что
снимаем, и оригинал шире снимка означал бы поток в обменник параллельно отдаче
клиенту — потокового размещения (`CAP_STREAMING`) ещё нет. `reload
body=capture` работает.

**Что кладём в запись, кроме тела.** Одного тела мало: без `content-type`
неясно, что за байты, без `content-length` / `content-encoding` — префикс это
или всё и в каком виде. Статус и время апстрима приходят в запись сами, как
поля исхода. Отсюда рекомендация — узкий `allow=` на заголовках ответа вместо
широкого `deny=`.

**`set-cookie` маскируется по умолчанию** — зеркало встроенного списка
секретов запроса (`authorization`, `cookie`). Снимается только явным
`allow=set-cookie`.

**Бюджет датаграммы — на запись.** Записей столько, сколько фаз бежало, и
превью запроса с превью ответа не складываются в один потолок.

## 1.8 что закрывается существующим

| streaming.md | чем |
| --- | --- |
| `waf_frame_inspectors_c2s` | `waf_inspect frame:c2s` |
| `waf_frame_mode_c2s` | `waf_hold frame:c2s` |
| `waf_frame_deadline`, `waf_on_frame_timeout` | `waf_deadline frame[:dir]` |
| `waf_frame_score_deny` | `waf_score_deny frame[:dir]` |
| `waf_frame_max_size`, `waf_message_max` | `waf_body_limit frame[:dir]` |
| `waf_frame_rate` | `waf_local_rate … count=frames` |
| `waf_frame_opcodes` | `waf_local_check … $waf_frame_opcode` |
| `waf_response_bypass` | `waf_inspect response none` плюс безусловный обход |
| `waf_response_buffer_max` | `waf_capture response body=` — держим ровно то, что снимаем |
| `waf_audit_frames` | круг аудита, не этот |

---

# 2. протокол

Аддитивно к `v: 2`: незнакомые поля игнорируются, сообщение фазы запроса не
меняется.

## 2.1 обе стороны в сообщении

```json
"response": { "status": 200, "upstream_ms": 34 },
"store":         { "headers": <заголовки ответа>, "args": null, "body": <тело ответа> },
"request_store": { "headers": <…>, "args": <…>, "body": <…> }
```

`store` — объекты **текущей** фазы, одно правило на все. Заголовки ответа —
объект обменника, а не инлайн: иначе `mask=` / `deny=` мимо `set-cookie`.
Правку внести в [verdict-protocol.md](../verdict-protocol.md).

## 2.2 prior пересекает фазу

В элемент `prior` добавляется `phase`. Фаза ответа видит вердикты фазы
запроса и сеет из них инбаунд-счёт, оставаясь stateless.

## 2.3 continue / resume

Вердикт фазы запроса:

```json
"continue": { "subject": "waf.req.modsec.i.7f3a91", "ttl_ms": 30000 }
```

Сообщение фазы ответа при `resume=prefer|require`: тот же JSON, другой
subject (личный, пока продолжение живо, иначе групповой), плюс
`"resume": { "token": …, "require": bool }`.

Инвариант: **липкость — оптимизация, а не канал данных**. Сообщение
одинаково с продолжением и без; инспектор с вытесненной транзакцией отвечает
тем же вердиктом меньшей полноты, а не ошибкой. Отсюда право включать
`resume=` позже и выключать в любой момент.

## 2.4 кадр остаётся при rid

`rid` — индекс слота воркера и поколение, то есть транспортная корреляция, а
не идентичность запроса. Кадр берёт обычный слот: маршрутизация вердиктов,
breaker, дедлайны и аудит работают без второй таблицы ожидания. `conn_id` и
`seq` едут в сообщении как идентичность для инспектора. Правка в
[streaming.md](../streaming.md).

## 2.5 контекст рукопожатия — не копия в каждом кадре

После апгрейда `ngx_http_request_t` жив, значит `conn`, `http` и
`request_store` фазы кадра заполняются из него так же, как на фазе запроса.
Секция `handshake` из streaming.md не нужна; заодно работают `waf_var`,
`waf_local_check` и переменные nginx. Цена — `waf_store ttl=` обязан
покрывать жизнь соединения, иначе объекты рукопожатия станут `unavailable`.

---

# 3. модуль: конфигурация

Файлы: `ngx_http_waf.h`, `core/ngx_http_waf_directives.c`,
`core/ngx_http_waf_conf.c`, `ngx_http_waf_module.c`.

- `NGX_HTTP_WAF_NPHASE` 4, слоты `REQUEST` / `RESPONSE` / `FRAME_C2S` /
  `FRAME_S2C`; `ngx_http_waf_arg_phase()` понимает `frame:dir`, `frame`
  раскладывается в два слота
- `capture` / `archive` / `preview` в `wlcf` — по фазе: набор, `_set`,
  `_cleared`, пределы, списки `mask=` / `deny=`, `reload`
- `waf_hold` — новая директива, `hold[NPHASE]`
- `waf_body_limit` — с фазой, `body_limit[NPHASE]`, политика по фазе
- `resume=` в `ngx_http_waf_binding_t`
- словарь объектов проверяется по фазе, а не глобально
- `phase_nyi` снимается по одной фазе за раз — ровно тогда, когда рантайм
  этой фазы появился. Принятая и не исполняемая директива хуже отсутствующей

Слияние — как в круге 1: набор своей фазы заменяется целиком; у `deadline`,
`on_*`, `deny_mode`, `score_deny`, `hold`, `body_limit` нет своей строки —
берётся `request`.

---

# 4. модуль: рантайм фазы ответа

## 4.1 разрез контекста

`ngx_http_waf_phase_ctx_t` — всё, что накапливает фаза: `wave`, `replies`,
`got`, `published`, `skipped`, `score`, `shadow`, `verdict`, `decisive`,
`code`, `fail_reason`, `deadline`, `locator`, `meta[]`, `store_blob[]`.
В `ctx` — сквозное: `rid`, `ray`, `vars`, `pairs[]`, `local_*`, `ph[NPHASE]`.
Аудит пишется на фазу, `ray` один.

## 4.2 точки подключения

`HEADER_FILTER` — статус и заголовки известны: обход, снимок
`waf_capture response headers`, старт волн без тела.
`BODY_FILTER` — накопление до `waf_capture response body=`, `put` в обменник,
волны с телом.

## 4.3 удержание = ровно то, что снимаем

Потолок памяти — размер снимка, отдельной директивы не нужно. Заголовки не
уходят в `ngx_http_next_header_filter` до вердикта; тело копируется в цепочку
контекста; всё, что за размером снимка, уходит потоком уже после вердикта.
`deny` — `ngx_http_filter_finalize_request()`, страница каталога.
Решение принимается в возобновлении, не в колбэке шины.

## 4.4 обход

`r != r->main`, `r->header_only`, 204/304, 101 (это фаза кадров), свои
страницы отказа и `error_page`, `X-Accel-Redirect`, `waf_inspect response
none`. `text/event-stream` при `gate` — деградация в `monitor` с записью в лог.

## 4.5 сжатие

Есть `waf_capture response body=` — снимаем `Accept-Encoding` в апстрим
(`waf_strip_accept_encoding on`). Выключено — тело уезжает с
`encoding: "gzip"`, инспектор вправе не смотреть.

## 4.6 обменник

Ключ объекта с фазой (`…:req:*`, `…:rsp:*`). Есть `waf_inspect response` —
`del` объектов запроса переезжает на конец фазы ответа, иначе восстанавливать
контекст будет не из чего.

---

# 5. инспекторы

## 5.0 инициализация CRS в профиле ответа

`Include @owasp_crs/REQUEST-901-INITIALIZATION.conf` обязателен и в профиле
фазы ответа — единственный файл `REQUEST-*`, который там нужен. Он ничего не
детектирует: выставляет уровни паранойи, веса severity и пороги, из которых
`RESPONSE-*` складывают счёт.

Без него правила ответной стороны срабатывают, но каждое прибавляет к счёту
нераскрытый макрос `%{tx.critical_anomaly_score}`: находки есть, счёт нулевой,
модуль ничего не узнаёт. Поймано интеграционным тестом
`internal/rules/response_phase_test.go` — на фейковой транзакции такое не
видно по построению.

## 5.1 modsec, уровень 0 — восстановление

`internal/engine/apply.go`: `ApplyResponse` — соединение, URI, заголовки
запроса, `ProcessRequestHeaders`, тело запроса если дали,
`ProcessRequestBody`, заголовки ответа, `ProcessResponseHeaders`,
`WriteResponseBody`, `ProcessResponseBody`, `ProcessLogging`. Интерфейс
`engine.Transaction` это уже умеет — методы есть и не вызываются.

Отчитывается каждая сторона за свои фазы (`matchedPhases`): вердикт запроса
несёт находки фаз 1–2, вердикт ответа — 3–4. Иначе одна находка считалась бы
дважды. Фаза 5 не отчитывается вовсе: её правила — сводка счёта.

Отдельного профиля у ответа нет: набор один на фазы 1–5, потому что транзакция
одна. Это же снимает `SecRuleRemoveById 980170` и синтетический
`x-waf-inbound-score` — оба были обходом отсутствующего состояния.

## 5.2 modsec, уровень 1 — липкий экземпляр

Сделано и стало основным путём. Карта `token → tx` (`internal/sticky`) с
потолком и сроком; изъятие из карты на время работы — `tx` не потокобезопасен.
Ключ свой, а не `rid`: rid кодирует слот ожидания модуля и берётся заново на
каждую волну, то есть у двух сообщений одного запроса он разный.

Закрывается транзакция по пяти событиям и только по ним: пришло продолжение,
фаза запроса отказала, истёк срок, кончился потолок, ушёл процесс. Курсор по
находкам — не отдельный механизм, а `matchedPhases`: в вердикт ответа идут
фазы 3–4.

Сайзинг: `held ≈ rps × upstream_p95`, `tx` держит буфер тела запроса. Потолок
по умолчанию — вчетверо больше глубины очереди, срок — 30 s
(`WAF_MODSEC_RESUME_MAX`, `WAF_MODSEC_RESUME_TTL`).

---

# 6. кадры: рантайм

Этап 12 роадмапа, здесь только язык и слоты. Что должно приехать вместе с
обработчиком апгрейда: слот на кадр в пределах `waf_max_inflight`, потолок
кадров в полёте на соединение, `waf_frame_sample` в `monitor`, формы отказа
по протоколам из [verdict-protocol.md](../verdict-protocol.md).

---

# 7. компилятор, контроллер, агент

- эмит: фаза первым словом у `waf_body_limit`, новые `waf_hold` и `resume=`,
  `frame:dir` — печатать только то, что модуль принимает сегодня
- модель маршрута: ключи фаз становятся четырьмя, а не двумя
- агент: ключ объекта с фазой, объекты запроса живут до конца фазы ответа
- аудит: две записи на запрос, один `ray`

---

# 8. тесты

`nginx/tests/unit/` — один conf на `#TEST` из `list/`.

**ломают загрузку:** `waf_body_limit` без фазы; `waf_hold request monitor`;
`waf_capture response args`; `waf_capture frame headers`; `resume=` на
`request`; `frame:xxx` как фаза; `waf_frame_inspectors_c2s` и прочие снятые;
`waf_capture` / `waf_inspect` на фазе, рантайма которой ещё нет.

**принимают:** `waf_hold response monitor`; `waf_capture response headers=32k
body=64k`; `waf_deadline frame 5ms block` на сервере и `waf_deadline frame:s2c
2ms pass` на location; `waf_inspect frame:c2s … wave=0`; `waf_score_deny
frame:c2s 80 response=ws_policy`; `waf_body_limit response 512k trim`.

Одна строка `frame` задаёт оба слота, поэтому `frame` и `frame:s2c` на одном
уровне — `nginx -t`: слот уже задан. Разные значения по направлениям пишутся
двумя строками или наследованием.

Рантайм фазы запроса — `nginx/tests/smoke` (без внешних зависимостей) и
`nginx/tests/bus` (NATS, Redis, поддельные инспекторы: волны, счёт, дедлайны,
`prior`). Вебсокет — `nginx/tests/ws`: рукопожатие через фазу запроса и кадры
в обе стороны; две его проверки сегодня фиксируют отсутствие покрытия после
`101` и станут приёмочными для этапа кадров. Ловушка, которую он поймал: маршрут с `return 204` не доходит до
ACCESS-фазы, то есть модуль на нём не вызывается вовсе, а `nginx -t` такой
конфиг принимает.

Рантайм фазы ответа — `nginx/tests/` поверх live-стенда: удержание, deny до
первого байта, обход, `monitor`, два аудита с одним `ray`.

---

# 9. порядок

1. ✅ **Язык.** `list/`: `hold.md`, `frame.md`, правки `inspect`, `capture`,
   `deadline`, `body_limit`, `verdict`, `archive`, `preview`, `list`.
   Правки `streaming.md` и `verdict-protocol.md`.
2. ✅ **Конфиг.** Четыре слота фазы, `frame:dir`, `waf_hold`, `waf_body_limit`
   с фазой, `resume=`, словарь объектов по фазе. `-t` тесты. Рантайм не
   трогаем: `response` и `frame` по-прежнему не бегут.
3. ✅ **Снимок по фазам.** `capture` / `archive` / `preview` в `wlcf` — по фазе.
   Рантайм фазы запроса читает свой слот, поведение не меняется.
4. ✅ **Разрез контекста.** `phases[NPHASE]` плюс указатель `ph` на текущий
   слот, волны по фазе (`waves[NPHASE]`), `logged` на фазу. Фаза запроса
   проверена дымовым прогоном `nginx/tests/smoke`.
5. ✅ **Фаза ответа: заголовки.** `HEADER_FILTER` и `BODY_FILTER`, обход, вход
   в фазу, волны, удержание ответа (`r->buffered`), возобновление по вердикту,
   `deny` через `ngx_http_filter_finalize_request`, `waf_hold response
   monitor`, отбрасывание `redirect`. Заголовки ответа едут инлайном
   (`set-cookie` не едет вовсе), контекст запроса — секцией `request_store`.
   Приёмка — `nginx/tests/bus`, включая настоящий modsec.
6. ✅ **Фаза ответа: снимок.** `waf_capture response headers|body` в обменник
   (`:rsp`, `:rsp:hdr`) и вместе с ним `mask=` / `deny=` вместо инлайна, волны
   с телом, снятие `Accept-Encoding` с возвратом клиентского значения до
   фильтра сжатия, archive и preview этой фазы. Проверка обменником объектов
   каждой фазы — своя: `waf_archive response` требует инспекторов фазы ответа
   и держит ключи `retain_ttl`. Приёмка — `nginx/tests/bus`: настоящий modsec
   отказывает утечке в теле по фазе 4, приёмник итогов видит две записи с
   одним `ray`, у записи фазы ответа — `headers_preview`, `body_preview` и
   `store.archive`.
7. ✅ **Протокол и modsec.** `request_store`, `prior[].phase`, секция
   `response`; инспектор доигрывает фазы 3–4 тем же набором правил.
   Проверено сквозняком: настоящий образ инспектора в `nginx/tests/bus`
   отказывает 500-му ответу по фазе 3 и утечке в теле по фазе 4 — тело он
   забирает из обменника по локатору шага 6.
8. ✅ **keep= / resume=.** Продолжение, личный subject, откат по no-responders.
   `keep=on` на строке запроса -- признак `resume.want` и ключ в сообщении
   фазы запроса, `continue` с subject и сроком в вердикте; `resume=` на
   строке ответа -- публикация поздней фазы в личный subject с тем же ключом
   и `require`, откат в групповой при `no_responders` и `prefer`. Ключ
   называет модуль (ray): rid у каждой фазы свой. Пара обязательна в обе
   стороны по листьям -- `nginx -t`. Приёмка -- `nginx/tests/bus`: маршрут с
   парой доигрывает транзакцию (`resumed=true`, вдвое меньше времени движка),
   соседний без неё переигрывает фазы 1–2, а на экземпляре без реестра
   `prefer` переигрывает и `require` отказывает (`MODSEC_RESUME_LOST`).
9. **Кадры.** Обработчик апгрейда, слоты, формы отказа.

Критерий шагов 2–3: `nginx -t` зелёный на `nginx/tests/unit/` и на трёх
`examples/*.conf`. Критерий шагов 5–6: заблокированный ответ не отдаёт
клиенту ни одного байта тела приложения.
