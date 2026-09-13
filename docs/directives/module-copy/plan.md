# план: list/ → модуль, агент, компилятор, тесты

Источник: `docs/directives/list/`. Расходится с кодом — правим код.
Примеры: `docs/directives/examples/{1-api,2-routes,3-local}.conf`.
Не в этом круге: audit, transform, encrypt, кадры, `waf_status`, страница `waf_local_rate`.

---

# 0. разрыв

Модуль ещё на старых именах и без обязательной фазы.

| list/ | модуль сейчас |
| --- | --- |
| `waf_inspect request <name> wave=` | `waf_inspect <name> wave=` , `phase=` ещё жив |
| `waf_inspect request none` | `waf_inspect none` — все фазы сразу |
| `waf_deadline request 50ms block` | `waf_deadline 50ms` + `waf_response_deadline` |
| `waf_on_* request pass` | без фазы |
| `waf_deny_mode` / `waf_score_deny` + фаза | без фазы + `waf_response_score_deny` |
| `waf_capture request headers mask=` | набор с `request`, списки — без фазы |
| `waf_archive` / `waf_preview` + фаза | archive почти, preview без фазы |
| `waf_local_dataset … active\|internal` `limit=` `ttl=` | `uuid=` `max=` `live_max=`, слот по uuid |
| `waf_local_check … action=wave` | только `block` / `allow` |
| `response`/`frame` на снимке | часть парсится, `-t` не везде |

Компилятор печатает старый текст: `waf_inspect modsec wave=0`, `waf_deadline 200ms`, `waf_inspect none`, `uuid=` / `max=` у датасета, `phase=response`.
Контроллер хранит плоско: `deadlineMs`, `onAbsent`, `LocalCheck.action` без `wave`.

Агент уже пишет archive/preview из обменника. Не знает фазу в ключе, не знает `reload` как «оригинал шире capture», датасеты ищет по uuid.

---

# 1. модуль

Файлы: `nginx/module/src/ngx_http_waf_module.c`, `core/ngx_http_waf_directives.c`, `core/ngx_http_waf_conf.c`, `ngx_http_waf.h`, runtime, `local/`.

## 1.1 фаза — первое слово

Один разборщик фазы: `request|response|frame`. Нет слова — `nginx -t`.
`phase=` на любой из этих директив — `-t`.

Снять (оставить заглушку «снято»):

```
waf_request_inspect / waf_response_inspect / waf_frame_inspect
waf_request_deadline / waf_response_deadline / waf_on_timeout / waf_on_body_oversize
waf_request_deny_mode / waf_response_deny_mode
waf_request_score_deny / waf_response_score_deny
waf_request_inspectors / waf_response_inspectors / waf_inspector_mode / …
waf_request_archive / waf_body_archive / waf_headers_preview / …
```

Хелп в `ngx_http_waf_module.c` — как в list/.

## 1.2 loc_conf на три фазы

В `wlcf` три слота (`request` / `response` / `frame`), не плоские поля.

| группа | merge | нет своей строки |
| --- | --- | --- |
| inspect | набор **своей** фазы целиком | родитель этой фазы. нет фазы — фаза не бежит |
| capture / archive / preview | объект своей фазы | родитель этой фазы. нет `response`/`frame` — пусто |
| deadline, on_*, deny_mode, score_deny | своя фаза | нет `response`/`frame` — **как request** |

`waf_inspect request none` не трогает capture/archive/preview.
`response` / `frame` на capture/archive/preview — `-t`, пока фаз нет.
`waf_inspect response` / `frame` — парсить, фазу не запускать.

## 1.3 inspect

```
waf_inspect request|response|frame <name> wave=<n> [timeout=] [weight=] [mode=];
waf_inspect request|response|frame none;
```

- `wave=` обязателен
- повтор имени на одной фазе одного уровня — `-t`
- одно имя на request и response — две строки, ок
- `none` нельзя мешать с именами **той же** фазы
- `timeout=` пустой — `waf_deadline` этой фазы
- сумма timeout > deadline — режет deadline
- `mode=passive` не гейтит, дедлайн не двигает, счёт в тень
- winner `deterministic` — индекс `waf_inspector` в http, не порядок inspect

Runtime request уже есть. Response/frame — разбор + merge, handler позже.

## 1.4 бюджет и вердикт

```
waf_deadline <фаза> <time> [pass|block];
waf_on_absent|on_bus_error|on_body_unavailable <фаза> pass|block;
waf_deny_mode <фаза> fast|deterministic;
waf_score_deny <фаза> <n> [response=<name>];
```

Без фазы — `-t`. Умолчания как в deadline.md / verdict.md.
`response=` — страница каталога, не фаза.
Порог `0` — не режем. Набран на ранней волне — дальние не публикуем.

## 1.5 снимок

Capture/archive/preview: фаза обязательна и на наборе, и на `mask=` / `deny=` / `allow=` / `reload`.

- размер > `waf_body_limit` или `client_max_body_size` — `-t`
- archive/preview без `reload` шире capture — `-t`
- `reload <obj>=capture` без объекта в capture — `-t`
- `reload` шире capture — ок, в Redis оригинал, инспекторы не видят
- archive: нужны store + agent + inspect на маршруте
- preview: размер обязателен

Validate в `ngx_http_waf_conf.c` — по фазе, не глобально.

## 1.6 датасеты и local_check

Слот = **имя**, не uuid.

```
waf_local_dataset <name> type=cidr|string [limit=] [ttl=] active [subject=];
waf_local_dataset <name> type=cidr|string [limit=] internal;
waf_local_dataset <name> <entry> …;
```

- нет `active`/`internal` или оба — `-t`
- `active`: тема `waf.sets.<name>` (keeper), `subject=` — `-t`. entry в конфиге — `-t`
- `internal`: `subject=` / `ttl=` — `-t`. больше `limit=` — `-t`
- `uuid=` / `max=` / `live_max=` — `-t`
- `type=regex` — `-t`
- shm: ключ имя. снапшот/add/remove без uuid
- `waf_local_rate … list=` без ttl: ttl списка. нет ни там ни там — `-t`

```
waf_local_check … action=block|allow|wave
```

`wave` — остальные local (check + rate ниже) не смотрим, сразу `waf_inspect request`.
`response=` только у `block`.

## 1.7 селекторы и if

Сделано в модуле, [select.md](list/select.md). Не сделано за его пределами:

- компилятор `if` и `$waf_request_*` не печатает; модель маршрута их не хранит
- в UX нет ни условия на вызове инспектора, ни выбора объекта запроса
- агент не при чём: условие считается на краю, в сообщение не едет

## 1.8 контур без смены синтаксиса

Уже близко к list/. Проверить и не ломать:

- `waf on` без `waf_agent_socket` — `-t`
- инспекторы без `waf_bus` — `-t`
- один unnamed `waf_store`
- `waf_shm_zone` до local, min 256k
- bus `tls=` / `creds=` — `-t`
- deny: статус модуля, тело — `error_page` + `$waf_deny_name` / `$waf_ray`. `page=@` хранить, не редиректить
- cookie: force Secure/HttpOnly/SameSite, без Domain
- `waf_var` — в inspect JSON, не в local_check
- `waf_redirect_allow` пустой = редиректы запрещены

---

# 2. агент

Файлы: `nginx/agent/` — retain, handoff, conf, beat.

Модуль кладёт объекты в Redis. Агент их забирает. Фаза должна быть в ключе/мета, иначе request и будущий response смешаются.

## 2.1 обменник и reload

- ключ объекта: фаза + вид (`request`/`headers`, `request`/`body`, …)
- без `reload` — то, что видели инспекторы (после mask/deny)
- с `reload` — оригинал шире capture; агент не режет «как инспекторам»
- один объект — один get на max(capture, archive reload, preview reload)
- `when=allow|deny` — после вердикта, не раньше
- нет archive на маршруте — preview сам от capture, не от archive

## 2.2 preview → аудит

Срез в запись ClickHouse. Archive не обязателен.
`allow=` / `mask=` / `deny=` агент применяет к тому, что вынул, если модуль не применил сам (сейчас режет модуль — не дублировать).

## 2.3 датасеты с шины

Снапшот / add / remove / `.event` автобана — по **имени** слота и `subject`.
Поле `uuid` в сообщении снять. Контроллер шлёт то же.
`ttl=` overlay: нет своего ttl у add — ttl списка. нет ttl у списка — live нет.

## 2.4 не агент

Страницы отказа — nginx + SSI. Агент файлы `page=@` не отдаёт.
`waf_inspect none` агента не вызывает. Пустой capture — в Redis ничего, агенту нечего везти.

---

# 3. компилятор

Файлы: `controller/src/compile/nginx-emit.ts`, `nginx-http.ts`, `waf-directives.md`, `model/waf-route.ts`.

Печатать **только** текст list/. Компилятор не умнее модуля: что модуль не примет — не эмитить.

## 3.1 эмит

| было | стало |
| --- | --- |
| `waf_inspect modsec wave=0` | `waf_inspect request modsec wave=0` |
| `waf_inspect … phase=response` | `waf_inspect response …` |
| `waf_inspect none` | `waf_inspect request none` (и отдельно response, если ключ есть) |
| `waf_deadline 200ms pass` | `waf_deadline request 200ms pass` |
| `waf_response_deadline` | `waf_deadline response …` |
| `waf_on_absent pass` | `waf_on_absent request pass` |
| `waf_deny_mode fast` | `waf_deny_mode request fast` |
| `waf_score_deny` / `waf_response_score_deny` | `waf_score_deny request\|response` |
| `waf_capture headers mask=` | `waf_capture request headers mask=` |
| `waf_capture off` | `waf_capture request none` |
| `waf_archive` / `waf_preview` без фазы | первое слово `request` |
| `uuid=` `max=` `live_max=` | `active`/`internal` `limit=` `ttl=` |

`wave=` всегда. `response`/`frame` на снимке не печатать — модуль даст `-t`.
Не печатать снятое: `waf_bus_flush_interval`, `waf_protocol_versions`, allow_headers, body_access, audit* — пока нет страницы в list/.

Один `waf_store`. Несколько строк `body_stores` — ошибка компиляции, не эмит пачки.

## 3.2 модель

`WafRouteSettings` — либо три вложенных фазы, либо явные ключи с фазой в имени. Плоские `deadlineMs` / `onAbsent` читать как **request**, чтобы старый jsonb не молчал.

Минимум:

```
deadline.request / deadline.response     # иначе deadlineMs = request
onAbsent.request / …
denyMode.request / …
scoreDeny.request / …
inspect.request / inspect.response       # вместо requestInspectors + phase=
localChecks[].action = block|allow|wave
```

`InspectorRef.phase` снять: фаза = в каком списке стоит.
`LocalCheck.action` + `wave`. `response` только при `block` — ошибка компиляции иначе.

Датасет:

```
mode: active | internal
limit, ttl
                # темы у набора нет: waf.sets.<name> выводится из имени
entries[]    # только internal → отдельные строки waf_local_dataset <name> <entry>
```

`uuid=` не печатать. `in_nginx=false` по-прежнему не в nginx.
Тема набора = `waf.sets.<name>`, снапшот и хвост — запросом к keeper.

## 3.3 валидация компилятора

То, что модуль поймает на `-t`, компилятор ловит раньше (превью конфига):

- inspect без wave / неизвестное имя
- score `response=` не из каталога
- capture/archive/preview без фазы или шире limit
- archive без store/agent/inspect
- dataset без mode, entry на active, ttl на internal
- `waf on` без agent_socket; инспекторы без bus

---

# 4. контроллер

UX и API под ту же модель. Не два языка: jsonb = то, что уйдёт в эмит.

## 4.1 маршрут (WafProtect)

На сервере и пути, не на http (кроме реестра инспекторов и каталогов):

- фаза: request сейчас; response — поля есть, серые, «фаза не бежит»
- inspect: список вызовов + `none`. Отдельно от «снять снимок»
- `/static/`: два тумблера — `inspect request none` и `capture request none`
- deadline / on_* / deny_mode / score — карточка фазы
- local_check: `wave` в select; `response=` только при block
- redirect_allow / cookie_defaults как в list/

Наследование в UI: «нет ключа фазы» ≠ «none». Для deadline «нет response» = как request.

## 4.2 датасеты

- режим `active` / `internal`, не uuid в директиве
- active: состав в UX → событие keeper → дельта на `waf.sets.<name>` (без reload)
- internal: адреса в форме → строки в nginx, смена = reload
- `limit` / `ttl`; ttl только active
- `list=` у rate — только active с ttl (своим или списка)

Шина: сообщения без uuid, ключ = имя слота.

## 4.3 каталоги http

Реестр `waf_inspector` — порядок = deterministic. Не тасовать молча.
`waf_deny_response`: `page=@` в store, в nginx только имя + status.
Один store. shm_zone до local.

## 4.4 превью

`GET /config/preview` должен проходить `nginx -t` на собранном образе.
Золото: тексты как `examples/*.conf` (смысл, не байт-в-байт комментарии).

---

# 5. тесты

Слои снизу вверх. `#TEST` в list/ — спецификация, не комментарий.

## 5.1 nginx -t  (`nginx/tests/unit/`)

Один conf = один `#TEST` или тесно связанная пачка.
Имена как в list/: `inspect-no-phase.conf`, `deadline-bare.conf`, `dataset-no-mode.conf`.

**ломают загрузку**

- inspect / deadline / on_* / deny_mode / score / capture mask без фазы
- `phase=` , снятые имена (`waf_request_deadline`, `waf_on_timeout`, …)
- inspect без wave, unknown name, none + имя той же фазы
- score −1, `response=` нет в каталоге
- capture/archive/preview `response`/`frame`
- capture без фазы на `headers mask=`
- body / archive / preview > body_limit / client_max_body_size
- archive без reload шире capture; `reload =capture` без объекта
- archive без store / agent / inspect
- dataset: нет zone, нет mode, оба mode, uuid/max/live_max, entry на active, subject/ttl на internal, type=regex, повтор имени, overflow internal
- rate `list=` без ttl
- check `action=wave` + `response=`
- bus tls/creds, два store, waf on без socket

**принимают**

- `examples/1-api.conf`, `2-routes.conf`, `3-local.conf` — `nginx -t`
- `waf_inspect request none` при capture родителя
- `waf_score_deny response 80 response=suspicious` (фаза + страница)
- `waf_deadline response` без своей строки — merge как request (через два location в одном conf)
- dataset active без subject, internal + entries
- check `action=wave`

Обновить `local-layer.conf`: `active`/`internal`, `limit=`, без `subject=` если имя совпало, `max=` убрать.

## 5.2 runtime модуля

Пока нет `t/`. Когда появится (или load-стенд):

- волны: 1 не публикуется, пока 0 не ответила
- location свой request, серверный не действует; response не сброшен
- request none: волн нет, capture родителя кладёт
- request none + capture none: в Redis пусто
- passive deny: прошёл, в debug/аудите вердикт
- deadline 10ms vs timeout 15ms — режет deadline
- absent: сразу on_absent, дедлайн не ждём
- passive молчит — deadline не из-за него
- deadline pass + частичный набор — переопределения успевших
- score 0: сумма 200, прошёл, в аудите score
- порог 100 — deny, страница
- fast vs deterministic (порядок реестра)
- challenge wave 1: redirect может обогнать deny соседа
- local wave: нижестоящий block/rate не смотрим
- mask/deny: инспекторам хеш / нет пары
- reload body: в Redis шире, в сообщении инспекторам — capture

## 5.3 агент  (`nginx/agent/**/*_test.go`)

- объект без archive — не трогать
- reload vs capture: везём оригинал, не срез инспекторов
- preview без archive — от capture
- when=deny не пишем на allow
- снапшот датасета по имени, без uuid
- add без ttl → ttl списка; списка нет → отказ

## 5.4 компилятор  (`controller/src/compile/*.test.ts`)

Переписать ожидания под новый текст. Добавить:

- request/response inspect — две директивы, без `phase=`
- none → `waf_inspect request none`
- deadline/on_*/score с фазой
- capture mask с `request`
- dataset `active` + `limit=` + без uuid
- internal → слот + строки entry
- `in_nginx=false` нет в файле
- два store — ошибка
- check `action=wave`
- не печатаем снятое

`waf-directives.md` — таблица как в list/, колонка «печатает» = новый синтаксис.

## 5.5 контроллер API

- PUT waf: фазовые ключи кругятся, старый плоский `deadlineMs` ещё принимается как request
- dataset create: mode обязателен; internal+subject 400; active+entries 400
- preview конфига: снимок как examples (смысл директив)
- шина датасета: payload без uuid

---

# 6. порядок

Не параллелить смену синтаксиса и новые фазы.

1. **Парсеры + `-t` + unit confs.** Модуль принимает list/, старое ломает. Runtime request не менять, кроме обязательной фазы в conf.
2. **Merge/validate** трёх фаз. Response/frame в conf есть, handler request как был.
3. **Датасеты + wave.** shm/шина по имени. `local-layer.conf` и 3-local.
4. **Компилятор** печатает новый текст. Тесты compile зелёные. Превью проходит `-t`.
5. **Контроллер UX/API** под модель. Снапшоты датасетов без uuid.
6. **Агент:** ключ с фазой, reload, датасеты по имени.
7. **Runtime-тесты** волн / score / none+capture / reload. Потом response-фаза — отдельный круг.

Критерий круга 1–5: `nginx -t` на трёх examples и на всём `nginx/tests/unit/`. Компилятор не умеет напечатать то, что `-t` отвергнет.
)
