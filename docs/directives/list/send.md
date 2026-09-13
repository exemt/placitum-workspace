# waf_send

Откуда отдать объект получателю: как пришёл или версию инспектора из
обменника. Четвёртая ось таблицы снимка после [capture](capture.md),
[preview](preview.md) и [archive](archive.md): те же фазы, тот же
словарь объектов, строки одного уровня складываются по объекту.

Получатель у каждой фазы свой: апстрим на `request`, клиент на
`response`, вторая сторона на `frame`. Модуль → обменник → инспекторы →
что отдать и откуда: одна логика на три фазы.

```
waf_send <фаза> <headers|args|body>=original|store ...;

<фаза> = request | response | frame | frame:c2s | frame:s2c
```

Контекст: `http`, `server`, `location`, наследуемая.  
Умолчание: **`store` у всех объектов на всех фазах** — подмена, которую
инспектор уже сделал, обязана доехать до получателя. Оригинал отдаётся,
когда его назвал оператор, и только тогда. Нет строки `response` /
`frame` — **не** берёт `request`: словари объектов у фаз разные.

До 10.09.2026 умолчание тела зависело от снимка: срез (`body=<size>`)
молча означал `original`, и подмена пропадала даже на объекте, который в
срез уложился целиком, — инспектор рапортовал об успехе, в записи стояло
`applied:false`, а маршрут выглядел настроенным. Проверка «кусок вместо
целого не отдаём» осталась, но там, где ей место: в рантайме и по факту
(`truncated` у локатора), а не по догадке из конфигурации.

# источники

| значение | что уходит |
| --- | --- |
| `original` | как пришёл. Правка инспектора, если была, не поднимается; в записи `rewrite.applied:false`, в логе INFO |
| `store` | версия инспектора из обменника (в панели — «с правками»): последняя, которую положили и назвали секцией `rewrite` реплая. Правки соседних волн складываются цепочкой — получателю уходит последнее звено, две секции `rewrite` на одной волне — сбой класса `body` ([правила](#правила)). Никто не положил — оригинал, GET в обменник не ходит |

У заголовков и строки запроса «с правками» это склейка по имени:
`set`/`unset` секций `headers` и `args` реплая ложатся поверх оригинала,
нетронутое имя, имя за срезом и под маской остаются как были, через
обменник эти объекты не ходят
([verdict-protocol.md](../../verdict-protocol.md#секция-args)). Тело
непрозрачно — оно заменяется целиком объектом обменника (`rewrite.body`
реплая, [verdict-protocol.md](../../verdict-protocol.md#секция-rewrite)).

# неполный снимок

`original` отдаёт оригинал всегда. `store` отдаёт версию инспектора,
когда снимок объекта полон: срез `waf_capture … body=64k` при теле
в 50k — снимок целый, локатор без `truncated`, объект поднимается.
Тело шире среза (локатор `truncated`, у кадра — срез кадра) инспектор
видел как префикс, и заменить целое куском значит сломать нагрузку. Опции «отдать кусок» нет
ни на одной фазе: **это сбой подъёма**, наравне с пропавшим ключом или
несошедшимся хешем, и исход решает [политика фазы](#сбой-подъёма) — отказ
(код `REWRITE_FAILED`, страница у HTTP, Close у кадров) либо оригинал. В записи `rewrite.applied:false, partial:true`, в логе WARN
«rewrite … failed (the capture is a prefix …)»: молчаливого оригинала
больше нет, кривая раскладка среза и отдачи видна по журналу. Заголовков
и строки запроса это не касается — их правки ложатся по имени поверх
оригинала.

Раскладка «срез + `store`» видна ещё на `nginx -t`: предупреждение на
каждый маршрут, где объект **явной строкой** отдаётся из обменника при
срезе снимка. На подставленном умолчании его нет: `store` теперь стоит
всюду, и предупреждение на каждый срез было бы шумом — в том числе на
маршрутах, где никто ничего не подменяет. Панель показывает то же
предупреждение в ячейке оси.

`waf_on_partial_rewrite` снята: кусок не отдаётся, а что делать с
неполным снимком, говорит политика фазы.

# сбой подъёма

Подъём сорвался: снимок взял только префикс объекта, ключа нет, размер
или хеш не сошлись, объект больше `waf_body_limit` фазы, ответ сжат
апстримом.

Своего рычага у директивы на это нет. Несостоявшаяся подмена — ошибка
обработки запроса, и решает её та же политика, что распоряжается всякой
недоступностью объекта обменника: `waf_exception <фаза> body`
([deadline.md](deadline.md)). `block` (умолчание) — отказ, `pass` —
оригинал с WARN. Реплай инспектора исход не переопределяет: `on_error` и
`response` в секции `rewrite` сняты вместе с одноимёнными опциями здесь.

Страница — умолчание маршрута ([deny_default.md](deny_default.md)); форма
отказа по протоколу: страница у HTTP, Close-кадр у WebSocket.

```nginx
waf_deny_response rewrite_failed status=502 page=@waf_deny;

waf_inspector mask subject=waf.req.mask;
waf_inspector dlp  subject=waf.rsp.dlp;

location /api/ {
    # запрос: тело из обменника, заголовки и строка как пришли
    waf_capture request headers args body;
    waf_inspect request mask wave=0 timeout=20ms;
    waf_send    request headers=original args=original body=store;

    # сбой подъёма -- отказ: умолчание класса body
    waf_exception request body deny;

    # ответ: заголовки правятся, тело уходит как отдал апстрим
    waf_capture response headers body=10k;
    waf_inspect response dlp wave=0 timeout=100ms;
    waf_send    response headers=store body=original;
}

location /ws/ {
    waf_capture frame body;
    waf_inspect frame ws_rw wave=0 timeout=100ms;
    waf_send    frame body=store;
    waf_exception frame body pass;               # сбой — кадр как пришёл
}
```

# с записью и архивом

Три версии объекта — снятое (что видели инспекторы), оригинал
(`reload`) и отданное — расходятся намеренно. Запись показывает снятое,
`reload` — оригинал, `source=sent` — отданное
([preview.md](preview.md#sourcesent--что-показать-при-подмене)); архив
хранит снятое или оригинал. `waf_send` на них не влияет: он говорит
только, что получил получатель, а расхождение помечено в записи секцией
`rewrite` у автора правки.

# правила

- нет фазы — `nginx -t`. объект не из словаря фазы (`response args`,
  `frame headers`) — `nginx -t`
- значение только `original` | `store`
- `<obj>=store` без `waf_capture <фаза> <obj>` — `nginx -t`: поднимать
  нечего
- `args=store` при `waf_capture … args mask=` / `deny=` — допустимо:
  правки ложатся по имени поверх оригинала, замаскированное имя можно
  снять или заменить
- `body=store` (и `frame body=store`) при срезе
  `waf_capture … =<size>` — допустимо, `nginx -t` предупреждает: объект в срезе поднимется, объект шире среза
  — сбой подъёма по `waf_exception … body`. Предупреждение бывает только
  у **явного** `store`: умолчание теперь тоже `store`, и на подставленном
  оно кричало бы на каждый срез
- один объект одной фазы на уровне называется один раз; `frame` занимает
  оба слота, `frame:c2s` рядом — `nginx -t`
- `store` при `waf_hold … monitor` не подменяет: отпущенный ответ уже у
  клиента, объект не поднимается, WARN в лог ([hold.md](hold.md))
- две секции `rewrite` на одной волне — сбой класса `body`
  ([waf_exception](deadline.md#waf_exception)), а не выбор победителя
- `response=` на несуществующую запись — `nginx -t`
- `waf_on_partial_rewrite` — `nginx -t` с подсказкой на `waf_send`

#TEST waf_send без фазы — nginx -t
#TEST waf_send response body=maybe — nginx -t
#TEST waf_send frame headers=store — nginx -t
#TEST waf_send request body=store без waf_capture request body — nginx -t
#TEST waf_send request args=store при waf_capture request args mask=token — nginx -t проходит
#TEST waf_send frame body=store и frame:c2s body=original на одном уровне — nginx -t
#TEST waf_send response response=nosuch — nginx -t
#TEST waf_on_partial_rewrite response store — nginx -t
#TEST request body=store, capture body целиком, rewrite.body: апстрим получил объект обменника, Content-Length переписан, applied:true
#TEST request body=store, capture body=10k, тело 200k, rewrite.body: сбой подъёма — отказ REWRITE_FAILED по умолчанию реплая, applied:false partial:true, WARN в логе
#TEST request body=store, capture body=64k, тело 50k, rewrite.body: снимок целый, апстрим получил объект обменника, applied:true
#TEST request body=original, rewrite.body: апстрим получил оригинал, applied:false, INFO в логе
#TEST request args=store, секция args {set,unset}: апстрим получил строку с правками по именам, $args новый, rewrite.args.applied:true
#TEST request args=original, секция args: строка как пришла, applied:false, INFO в логе
#TEST request headers=original, headers.set в реплае: апстрим получил заголовки как пришли
#TEST response body=original: клиент получил ответ апстрима, applied:false
#TEST response body=store, capture body=10k, ответ 200k: сбой подъёма, отказ страницей умолчания, partial:true; waf_exception response body pass — оригинал
#TEST response body=store, ключа нет, waf_exception response body deny: отказ страницей умолчания маршрута
#TEST waf_send response on_error=deny — nginx -t: unknown option
#TEST frame body=store, capture frame body=10k на кадре 200k: сбой подъёма, Close 1008 REWRITE_FAILED по waf_exception frame body, partial:true
#TEST waf_send response body=store при waf_capture response body=10k — nginx -t проходит с WARN
#TEST waf_capture response body=10k без waf_send — тихо на nginx -t: предупреждение только у явного store
#TEST waf_capture response body=10k без waf_send, ответ 4k с rewrite.body: клиент получил объект инспектора — умолчание store, снимок полон
#TEST waf_capture response body без waf_send, rewrite.body: клиент получил объект инспектора — умолчание store
#TEST две волны с rewrite: вторая читает объект первой, клиент получил версию второй
#TEST frame body=original: кадр как пришёл, INFO в логе
