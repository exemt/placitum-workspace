# waf_preview

Бюджет и источник объекта на одном запросе может переопределить
любой спрошенный инспектор глаголом `audit` канала действий (`headers` / `args` / `body` с `limit` и
`source`); сумма бюджетов прижимается к тому же потолку датаграммы
([inspector-actions.md](../../inspector-actions.md#запись-и-архив)).

Срез в записи аудита (ClickHouse). Пишет агент. Наследует capture: объекты,
`mask=` / `deny=`. Своя строка перекрывает только названное.

Archive не обязателен. Нет archive — preview сам наследует capture.
Есть оба — два независимых переопределения от одного capture, не друг от друга.

Без `reload` объект не из capture или размер больше — `nginx -t`.
`reload` кладёт в Redis оригинал. Инспекторы его не видят.

```
reload body=capture   # тот же размер, что capture
reload body           # целиком
reload body=12k       # 12k
```

`=capture` — идентичный размер. Объекта нет в capture — `nginx -t`.
Без `=` или с размером больше capture — исключение.
Размер больше `waf_body_limit` или `client_max_body_size` — `nginx -t`.
То же для `reload body` / `body=2m`. Без `reload` агент режет срез
из того, что положил capture. Один объект — один put на `max` размеров reload.

```
waf_preview <фаза> <headers|args|body>=<size>[/<item>]|none ...;
waf_preview <фаза> none;
waf_preview <фаза> reload <headers|args|body>[=capture|<size>] ...;
waf_preview <фаза> headers|args allow=<name>,...;
waf_preview <фаза> headers|args mask=<name>,...;
waf_preview <фаза> headers|args deny=<name>,...;
waf_preview response|frame body=<size> source=sent|original;

<фаза> = request | response | frame | frame:c2s | frame:s2c
```

## source=sent — что показать при подмене

Инспектор может подменить тело (секция `rewrite`): у ответа и у
кадра тогда две версии — оригинал, что пришёл, и то, что ушло получателю. По
умолчанию (`source=original`) запись показывает **оригинал**, помечая
`rewritten`. `source=sent` кладёт в запись **доставленную** версию
(`body_preview`), а не оригинал, и добавляет к секции `body_preview_source:
"sent"`, чтобы оператор не принял одно за другое.

Оригинал при этом никуда не девается: он лежит в обменнике и уезжает в архив
(`waf_archive`). То есть запись = что доставили, архив = что пришло, и оператор
берёт нужное. Ось только у переписываемого тела — `response` и `frame`; на
`request` тело не подменяют, `source=` там — `nginx -t`.

```nginx
location /api {
    waf_capture response body=64k;
    waf_inspect response dlp wave=0;

    waf_preview response body=8k source=sent;   # в запись — отданное клиенту
    waf_archive response body ttl=30d;          # в архив — оригинал апстрима
}
```

Контекст: `http`, `server`, `location`, наследуемая.  
Умолчание: `off` у каждой фазы.

Без фазы — `nginx -t`. Наследует capture **той же фазы**, и словарь
объектов у каждой фазы свой ([capture.md](capture.md#объекты-по-фазам)).

Записей аудита столько, сколько фаз бежало, и бюджет датаграммы
считается на запись: превью запроса и превью ответа складываются
не друг с другом, а каждое со своим потолком.

`frame`: срез полезной нагрузки кадра, объект один — `body`. Ложится в
ту же `body_preview` записи кадра, что у тела запроса, и по ней же
ищется поперёк всех записей. Запись кадра пишется по `waf_audit_frames`
([frame.md](frame.md)): без записи нет и среза. Может быть **шире
снимка** — весь кадр в буфере, масок нет; потолок один, `waf_body_limit
frame`. `reload` у кадра нет: размер задаётся прямо
([archive.md](archive.md#на-фазе-кадров)).

Заголовки ответа в срезе — те же, что видит снимок: список `headers_out`
плюс `Content-Type` и длина, которые nginx держит отдельными полями.
Без них запись не объясняет, что за байты в `body_preview`.

Размер обязателен. `/item` — потолок пары, только у headers/args.

```nginx
client_max_body_size 1m;
waf_body_limit 1m block;

waf_capture request headers=64k args=64k;
waf_capture request headers mask=authorization,cookie;
waf_capture request args deny=session;

# archive нет — preview сам наследник capture
waf_preview request headers=30k/1k args=8k/1k;
waf_preview request reload headers=capture;
# оригинал headers, тот же 64k
waf_preview request reload body=12k;
# исключение: тела в capture нет, в Redis 12k оригинала, в записи префикс
# reload body=capture — nginx -t: в capture тела нет
# body=2m / reload body=2m — nginx -t: больше waf_body_limit / client_max_body_size
waf_preview request headers deny=x-api-key;
# в записи нет x-api-key
waf_preview request args deny=token;
# token в записи нет. session нет с capture
```

# с capture, без archive

Capture снимает. Preview режет срез в запись. Агент пишет ClickHouse.
В S3 ничего: archive `none`, ключи после записи удаляются.

- нет своей строки mask/deny — списки capture
- своя строка — переопределение, не дополнение
- без `reload` объект или размер шире capture — конфиг не грузится
- `reload <obj>=capture` — оригинал в размере capture
- `reload <obj>` — целиком. `=<size>` — столько. больше capture — исключение
- больше `waf_body_limit` или `client_max_body_size` — `nginx -t`
- инспекторам по-прежнему только capture

На этом примере:

1. Capture кладёт headers≤64k и args≤64k. Тела нет. Инспекторы тело не ждут.
2. Инспекторы: `authorization`/`cookie` — sha256, `session` нет, `body` — `null`.
3. `reload headers=capture` — оригинал 64k; `reload body=12k` — оригинал тела.
4. В записи: headers≤30k (пара ≤1k) без `x-api-key`, cookie — оригинал;
   args≤8k без `token`, `session` нет; body — первые 12k.
5. Срез есть на allow и на deny.

# с archive

Оба наследуют capture порознь. Разные `deny=` / `reload` — нормально.
Общий только снимок и один put оригинала на объект, если reload есть
хотя бы у одного.

# на фазе ответа

Тело — то, ради чего превью ответа заводят: инцидент утечки
разбирают по первым килобайтам ответа, а не по его размеру. Но
одного тела мало.

| в записи | зачем |
| --- | --- |
| `body=<size>` | что именно утекло. Префикс, как и на запросе |
| `headers=<size>/<item>` | `content-type` — без него неясно, что это за байты; `content-length` и `content-encoding` — префикс это или всё, и в каком виде |
| статус и время апстрима | приходят в запись сами, отдельной директивы не требуют: это поля исхода, а не срез |

Строка запроса на этой фазе не срезается: она объект фазы запроса
и попадает в свою запись, связанную тем же `ray`.

**`set-cookie` маскируется по умолчанию.** У запроса встроенный
список секретов закрывает `authorization` и `cookie`; на ответе его
зеркало — `set-cookie`, и снять маску можно только явной строкой
`waf_preview response headers allow=set-cookie`. Сессия в аудите —
это сессия, украденная у того, кто аудит читает.

**Узкий `allow=` дешевле широкого `deny=`.** Заголовков ответа
немного, и перечислить нужные короче, чем угадывать вредные:

```nginx
location /api/ {
    waf_capture response headers=8k body=64k;
    waf_preview response body=2k;
    waf_preview response headers=1k/256;
    waf_preview response headers allow=content-type,content-length,
                                     content-encoding,content-disposition;
}
```

**`reload` шире capture — `nginx -t`**, по той же причине, что у
архива ([archive.md](archive.md#на-фазе-ответа)): держим ровно то,
что снимаем, а потокового размещения ещё нет.

# правила

- нет фазы — `nginx -t`. `frame reload` — `nginx -t`; `frame headers` / `args` — `nginx -t`
- у кадра превью и архив могут быть шире снимка (буфер, масок нет), потолок — `waf_body_limit frame`
- `source=sent` (response/frame body): в записи доставленная версия подменённого тела, оригинал в архиве; помечается `body_preview_source: "sent"`. `source=` на request — `nginx -t`
- `reload` шире capture вне фазы запроса — `nginx -t`
- размер обязателен. `=none` — секция выкл. голое `none` — сброс набора
- `/item` — потолок пары (headers/args). тело — префикс, `/item` нет
- бюджет — байты записанного JSON
- `reload <obj>=capture` — размер capture. `reload <obj>` — целиком.
  `=<size>` — столько. `=capture` при объекте не в capture — `nginx -t`
- строки одного уровня складываются по объекту
- location без своей строки берёт родителя. своя строка перекрывает только
  названный объект
- размер больше `waf_body_limit` или `client_max_body_size` — `nginx -t`.
  больше capture — только с `reload`, эти два лимита всё равно нельзя
- `allow=` / `mask=` / `deny=`: нет строки — списки capture. запрет сильнее
- в сообщение инспекторам не добавляет

#TEST preview body без reload при capture без body — nginx -t
#TEST reload body=capture при capture без body — nginx -t
#TEST reload body=12k при capture без body: в записи 12k, у инспекторов null
#TEST headers=2m без reload при capture headers=64k — nginx -t
#TEST body=2m / reload body=2m при waf_body_limit 1m или client_max_body_size 1m — nginx -t
#TEST без archive: срез в ClickHouse есть, в S3 нет
#TEST без reload: cookie в записи — sha256
#TEST reload headers=capture: cookie в записи — оригинал, size как capture
#TEST deny=x-api-key: в ClickHouse нет, у инспекторов есть
#TEST session в записи нет (наследство capture)
#TEST waf_preview headers=30k без фазы — nginx -t
#TEST waf_preview response body=10k шире capture response — nginx -t
#TEST waf_preview response headers body при capture response — ок
#TEST waf_preview frame headers=1k — nginx -t
#TEST waf_preview frame reload body=capture — nginx -t
#TEST waf_preview frame body=16k при capture frame body=8k — ок (шире снимка), режется по waf_body_limit
#TEST waf_preview frame body=16k source=sent — ок; подменённый кадр: body_preview = доставленное, body_preview_source=sent, оригинал в архиве
#TEST waf_preview response body=8k source=sent при подмене тела ответа: в записи отданное клиенту, в архиве оригинал
#TEST waf_preview request body=8k source=sent — nginx -t (тело запроса не подменяют)
#TEST waf_preview response body=4k source=maybe — nginx -t
#TEST waf_preview frame:c2s body=512 при waf_audit_frames deny: body_preview у отказанного кадра, у пропущенного записи нет
#TEST waf_preview frame body=256 при waf_audit_frames all: body_preview у записей обеих сторон
#TEST waf_preview response args=1k — nginx -t
#TEST waf_preview response reload body шире capture — nginx -t
#TEST set-cookie в превью ответа: sha256, пока не назван в allow=
#TEST две записи на запрос: бюджет датаграммы считается на каждую
#TEST превью ответа: Content-Type и Content-Length в headers_preview
#TEST превью ответа: body_preview — тело апстрима, не тело запроса
