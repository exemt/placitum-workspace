# waf_archive

Что агент увезёт в S3 после вердикта. Наследует capture: объекты, размеры,
`mask=` / `deny=`. Своя строка перекрывает только названное. Пишет агент.

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
То же для `reload body` / `reload body=2m`. Без `reload` агент забирает то,
что лежит после capture. Один объект — один put на `max` размеров reload.

```
waf_archive <фаза> <headers|args|body>[=<size>|none] ...
            [ttl=<time>] [when=allow|deny|allow,deny];
waf_archive <фаза> none;
waf_archive <фаза> reload <headers|args|body>[=capture|<size>] ...;
waf_archive <фаза> headers|args allow=<name>,...;
waf_archive <фаза> headers|args mask=<name>,...;
waf_archive <фаза> headers|args deny=<name>,...;

<фаза> = request | response | frame | frame:c2s | frame:s2c
```

Контекст: `http`, `server`, `location`, наследуемая.  
Умолчание: `none` на каждой фазе.

Без фазы — `nginx -t`. Наследует capture **той же фазы**, и словарь
объектов у каждой фазы свой ([capture.md](capture.md#объекты-по-фазам)):
у ответа `headers` и `body`, у кадра только `body`.

`reload` шире capture — только на фазе запроса, пока фазу спрашивают. На
остальных фазах оригинал брать неоткуда: то, что за снимком, уже ушло
клиенту, а перечитать ответ второй раз нельзя — `nginx -t`. Фаза без
инспекторов снимает копию сама и в размере архива
([без инспекторов](#без-инспекторов)).

Нужны `waf_store` и `waf_agent_socket` — иначе `nginx -t`. Инспекторы не
нужны.

Набор, срок, исход, размер и источник на одном запросе может переопределить
любой спрошенный инспектор глаголом `archive` канала действий: `set: on` оставляет объекты вопреки `when=` (и
там, где строки `waf_archive` нет вовсе — тогда всё снятое), объект за
объектом со своими `limit` и `source` (`original` — тот же `reload`) и
общими `ttl` и `when`; `set: off` — объекты уходят с вердиктом. Свой `when`
просьбы заменяет маршрутный целиком, а без него просьба исполняется на любом
исходе: отправитель про `when=` маршрута не знает. Списки имён остаются
директивы
([inspector-actions.md](../../inspector-actions.md#запись-и-архив)).

```nginx
client_max_body_size 1m;
waf_body_limit 1m block;

waf_capture request headers=64k args=64k;
waf_capture request headers mask=authorization,cookie;
waf_capture request args deny=session;

# hdr/args при deny. mask/deny — с capture, пока не перекроем
waf_archive request headers args ttl=30d when=deny;
waf_archive request reload headers=capture;
# оригинал headers, тот же 64k
waf_archive request reload body=128k;
# исключение: тела в capture нет, в Redis 128k оригинала, инспекторам null
# reload body=capture — nginx -t: в capture тела нет
# reload body=2m / больше waf_body_limit или client_max_body_size — nginx -t
waf_archive request headers deny=x-api-key;
# в S3 нет x-api-key
waf_archive request args deny=token;
# token в S3 нет. session нет — наследство capture. reload args нет:
# агент увидит args после capture (без session)
```

# с capture

Capture снимает и кладёт в Redis вид инспекторам. Archive выбирает,
что из этого уедет в S3, и может перекрыть списки. Сам не читает,
в сообщение инспекторам не добавляет.

- нет своей строки по объекту — объекты и mask/deny с capture
- своя строка — переопределение, не дополнение к спискам capture
- без `reload` объект или размер шире capture — конфиг не грузится
- `reload <obj>=capture` — оригинал в размере capture
- `reload <obj>` — целиком. `=<size>` — столько. больше capture — исключение
- больше `waf_body_limit` или `client_max_body_size` — `nginx -t`
- инспекторам по-прежнему только capture

На этом примере:

1. Capture кладёт headers≤64k и args≤64k. Тела нет. Инспекторы тело не ждут.
2. Инспекторы: `authorization`/`cookie` — sha256, `session` нет, `body` — `null`.
3. После вердикта: `reload headers=capture` — оригинал 64k;
   `reload body=128k` — оригинал тела, которого в capture не было.
4. `deny` и `when=deny` — агент пишет hdr/args/body в S3 на 30d, без `x-api-key`
   и `token`, `session` нет. cookie в S3 — оригинал.
5. `allow` — в S3 ничего, ключи удаляются.

Нет archive, есть preview — нормально. Набор и списки preview берёт
у capture сам, archive тут ни при чём.

# на фазе ответа

Объекты — заголовки и тело ответа. Строка запроса не архивируется на
этой фазе вовсе: она объект фазы запроса, и её архив настраивается
там же. Один объект — один ключ, дважды он не едет.

**Исход — свойство вида, а не строки.** `ttl=` и `when=` привязаны к
объектам той же строки, и строки одного уровня складываются: «тело только
на отказ, заголовки всегда» — это две строки, а не одна. Неназванный на
этом уровне вид приносит срок и исход от родителя вместе с собой.

```nginx
waf_archive request headers args;            # любой исход, вечно
waf_archive request body ttl=30d when=deny;  # тело -- только улику
```

**Исход смотрится один на маршрут.** `when=deny` у фазы запроса
срабатывает и тогда, когда отказала фаза ответа: запрос-улика нужен
ровно в этом случае, а объекты фазы запроса и так живут до конца
фазы ответа ([capture.md](capture.md)). Решение по `when=` поэтому
откладывается до последней фазы, вынесшей исход; когда фазы ответа
на маршруте нет, всё как раньше.

**`reload` шире capture пока запрещён.** У запроса тело всё равно
прочитано целиком, и оригинал кладётся из готового буфера. У ответа
мы держим ровно то, что снимаем ([hold.md](hold.md)), и оригинал
шире снимка означал бы поток в обменник параллельно отдаче клиенту —
потокового размещения ещё нет. `reload body=capture` работает,
`reload body` и `reload body=<больше capture>` — `nginx -t`.

**Сжатие.** В архив ложится то, что видел модуль. При
`waf_strip_accept_encoding on` ([misc.md](misc.md)) это открытый
текст, при `off` — байты gzip, и `encoding` в записи говорит, какие
именно. Архив, который нельзя открыть без словаря апстрима, хуже
отсутствующего.

# на фазе кадров

Объект один — полезная нагрузка кадра (`body`), словарь тот же, что у
снимка ([capture.md](capture.md#объекты-по-фазам)): `headers` и `args`
на кадре — `nginx -t`. Сторона — в первом слове: `frame` настраивает
оба направления, `frame:c2s` / `frame:s2c` — своё; на одном уровне
объект называется один раз, `frame` и `frame:c2s` вместе — отказ.

```nginx
location /ws/ {
    waf_capture  frame:c2s body=64k;
    waf_inspect  frame:c2s modsec wave=0 timeout=200ms;

    waf_archive  frame:c2s body ttl=30d when=deny;
    waf_preview  frame:c2s body=512;
}
```

**Запись решает, что остаётся.** Кадр пишется в аудит по
`waf_audit_frames` ([frame.md](frame.md)): `deny` (умолчание) — только
кадр с отказом, подменой или счётом, `all [sample=n]` — каждый n-й,
`off` — никакой. Объект кадра остаётся агенту только вместе с записью:
кадр без записи снимается из обменника сразу, иначе болтливый сокет
забил бы обменник пропущенными кадрами до `retain_ttl`. `when=` поверх
этого сужает набор по исходу самого кадра — исход у кадра свой,
рукопожатие и соседние кадры на него не влияют.

**Архив и превью могут быть шире снимка — без `reload`.** У кадра нет
масок, и весь кадр лежит в буфере до вердикта (`gate`), как тело
запроса, а не как поток ответа. Поэтому снимок, архив и превью — три
независимых окна размера в один и тот же буфер: инспекторам можно
дать короткий срез (`waf_capture frame:c2s body=8k`), а в архив увезти
весь кадр (`waf_archive frame:c2s body`) или его больший префикс
(`body=32k`). Локатор инспектору всё равно режется по снимку, даже
когда в обменнике лежит больше. Единственный потолок — `waf_body_limit
frame`: шире буфера не бывает, `waf_archive frame body=<больше
лимита>` — `nginx -t`.

**`reload` у кадра нет.** `reload` до-кладывает оригинал за маской —
у кадра ни масок, ни отдельного оригинала, размер задаётся прямо:
`waf_archive frame reload …` и `waf_preview frame reload …` — `nginx
-t`. У стороны с инспекторами снимок обязателен (он даёт инспекторам их
вид): `waf_archive frame` без `waf_capture frame body` — `nginx -t`.
Стороне без инспекторов снимок не нужен.

**Адрес объекта.** В обменнике — ключ `<node>:<rid>:frm` (rid у каждого
кадра свой), в архиве — `<дата>/<node>/<ray>.frame.<сторона>.<номер>.body`:
всё соединение лежит под `ray` рукопожатия, и кадр внутри него
различается тем же адресом, каким его запись ищется в журнале
(`?phase=frame&frame=<direction>:<seq>`, [audit.md](../../audit.md#кадры)).
Срез превью ложится в ту же `body_preview`, что у тела запроса, и по
ней же ищется поперёк всех записей — кадры включительно.

Сторона без инспекторов архивирует так же — журналом
([без инспекторов](#без-инспекторов)): `waf_archive frame` при
`waf_inspect frame:c2s` кладёт и кадры `s2c`, если их записи выпадают.

# без инспекторов

Фаза, где никого не спрашивают, пишет журнал, и архив у неё работает.
Снимка для волн нет, поэтому объект берётся из самого трафика: в размере
архива (без `=` — целиком, не больше `waf_body_limit`), со списками снимка
(`mask=` / `deny=` у `waf_capture` действуют и здесь), с `reload` —
оригиналом. Правила «шире capture» к такой фазе не применяются: сверять не
с чем.

- **запрос** — объекты кладутся после прохода, тело дочитывается, если его
  архив или превью названы; запись уходит, когда ключи легли;
- **ответ** — ничем не удерживается: заголовки и тело уходят клиенту сразу,
  в обменник ложится копия префикса тела, и запись фазы ответа уходит по
  концу ответа. Запрос при этом держится, пока обменник не ответит, — уже
  после отдачи;
- **кадры** — объект кладётся у кадров, которым выпала запись
  (`waf_audit_frames all [sample=n]`); кадр уходит получателю сразу, а
  следующие кадры обеих сторон (кадр в полёте один на соединение) ждут,
  пока обменник примет объект.

Исход у журнала — `allow`: `when=deny` на фазе без инспекторов выпадает
только на отказе локального слоя (`waf_local_check`, `waf_local_rate`) — его
объекты берутся из запроса так же, как у журнала, — и на объектах запроса,
если отказала поздняя фаза с инспекторами.

```nginx
location /api/ {
    waf_inspect  request none;
    waf_capture  request headers=8k;
    waf_capture  request headers mask=authorization,cookie;
    waf_preview  request headers=2k/256 body=1k;
    waf_archive  request headers body ttl=7d;      # cookie в S3 -- sha256

    waf_preview  response headers=1k/256 body=2k;
    waf_archive  response body=64k ttl=7d;         # префикс ответа, без удержания
}
```

# правила

- нет фазы — `nginx -t`
- `reload` шире capture вне фазы запроса — `nginx -t`, пока фазу спрашивают
- инспекторы не нужны: фаза без волн пишет журнал, объекты — из трафика в
  размере архива
- без `=` — весь объект из capture. `=none` — этот вид выкл
- `reload <obj>=capture` — размер capture. `reload <obj>` — целиком.
  `=<size>` — столько. `=capture` при объекте не в capture — `nginx -t`
- строки одного уровня складываются по объекту
- location без своей строки берёт родителя. своя строка перекрывает только
  названный объект
- `none` — сброс набора
- размер больше `waf_body_limit` или `client_max_body_size` — `nginx -t`.
  больше capture — только с `reload`, эти два лимита всё равно нельзя
- размер режет агент, не модуль
- `ttl=` срок в архиве, без него — вечно. на виды своей строки
- `when=` `allow` | `deny` | оба. нет `when=` — любой исход, включая
  redirect. тоже на виды своей строки: разные исходы — разные строки
- `allow=` только эти имена. `mask=` значение — sha256. `deny=` выкинуть.
  нет строки — списки capture. запрет сильнее. тела в списках нет
- в сообщение инспекторам не добавляет

#TEST archive body без reload при capture без body — nginx -t
#TEST reload body=capture при capture без body — nginx -t
#TEST reload body=128k при capture без body: в S3 128k, у инспекторов null
#TEST reload body=capture при capture body=4k: в Redis 4k оригинал
#TEST reload body при capture body=4k: в Redis целиком, инспекторы видели 4k
#TEST reload body=2m / archive body=2m при waf_body_limit 1m или client_max_body_size 1m — nginx -t
#TEST when=deny: при allow в S3 ничего
#TEST when=allow,deny при redirect: в S3 ничего, при allow и deny -- уехало
#TEST разные when= у соседних строк уровня: тело при allow не уехало, заголовки уехали
#TEST без reload: в S3 cookie — sha256 (как у инспекторов)
#TEST reload headers=capture: в S3 cookie — оригинал, size как capture
#TEST deny=x-api-key: в S3 нет, у инспекторов есть
#TEST без store / без agent_socket / inspect none — nginx -t
#TEST waf_archive reload body=128k без фазы — nginx -t
#TEST waf_archive response headers body при capture response — ок
#TEST waf_archive response без inspect response — nginx -t
#TEST waf_archive frame:c2s body when=deny при waf_audit_frames deny: у отказанного кадра store.archive и ключ :frm живёт retain_ttl
#TEST waf_archive frame body при waf_audit_frames deny: пропущенный кадр без записи — ключ снят сразу
#TEST waf_archive frame при waf_inspect frame:c2s — nginx -t
#TEST capture frame body=8k + archive frame body (whole): в обменнике весь кадр, инспектору locator size = 8k
#TEST capture frame body=8k + archive frame body=32k: в S3 до 32k, инспектору 8k
#TEST waf_archive frame body=<больше waf_body_limit frame> — nginx -t
#TEST waf_archive frame reload body=capture — nginx -t
#TEST waf_archive frame headers — nginx -t
#TEST waf_archive frame body и frame:c2s body на одном уровне — nginx -t
#TEST объект кадра в S3: <ray>.frame.c2s.<seq>.body, два кадра одного соединения не перекрывают друг друга
#TEST waf_archive response reload body шире capture — nginx -t
#TEST waf_archive response args — nginx -t
#TEST deny на фазе ответа: request-объекты с when=deny уехали
#TEST archive response: ключи :rsp и :rsp:hdr живут retain_ttl, не ttl
#TEST archive response: секция store.archive в записи фазы ответа
