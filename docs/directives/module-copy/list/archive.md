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
что лежит после capture. Снимок кладётся до волн в размере capture; `reload`
докладывает оригинал после вердикта, в `max` размеров reload, и только когда
он кому-то нужен: на исходе, где `when=` объект не берёт, второго put нет. Те
же байты (списки ничего не тронули, размер не вырос) второй раз не кладутся.

`mask=` архива на имя, уже замаскированное capture, без `reload` — не хеш от
хеша: модуль называет такие имена агенту (`hashed`), и в S3 тот же sha256, что
видели инспекторы. `allow=` / `mask=` на имя, выброшенное `deny=` capture, без
`reload` — `nginx -t`: имени в объекте уже нет.

```
waf_archive request|response|frame <headers|args|body>[=<size>|none] ...
            [ttl=<time>] [when=allow|deny];
waf_archive request|response|frame none;
waf_archive request|response|frame reload <headers|args|body>[=capture|<size>] ...;
waf_archive request|response|frame headers|args allow=<name>,...;
waf_archive request|response|frame headers|args mask=<name>,...;
waf_archive request|response|frame headers|args deny=<name>,...;
```

Контекст: `http`, `server`, `location`, наследуемая.  
Умолчание: `none` на каждой фазе.

Без фазы — `nginx -t`. У кадра объект только `body`, `reload` нет — `frame headers`/`frame reload` `nginx -t`.
Наследует capture **той же фазы**.

Нужны `waf_store`, `waf_agent_socket` и инспекторы на маршруте — иначе `nginx -t`.

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

# правила

- нет фазы — `nginx -t`. `frame headers` / `frame reload` — `nginx -t`
- без `=` — весь объект из capture. `=none` — этот вид выкл
- `reload <obj>=capture` — размер capture. `reload <obj>` — целиком.
  `=<size>` — столько. `=capture` при объекте не в capture — `nginx -t`
- строки одного уровня складываются по объекту
- location без своей строки берёт родителя. своя строка перекрывает только
  названный объект
- `none` — сброс набора
- размер больше `waf_body_limit` или `client_max_body_size` — `nginx -t`.
  больше capture — только с `reload`, эти два лимита всё равно нельзя
- размер режет агент, не модуль; в обменнике снимок, reload шире — после вердикта
- `ttl=` срок в архиве, без него — вечно
- `when=` `allow` | `deny` | оба. нет `when=` — любой исход
- `allow=` только эти имена. `mask=` значение — sha256. `deny=` выкинуть.
  нет строки — списки capture. запрет сильнее. тела в списках нет
- в сообщение инспекторам не добавляет

#TEST archive body без reload при capture без body — nginx -t
#TEST reload body=capture при capture без body — nginx -t
#TEST reload body=128k при capture без body: в S3 128k, у инспекторов null
#TEST reload body=capture при capture body=4k: в Redis 4k оригинал
#TEST reload body при capture body=4k: до волн 4k, после отказа целиком; инспекторы видели 4k
#TEST reload body при capture body=4k, when=deny, allow: один put тела, второго нет
#TEST capture mask=token + archive mask=token без reload: в S3 один sha256, hashed в записи
#TEST capture deny=x-api-key + archive allow=x-api-key без reload — nginx -t
#TEST reload body=2m / archive body=2m при waf_body_limit 1m или client_max_body_size 1m — nginx -t
#TEST when=deny: при allow в S3 ничего
#TEST без reload: в S3 cookie — sha256 (как у инспекторов)
#TEST reload headers=capture: в S3 cookie — оригинал, size как capture
#TEST deny=x-api-key: в S3 нет, у инспекторов есть
#TEST без store / без agent_socket / inspect none — nginx -t
#TEST waf_archive reload body=128k без фазы — nginx -t
#TEST waf_archive response headers — nginx -t
#TEST waf_archive frame:c2s body when=deny при waf_inspect frame:c2s — ок
#TEST waf_archive frame reload / frame headers — nginx -t
