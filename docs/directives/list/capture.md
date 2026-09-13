# waf_capture

Первый снимок на маршруте: какие объекты, какой размер. Инспекторы видят это
после `mask=` / `deny=`. Archive и preview наследуют этот набор и эти списки,
каждый может перекрыть своим. Шире capture без `reload` — `nginx -t`.
Любой размер больше `waf_body_limit` этой фазы или `client_max_body_size` —
`nginx -t`.

В Redis после волн лежит то, что видели инспекторы. Чистый объект агенту —
`reload` на archive / preview, не здесь.

`reload body=capture` — тот же размер, что capture. `reload body` — целиком.
`reload body=12k` — 12k. Целиком или с размером больше capture — исключение:
в Redis оригинал шире, инспекторы его не видят.

```
waf_capture request|response|frame|frame:c2s|frame:s2c
            <headers|args|body>[=<size>|none] ...;
waf_capture <фаза> none | off;
waf_capture <фаза> headers|args mask=<name>,...;
waf_capture <фаза> headers|args deny=<name>,...;
```

Контекст: `http`, `server`, `location`, наследуемая.  
Умолчание `request`: `headers args` (весь объект).
`response` / `frame` — нет строки: ничего.

Без фазы — `nginx -t`. Набор **своей фазы** сам по себе:
`request` на location не сбрасывает `response`. У кадров направление
в первом слове: `frame` — обе стороны, `frame:c2s` перекрывает одну.

# объекты по фазам

| фаза | объекты | что это |
| --- | --- | --- |
| `request` | `headers` `args` `body` | запрос клиента |
| `response` | `headers` `body` | ответ апстрима. `args` — `nginx -t`: строки запроса у ответа нет |
| `frame[:dir]` | `body` | полезная нагрузка кадра, при `waf_frame_reassemble on` — собранного сообщения. `headers` / `args` — `nginx -t` |

Третьего словаря нет: `body` кадра — тот же объект обменника и то же
`store.body` в сообщении инспектору.

Контекст запроса на фазе ответа и на фазе кадра инспектор получает
секциями `conn` / `http` / `request_store` — объектами, снятыми на
фазе запроса. Снимать их второй раз незачем, и `waf_capture response
headers` — это заголовки **ответа**, а не запроса.

```nginx
client_max_body_size 1m;
waf_body_limit request 1m block;

# hdr/args, тела нет. cookie — sha256, session выкинут
# headers=2m / body=2m — nginx -t: больше waf_body_limit / client_max_body_size
waf_capture request headers=64k args=64k;
# на маршруте получим headers + args, body получать не будем
waf_capture request headers mask=authorization,cookie;
# значения заголовков authorization, cookie заменим на хеши
waf_capture request args deny=session;
# аргумент session удалим

location /api/ {
    # ответ: заголовки и первые 64k тела. set-cookie — хешем
    waf_capture  response headers=8k body=64k;
    waf_capture  response headers mask=set-cookie;
    waf_body_limit response 512k trim;
    waf_inspect  response dlp wave=0 timeout=20ms;
}
```

# правила

- нет фазы — `nginx -t`
- объект не из словаря фазы — `nginx -t`
- без `=` — весь объект. `=none` — этот вид выкл
- строки одного уровня складываются по объекту
- location без своей строки берёт родителя **этой фазы**. своя строка
  перекрывает только названный объект (`body=4k` не сбрасывает headers)
- `none` / `off` — сброс набора своей фазы
- размер больше `waf_body_limit` этой фазы или `client_max_body_size` —
  `nginx -t`. без `=` весь объект, но не шире этих двух
- `mask=` имя оставить, значение — sha256. `deny=` выкинуть до put.
  тела в списках нет
- нет объекта в capture — в сообщении `null`. тело в capture — волна 0
  этой фазы ждёт put
- archive / preview без `reload`: объект не из capture своей фазы или размер
  больше — `nginx -t`
- `reload <obj>=capture` — оригинал в размере capture. объекта нет — `nginx -t`
- `reload <obj>` / `=<size>` больше capture — исключение.
  больше `waf_body_limit` или `client_max_body_size` — всё равно `nginx -t`
- снятое тело ответа держится в памяти до вердикта при `waf_hold response
  gate` ([hold.md](hold.md)): размер снимка — он же потолок удержания
- `waf_capture response body=` включает снятие `Accept-Encoding` в апстрим
  ([misc.md](misc.md)): сжатое тело инспектор не смотрит
- снимка `frame` ещё нет: набор разбирается, фаза не бежит — `nginx -t`
- объекты снимаются, когда фаз больше не осталось: на маршруте без фазы
  ответа — по вердикту запроса, с ней — по вердикту ответа. Объекты запроса
  переживают свою фазу потому, что их ключи едут инспектору ответа секцией
  `request_store`. Названные в `waf_archive` остаются агенту

#TEST body=2m при client_max_body_size 1m / waf_body_limit request 1m — nginx -t
#TEST без body: store.body=null, волна 0 не ждёт
#TEST archive body без reload при capture без body — nginx -t
#TEST archive reload body=capture при capture без body — nginx -t
#TEST archive reload body=128k при capture без body — ок, инспекторы body не видят
#TEST mask=cookie: у инспекторов sha256
#TEST deny=session: у инспекторов пары нет
#TEST waf_capture headers mask=cookie без фазы — nginx -t
#TEST waf_capture response args — nginx -t
#TEST capture response headers body: в обменнике :rsp:hdr и :rsp, инлайна нет
#TEST capture response body: Accept-Encoding в апстрим — identity
#TEST waf_capture frame headers — nginx -t
#TEST waf_capture request none на location: response родителя не сброшен
