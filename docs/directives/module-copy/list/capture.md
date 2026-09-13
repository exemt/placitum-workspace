# waf_capture

Первый снимок на маршруте: какие объекты, какой размер. Инспекторы видят это
после `mask=` / `deny=`. Archive и preview наследуют этот набор и эти списки,
каждый может перекрыть своим. Шире capture без `reload` — `nginx -t`.
Любой размер больше `waf_body_limit` или `client_max_body_size` — `nginx -t`.

В Redis после волн лежит то, что видели инспекторы. Чистый объект агенту —
`reload` на archive / preview, не здесь.

`reload body=capture` — тот же размер, что capture. `reload body` — целиком.
`reload body=12k` — 12k. Целиком или с размером больше capture — исключение:
после вердикта в Redis докладывается оригинал шире, инспекторы его не видят.
До волн лежит ровно capture: размер снимка — это и размер put перед волной.

```
waf_capture request|response|frame <headers|args|body>[=<size>|none] ...;
waf_capture request|response|frame none | off;
waf_capture request|response|frame headers|args mask=<name>,...;
waf_capture request|response|frame headers|args deny=<name>,...;
```

Контекст: `http`, `server`, `location`, наследуемая.  
Умолчание `request`: `headers args` (весь объект).  
`response` / `frame` — нет строки: ничего. Задать — `nginx -t`,
фаз ещё нет.

Без фазы — `nginx -t`. Набор **своей фазы** сам по себе:
`request` на location не сбрасывает будущий `response`.

```nginx
client_max_body_size 1m;
waf_body_limit 1m block;

# hdr/args, тела нет. cookie — sha256, session выкинут
# headers=2m / body=2m — nginx -t: больше waf_body_limit / client_max_body_size
waf_capture request headers=64k args=64k;
# на маршруте получим headers + args, body получать не будем
waf_capture request headers mask=authorization,cookie;
# значения заголовков authorization, cookie заменим на хеши
waf_capture request args deny=session;
# аргумент session удалим
```

# правила

- нет фазы — `nginx -t`. `response` / `frame` — `nginx -t`
- без `=` — весь объект. `=none` — этот вид выкл
- строки одного уровня складываются по объекту
- location без своей строки берёт родителя. своя строка перекрывает только
  названный объект (`body=4k` не сбрасывает headers)
- `none` / `off` — сброс набора
- размер больше `waf_body_limit` или `client_max_body_size` — `nginx -t`.
  без `=` весь объект, но не шире этих двух
- `mask=` имя оставить, значение — sha256. `deny=` выкинуть до put.
  тела в списках нет
- нет объекта в capture — в сообщении `null`. тело в capture — волна 0 ждёт put
- archive / preview без `reload`: объект не из capture или размер больше — `nginx -t`
- `reload <obj>=capture` — оригинал в размере capture. объекта нет — `nginx -t`
- `reload <obj>` / `=<size>` больше capture — исключение.
  больше `waf_body_limit` или `client_max_body_size` — всё равно `nginx -t`

#TEST body=2m при client_max_body_size 1m / waf_body_limit 1m — nginx -t
#TEST без body: store.body=null, волна 0 не ждёт
#TEST archive body без reload при capture без body — nginx -t
#TEST archive reload body=capture при capture без body — nginx -t
#TEST archive reload body=128k при capture без body — ок, инспекторы body не видят
#TEST mask=cookie: у инспекторов sha256
#TEST deny=session: у инспекторов пары нет
#TEST waf_capture headers mask=cookie без фазы — nginx -t
#TEST waf_capture response headers — nginx -t
#TEST waf_capture frame args — nginx -t
