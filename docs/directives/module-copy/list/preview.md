# waf_preview

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
То же для `reload body` / `body=2m`. Без `reload` срез берётся из того, что
положил capture. Снимок кладётся до волн в размере capture; `reload`
докладывает оригинал после вердикта, в `max` размеров reload archive и preview.
Те же байты второй раз не кладутся.

`mask=` превью на имя, выброшенное `deny=` capture, без `reload` — `nginx -t`:
превью применяет запрет снимка, и имени в записи не будет.

`source=sent` у `body` — на всех фазах: ответ и кадр подменяет секция
`rewrite`, запрос — `waf_send request body=store`. Запись при этом показывает
доставленное, а оригинал остаётся в архиве; sha256 доставленного — в секции
`rewrite` записи всегда.

```
waf_preview request|response|frame <headers|args|body>=<size>[/<item>]|none ...;
waf_preview request|response|frame none;
waf_preview request|response|frame reload <headers|args|body>[=capture|<size>] ...;
waf_preview request|response|frame headers|args allow=<name>,...;
waf_preview request|response|frame headers|args mask=<name>,...;
waf_preview request|response|frame headers|args deny=<name>,...;
```

Контекст: `http`, `server`, `location`, наследуемая.  
Умолчание: `off` у каждой фазы.

Без фазы — `nginx -t`. У кадра объект только `body`, `reload` нет — `frame headers`/`frame reload` `nginx -t`.
Наследует capture **той же фазы**.

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
Общий только снимок и один put оригинала на объект после вердикта, если
reload есть хотя бы у одного; ради одного архива он не делается на исходе,
где архив объект не берёт, ради превью — делается всегда.

# правила

- нет фазы — `nginx -t`. `frame headers` / `frame reload` — `nginx -t`
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
#TEST waf_preview response body=10k — nginx -t
#TEST waf_preview frame:c2s body=512 при waf_inspect frame:c2s — ок
#TEST waf_preview frame headers=1k / frame reload — nginx -t
