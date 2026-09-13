# мелочи контура

Все в `http`, кроме `waf_debug_header` и
`waf_strip_accept_encoding` — эти ещё `server` / `location`.

```
waf_node_id <string>;
waf_reply_max <size>;
waf_header_value_max <size>;
waf_max_inflight <n>;
waf_body_max_holds <n>;
waf_var <name> <value>;
waf_debug_header on|off;
waf_strip_accept_encoding on|off;
```

```nginx
http {
    waf_node_id edge-07;
    waf_reply_max 8k;
    waf_header_value_max 4k;
    waf_max_inflight 4096;
    waf_body_max_holds 1000;

    waf_var ja3 $http_x_ja3;
    waf_var via $http_x_forwarded_for;

    location /debug {
        waf_debug_header on;
    }
}
```

# waf_node_id

Имя узла: инбокс шины, ключи обменника, аудит, `$waf_node_id`.
Уникален во флоте. Нет строки — hostname.

# waf_reply_max

Потолок ответа инспектора. Умолчание `8k`. Больше — ответ
отброшен целиком, как молчание. Половину разобрать нельзя.

# waf_header_value_max

Потолок одного значения в переопределении заголовка / cookie.
Умолчание `4k`. Не размер сообщения: живёт и при большом
`waf_reply_max`. Редирект-URL тоже сюда.

# waf_max_inflight

Слоты ожидания на воркер. Умолчание `4096`. Больше `16777215`
— `nginx -t` (в `rid` на индекс 24 бита).

# waf_body_max_holds

Сколько тел одновременно лежит в обменнике на воркер. Умолчание
`1000`. Не размер одного тела — полёт. Исчерпание —
`waf_exception … body` этой фазы.

# waf_var

Поле в сообщение инспекторам и в итог агенту. Не в
`waf_local_check`: check читает переменные nginx как есть.

Имя — ключ, `A–Z a–z 0–9 _ . -`. Значение — комплексное
nginx (`$http_x_ja3`). Считается раз на запрос, до локального
слоя. Не посчиталось — пустая строка, запрос не падает.

До 16 штук. Значение на проводе режется до 256 байт: это
диагностика, не способ вернуть заголовки в каждое сообщение.

## стандартный набор

Восемь полей модуль считает сам, без `waf_var`, и их имена
заняты — `waf_var user_agent …` даёт `nginx -t`:

| поле | переменная |
| --- | --- |
| `user_agent` | `$http_user_agent` |
| `referer` | `$http_referer` |
| `xff` | `$http_x_forwarded_for` |
| `accept_language` | `$http_accept_language` |
| `origin` | `$http_origin` |
| `content_type` | `$content_type` |
| `accept` | `$http_accept` |
| `request_id` | `$request_id` |

Только ядро nginx: ничего из `ngx_http_ssl_module`, чтобы
конфигурация без TLS не падала на имени переменной. `Cookie` и
`Authorization` в набор не попадут никогда: к заголовкам в
обменнике маршрут применяет `mask=` / `deny=`, а секция `vars`
едет инлайном мимо них.

## кому что едет

Запись аудита везёт набор целиком — стандартные поля и все
`waf_var`. Сообщение инспектору — только то, что названо в
`vars=` его объявления ([inspector.md](inspector.md)): имена
полей через запятую либо `all`. Без опции секции `vars` в
сообщении нет. Значения считаются один раз на запрос, состав
у каждого имени свой.

Стандартный набор в строку лога не печатается — там только
`waf_var`.

Значения всех полей берутся на входе запроса: на фазе ответа и
на кадрах инспектор видит те же строки, а `$upstream_*` и
`$status` в `waf_var` останутся пустыми.

# waf_debug_header

`X-WAF-Debug`: rid, ray, вердикт, счёт, волна, кто ответил и за
сколько. Умолчание `off`. Ставится и на отказе политикой
без вердикта. Только тестовый контур: светит устройство защиты.

`rid` — слот ожидания: живёт один запрос и адресует только строки
`error_log`. `ray` — тот же идентификатор, что в записи аудита и на
странице отказа; по нему запись ищут в поиске, а через неё достают
содержимое объектов, когда те уже переехали из обменника в архив.

# waf_strip_accept_encoding

Снимать ли `Accept-Encoding` в апстрим. Умолчание `on` там, где
маршрут снимает тело ответа (`waf_capture response body=`), иначе
`off`.

Та же мысль, что `waf_ws_strip_extensions` ([frame.md](frame.md)):
не согласовывать то, что придётся распаковывать в воркере. Сжатое
тело для фазы ответа бесполезно — правила по `RESPONSE_BODY`
смотрели бы в gzip.

`off` — тело уезжает инспектору с `encoding: "gzip"` в локаторе, и
инспектор вправе его не смотреть. Цена `on` — апстрим отдаёт
несжатое; клиенту nginx сожмёт сам (`gzip on`).

Директива приезжает вместе с фазой ответа: пока её нет, `nginx -t`
имени не принимает.

```nginx
location /api/ {
    waf_capture response headers=8k body=64k;   # включает снятие
}

location /big/ {
    waf_strip_accept_encoding off;              # трафик до апстрима дороже
    waf_capture response headers=8k;
}
```

# правила

- повтор `waf_var` / плохая буква в имени / 17-я — `nginx -t`
- `waf_max_inflight` больше маски слота — `nginx -t`
- Redis + `waf_deadline request 50ms` — ок: Redis не `remote`
- обменник `remote` и дедлайн ниже порога — `nginx -t`

#TEST waf_var $ja3 $http_x_ja3 — nginx -t ($ в имени)
#TEST 17-я waf_var — nginx -t
#TEST повтор имени — nginx -t
#TEST waf_var user_agent … — nginx -t (имя стандартного поля; unit/var-reserved-name.conf)
#TEST vars=ua на waf_inspector — nginx -t (unit/vars-unknown.conf); vars=all и имена — ок (unit/vars-ok.conf)
#TEST объявление без vars=: в сообщении инспектору секции vars нет, в записи аудита — весь набор
#TEST max_inflight 20000000 — nginx -t
#TEST remote store + deadline request 50ms при min 1s — nginx -t
#TEST reply больше 8k: как молчание, решает deadline
#TEST debug on: в ответе X-WAF-Debug, в том числе на 403
#TEST capture response body= без своей строки: Accept-Encoding снят
#TEST strip_accept_encoding off: в локаторе encoding=gzip
