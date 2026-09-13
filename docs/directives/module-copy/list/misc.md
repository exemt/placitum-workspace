# мелочи контура

Все в `http`, кроме `waf_debug_header` — ещё `server` / `location`.

```
waf_node_id <string>;
waf_reply_max <size>;
waf_header_value_max <size>;
waf_max_inflight <n>;
waf_body_max_holds <n>;
waf_body_remote_min_deadline <time>;
waf_var <name> <value>;
waf_debug_header on|off;
```

```nginx
http {
    waf_node_id edge-07;
    waf_reply_max 8k;
    waf_header_value_max 4k;
    waf_max_inflight 4096;
    waf_body_max_holds 1000;
    waf_body_remote_min_deadline 1s;

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
`waf_on_body_unavailable` этой фазы.

# waf_body_remote_min_deadline

Минимальный `waf_deadline` для обменника класса `remote` (десятки
мс: не Redis). Умолчание `1s`. Ниже — `nginx -t`: round-trip
не влезет, маршрут выглядел бы проверяющим.

# waf_var

Поле в сообщение инспекторам и в итог агенту. Не в
`waf_local_check`: check читает переменные nginx как есть,
а куки, аргументы и заголовки -- селекторами
([select.md](select.md)).

Имя — ключ, `A–Z a–z 0–9 _ . -`. Значение — комплексное
nginx (`$http_x_ja3`). Считается раз на запрос, до локального
слоя. Не посчиталось — пустая строка, запрос не падает.

До 16 штук. Значение на проводе режется до 256 байт: это
диагностика, не способ вернуть заголовки в каждое сообщение.

# waf_debug_header

`X-WAF-Debug`: rid, вердикт, счёт, волна, кто ответил и за
сколько. Умолчание `off`. Ставится и на отказе политикой
без вердикта. Только тестовый контур: светит устройство защиты.

# правила

- повтор `waf_var` / плохая буква в имени / 17-я — `nginx -t`
- `waf_max_inflight` больше маски слота — `nginx -t`
- Redis + `waf_deadline request 50ms` — ок: Redis не `remote`
- обменник `remote` и дедлайн ниже порога — `nginx -t`

#TEST waf_var $ja3 $http_x_ja3 — nginx -t ($ в имени)
#TEST 17-я waf_var — nginx -t
#TEST повтор имени — nginx -t
#TEST max_inflight 20000000 — nginx -t
#TEST remote store + deadline request 50ms при min 1s — nginx -t
#TEST reply больше 8k: как молчание, решает deadline
#TEST debug on: в ответе X-WAF-Debug, в том числе на 403
