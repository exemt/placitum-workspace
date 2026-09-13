# waf_inspect

Кого опрашивать на фазе. Имя из реестра — [inspector.md](inspector.md).
Что видят все на маршруте — [capture.md](capture.md), одно на всех.

Фаза — первое слово, как у `waf_capture request`. Мы (`request`) →
приложение → мы (`response`). Кадры — `frame`, когда появится апгрейд.

```
waf_inspect request|response|frame <name> wave=<n>
            [timeout=<time>] [weight=<n>] [mode=active|passive]
            [if <variable> in|not in <dataset>] ...;
waf_inspect request|response|frame none;
```

Контекст: `http`, `server`, `location`. Набор **своей фазы**
заменяется целиком: строка `request` на location не трогает
`response`. Нет строки фазы — фаза не бежит. `none` — никого
на этой фазе. Неизвестное имя / нет фазы — `nginx -t`.

`wave=` обязателен. N стартует, когда предыдущая волна **этой
фазы** завершилась. Один номер у нескольких — параллельно.
Пустая волна пропускается.

`timeout=` без значения — бюджет своей фазы
([deadline.md](deadline.md)). `phase=` на строке — `nginx -t`.
`waf_request_inspect` / `waf_response_inspect` / `waf_frame_inspect`
сняты.

`response` / `frame` разбираются. Фаз ещё нет.

```nginx
http {
    waf_inspector allow_ip  subject=waf.req.ip profile=allow;
    waf_inspector strict_ip subject=waf.req.ip profile=strict;
    waf_inspector sqli      subject=waf.req.sqli;
    waf_inspector modsec    subject=waf.req.modsec profile=strict;
    waf_inspector challenge subject=waf.req.chal;
    waf_inspector json      subject=waf.req.json;

    server {
        waf_capture request headers=64k args=64k;

        waf_inspect request allow_ip  wave=0 timeout=5ms;
        waf_inspect request sqli      wave=1 timeout=15ms weight=1.0;
        waf_inspect request modsec    wave=1 timeout=1000ms;
        waf_inspect request challenge wave=2 timeout=10ms weight=0;

        location /api/ {
            waf_capture request body=4k;
            waf_inspect request allow_ip wave=0 timeout=5ms;
            waf_inspect request sqli     wave=1 timeout=15ms mode=passive;
        }

        location /strict/ {
            waf_inspect request strict_ip wave=0 timeout=5ms;
            waf_inspect request sqli      wave=1 timeout=15ms;
        }

        location /static/ {
            waf_capture request none;
            waf_inspect request none;
        }

        location /account/ {
            waf_inspect request  allow_ip wave=0 timeout=5ms;
            waf_inspect request  json     wave=1 timeout=1000ms;
            waf_inspect response json     wave=0 timeout=800ms;
        }
    }
}
```

`/` — серверный request: ip → (sqli∥modsec) → challenge.  
`/api/` — свой request, без modsec и challenge. sqli смотрит, не гейтит.  
`/strict/` — тот же subject, что `allow_ip`, профиль `strict`.  
`/static/` — request никого и capture сброшен: inherit снимка иначе
кладёт hdr/args (или тело) в redis без инспекторов.  
`/account/` — `json` дважды: request и response, волны фаз свои.

# опции

| | умолчание | |
| --- | --- | --- |
| фаза | обязательна | `request` `response` `frame` |
| `wave=` | обязателен | номер волны этой фазы |
| `timeout=` | `waf_deadline` этой фазы | ожидание одного |
| `weight=` | `1.0` | вклад в счёт, `0`…`10.0` |
| `mode=` | `active` | `active` — ждут и гейтит. `passive` — ждут ради лога, счёт в тень, молчание не двигает deadline |
| `if` | нет | когда спрашивать. несколько — И. [select.md](select.md) |

# правила

- повтор имени на одной фазе одного уровня — `nginx -t`
- одно имя на request и на response — две строки, нормально
- нет фазы / нет `wave=` — `nginx -t`
- `phase=` — `nginx -t`
- `waf_request_inspect` / `waf_response_inspect` / `waf_frame_inspect` — `nginx -t`
- тело в capture — в сообщении у request, волна 0 request ждёт put
- локальный слой раньше любой волны request.
  `action=wave` там — сразу в `waf_inspect request`
- `waf_inspect request none` снимок не выключает: нужен
  `waf_capture request none` (и archive/preview `none`, если были)
- `if` не сошёлся — инспектора не спрашивали: волна не ждёт, счёт не растёт,
  `waf_on_absent` не применяется, в аудите `skipped`. Все инспекторы фазы
  пропущены — фаза не бежит, как при `none`

#TEST неизвестное имя — nginx -t
#TEST без фазы / без wave= — nginx -t
#TEST waf_request_inspect / phase= — nginx -t
#TEST wave=0 и wave=1: 1 не публикуется, пока 0 не ответила
#TEST /api/: свой request, серверный request не действует, response не сброшен
#TEST нет строки фазы на location: берёт сервер этой фазы
#TEST request none: request не бежит, capture родителя всё ещё кладёт
#TEST request none + capture none: в redis ничего
#TEST mode=passive deny: запрос прошёл, вердикт в debug/аудите
#TEST if не сошёлся: инспектор не публикуется, on_absent не применяется
#TEST все инспекторы волны под if: волна пуста, снимок в redis не кладётся
