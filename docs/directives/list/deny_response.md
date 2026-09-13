# waf_deny_response

Каталог страниц отказа. Только `http`. Инспектор, check и rate
называют запись по имени — код и тело с провода не принимаются.

```
waf_deny_response <name> [type=http|grpc|websocket]
                  [status=<n>] [page=@<location>]
                  [message=<text>] [code=<n>] [reason=<text>]
                  [params=<w1>,<w2>,...];
```

Имя уникально. Нет `type=` — `http`. Нет `status=` — `403`.

`page=` — только `@имя`. Модуль сам на `@` не ходит: отдаёт статус,
страницу берёт nginx через `error_page` и `$waf_deny_name`.

```nginx
http {
    waf_deny_response blocked     status=403 page=@waf_deny;
    waf_deny_response suspicious  status=403 page=@waf_deny;
    waf_deny_response too_many    status=429 page=@waf_deny;
    waf_deny_response leak        status=502 page=@waf_deny;

    # type=grpc / websocket разбираются. пока применяется голый 403
    waf_deny_response grpc_denied type=grpc status=7
                      "message=blocked by policy";
    waf_deny_response ws_policy   type=websocket code=1008
                      "reason=policy violation";
}

server {
    error_page 403 =403 @waf_deny;
    error_page 429 =429 @waf_deny;
    error_page 502 =502 @waf_deny;

    location @waf_deny {
        waf off;
        ssi on;
        ssi_types *;
        root /usr/share/waf/pages;
        try_files /$waf_deny_name.html /blocked.html;
    }
}
```

`=403` в `error_page` держит статус: без него `try_files` дал бы 200.

Кто пишет имя: `response=` у `waf_local_check` / `waf_local_rate` /
`waf_score_deny`, поле `response` в ответе инспектора. Нет имени —
[deny_default.md](deny_default.md).

# type=

| | поля | |
| --- | --- | --- |
| `http` | `status=` `page=` `params=` | статус только `400`…`599` |
| `grpc` | `status=` `message=` | `status=` — код grpc-status |
| `websocket` | `code=` `reason=` | `code=` — Close |

`message=` директива принимает у любого типа, и у `http` он доедет
до страницы переменной `$waf_deny_message`. Но **панель его у
`http` не пишет и вычищает** (миграция 065): текст отказа —
свойство самой страницы, и второе место под ту же фразу разошлось
бы с ней молча. Своя фраза у записи — это своя страница, копией с
`blocked` (docs/deny-pages.md).

Тем самым `message=` у `http` остаётся рычагом уровня директивы:
он работает в руками написанном `nginx.conf`, но не появляется у
конфигурации, собранной контроллером. Встроенные страницы его тоже
больше не печатают (миграция 066): ветка, которую нечем включить,
стояла первой в цепочке и отменяла разбор причины.

# params=

Что записи разрешено отдать клиенту: перечень через запятую из
`ray`, `addr`, `scope`, `subject`, `retry` — хвосты имён переменных
`$waf_deny_*`. Нет `params=` — открыто всё; перечень читается как
«отдаю только это». Запертая переменная становится not_found, и
страница прячет её блок целиком.

Гейт закрывает только клиентское семейство `$waf_deny_*`:
диагностические `$waf_ray`, `$waf_score` и логи он не трогает.

```nginx
waf_deny_response blocked       status=403;              # всё открыто
waf_deny_response blocked_quiet status=403 params=ray;   # только Event ID
```

Незнакомое слово и пустой `params=` — `nginx -t`: опечатка, молча
открывшая всё, была бы ровно той дырой, от которой перечень заводили.

# кто какую запись берёт

- локальный отказ — `response=` правила, иначе default
- порог счёта — `response=` у `waf_score_deny`, иначе default
- инспектор — `response` в ответе, иначе default
- имя с провода нет в каталоге — default, в лог ошибка

# переменные в `@waf_deny`

Диагностика (оператору): `$waf_deny_name` `$waf_deny_status`
`$waf_ray` `$waf_reason` `$waf_score` `$waf_node_id`.

Клиенту: `$waf_deny_message` (это `message=` записи),
`$waf_deny_scope` `$waf_deny_subject` `$waf_deny_retry` — что
закрыто, чем названо, когда отпустит. Приезжают в `reason` ответа
инспектора, см. [deny-pages.md](../../deny-pages.md).

Пустые, если запрос мимо модуля.

# правила

- повтор имени — `nginx -t`
- `page=` без `@` — `nginx -t`
- `type=http` и статус не 4xx/5xx — `nginx -t` (2xx/3xx = тихий пропуск)
- `response=` у check / rate / score на несуществующее имя — `nginx -t`
- `type=grpc` / `websocket` на живом http-маршруте — голый `403`,
  не grpc-status

#TEST повтор имени — nginx -t
#TEST page=waf_blocked без @ — nginx -t
#TEST status=302 / status=200 — nginx -t
#TEST local_check response=неттакой — nginx -t
#TEST нет записи blocked, default не задан: warn, голый 403
