# бюджет и политики

Запрос идёт тремя кусками: мы (`request`) → приложение → мы
(`response`). Бюджет и сбой — у каждой нашей фазы свои.
Фаза — первое слово, как у `waf_capture request`.

Сколько фаза ждёт и что делать, если вердикта нет.
Как из ответов получается исход — [verdict.md](verdict.md).

```
waf_deadline request|response|frame <time> [pass|block];

waf_on_absent           request|response|frame pass|block;
waf_on_bus_error        request|response|frame pass|block;
waf_on_body_unavailable request|response|frame pass|block;
```

Контекст: `http`, `server`, `location`, наследуемая.

`waf_deadline request` — один таймер на все волны фазы запроса.
Умолчание: `50ms block`. Срок и политика одной строкой.

`timeout=` на [inspect.md](inspect.md) — ожидание одного.
Нет своего — берёт дедлайн своей фазы. Сумма таймаутов больше
дедлайна — побеждает дедлайн, дальние волны не публикуются.

`mode=passive` дедлайн не двигает.

Нет строки `response` / `frame` — берёт `request`. Фаз ещё нет.

Без первого слова — `nginx -t`.
`waf_request_deadline` / `waf_response_deadline` / `waf_on_timeout`
сняты.

```nginx
http {
    waf_deadline request 50ms block;

    location /api/ {
        waf_deadline request 30ms pass;   # доступность важнее покрытия
        waf_on_absent request block;
        waf_on_bus_error request pass;
        waf_on_body_unavailable request block;
    }

    location /account/ {
        waf_on_absent request block;
        waf_on_absent response pass;      # нет json на ответе — не 502
    }
}
```

# политики

Причины разные, в одну директиву не сводим. Каждая — на фазу.

| | событие | умолч. |
| --- | --- | --- |
| второе слово `waf_deadline` | дедлайн или таймаут `active` этой фазы | `block` |
| `waf_on_absent` | на subject этой фазы никого нет. сразу | `block` |
| `waf_on_bus_error` | шина / публикация на этой фазе | `pass` |
| `waf_on_body_unavailable` | обменнику не удалось положить тело этой фазы | `block` |

Тело больше лимита — второе слово [body_limit.md](body_limit.md),
не сюда. `waf_on_body_oversize` снята.

`block` без вердикта — страница из [deny_default.md](deny_default.md).

# pass и счёт

При `pass` ответы, что успели, применяются.
Молчание в сумму кладёт ноль: `waf_deadline request … pass` умеет
увести запрос под [waf_score_deny](verdict.md). То же делает breaker.

# правила

- нет фазы — `nginx -t`
- нет политики — политика родителя этой фазы, иначе умолчание
- нет `response` / `frame` — берёт `request`
- `waf_on_absent block` без фазы — `nginx -t`
- `waf_request_deadline` / `waf_response_deadline` / `waf_on_timeout`
  / `waf_on_body_oversize` — `nginx -t`

#TEST waf_deadline 50ms без фазы — nginx -t
#TEST waf_on_absent block без фазы — nginx -t
#TEST waf_request_deadline — nginx -t
#TEST waf_on_timeout — nginx -t
#TEST waf_on_body_oversize — nginx -t
#TEST timeout=15ms при deadline request 10ms: волна режется дедлайном
#TEST absent request: сразу on_absent request, дедлайн не ждём
#TEST mode=passive молчит: deadline не истекает из-за него
#TEST deadline request pass + частичный набор: переопределения успевших стоят
#TEST нет on_absent response: как request
