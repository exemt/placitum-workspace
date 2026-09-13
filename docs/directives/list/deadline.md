# бюджет и исключения

Запрос идёт тремя кусками: мы (`request`) → приложение → мы
(`response`). Кадры после апгрейда — `frame`. Бюджет и сбой — у
каждой нашей фазы свои. Фаза — первое слово, как у `waf_capture
request`; у кадров направление в том же слове.

Сколько фаза ждёт и что делать, если вердикта нет.
Как из ответов получается исход — [verdict.md](verdict.md).

```
waf_deadline  <фаза> <time>;

waf_exception <фаза> [timeout|absent|bus|body|inspector|overload]
                     pass|deny [response=<имя>];

<фаза> = request | response | frame | frame:c2s | frame:s2c
```

Контекст: `http`, `server`, `location`, наследуемая.

# waf_deadline

`waf_deadline request` — один таймер на все волны фазы запроса.
Умолчание: `50ms`. Только срок: что делать, не дождавшись,
говорит `waf_exception`.

`timeout=` на [inspect.md](inspect.md) — ожидание одного.
Нет своего — берёт дедлайн своей фазы. Сумма таймаутов больше
дедлайна — побеждает дедлайн, дальние волны не публикуются.

`mode=passive` дедлайн не двигает. `mode=vote` двигает как боевой: его
очки нужны сумме, и ждут его так же.

Нет строки `response` / `frame` — берёт `request`. `frame` без
направления задаёт обе стороны сразу; чтобы у направлений были
разные значения, пишутся две строки — `frame:c2s` и `frame:s2c`,
либо `frame` выше по конфигурации и `frame:s2c` на маршруте.
Дедлайн кадра считается на кадр, а не на соединение.

Фаза ответа бежит. Фаза кадров разбирается, но не бежит.

Без первого слова — `nginx -t`. Политика вторым словом — тоже
`nginx -t`, с подсказкой: она переехала в `waf_exception`.

# waf_exception

Что делать, когда вердикта нет. Одна директива на все причины:
раньше их было четыре — политика вторым словом `waf_deadline` и три
`waf_on_*`, — и каждая новая причина тянула за собой пятую.

| класс | событие | умолч. |
| --- | --- | --- |
| `timeout` | дедлайн фазы либо таймаут `active` инспектора | `deny` |
| `absent` | на subject этой фазы никого нет. сразу | `deny` |
| `bus` | шина, публикация, слоты ожидания (`waf_max_inflight`) | `pass` |
| `body` | обменник не отдал и не принял объект этой фазы; подмена не собралась | `deny` |
| `inspector` | инспектор ответил `verdict: "error"` — «проверить не смог» | `deny` |
| `overload` | тот же `error`, но с `reason.class: "overload"`: запрос сброшен на входе — очередь полна либо бюджет протух до начала работы | `deny` |

Класс необязателен: строка без него задаёт все шесть. Классы
остались потому, что события разной природы — пустой subject это
ошибка развёртывания, а дедлайн перегрузка, — и одна политика на
оба означала бы, что одна из двух настроена неверно всегда.

`inspector` и `overload` разведены по той же причине. «Не смог» —
свойство инспектора: разъехалась схема, не поднялся движок, молчит
соседняя служба; чинится развёрткой, и пропускать такое сутками
никто не хочет. Перегрузка — свойство минуты: инспектор цел, очередь
рассосётся, и на маршруте, где доступность дороже покрытия,
`overload pass` — осмысленный выбор, которого `inspector pass` не
даёт: он отпускал бы и сломанное.

`response=` — запись каталога [deny_response.md](deny_response.md),
которой отвечать на `deny`. Не названа — `503` без каталога: так
модуль отвечал до директивы, и менять код на чужой странице молча
нельзя. У `pass` страницы нет: запрос идёт дальше — `nginx -t`.

Классы `inspector` и `overload` — единственные, о которых сообщает
сам инспектор: `verdict: "error"` вместо вердикта, а сброс на входе
ещё и с `reason.class: "overload"`
([verdict-protocol.md](../../verdict-protocol.md#вердикт-error)).
Обязательный срывает волну сразу, не дожидаясь дедлайна; пассивный
и совещательный не срывают ничего. Остальные четыре класса инспектор не называет и
переопределить не может.

```nginx
http {
    waf_deadline  request 50ms;
    waf_exception request deny;              # все шесть классов

    location /api/ {
        waf_deadline  request 30ms;          # доступность важнее покрытия
        waf_exception request timeout pass;
        waf_exception request bus pass;
        waf_exception request overload pass; # очередь рассосётся, отказ -- нет
    }

    location /account/ {
        waf_exception request absent deny response=error;
        waf_exception response absent pass;  # нет json на ответе — не 502
    }

    location /ws/ {
        waf_deadline  frame     5ms;         # обе стороны
        waf_deadline  frame:s2c 2ms;
        waf_exception frame:s2c timeout pass; # выдача важнее покрытия
    }
}
```

Подмена поверх неполного снимка — сбой подъёма, как пропавший ключ, и
решает его класс `body`: своего рычага у [send.md](send.md#сбой-подъёма)
больше нет, `on_error=` и `waf_on_partial_rewrite` сняты.

Тем же классом разрешается несобранная подмена: две секции `rewrite` на
одной волне и упёршаяся глубина цепочки версий
([verdict-protocol.md](../../verdict-protocol.md#секция-rewrite)). При
`pass` получателю уходит версия, актуальная на начало волны, при `deny`
— отказ. Выбирать победителя из двух правок модуль не берётся: это
тихо потерянная половина работы, а не разрешённый конфликт.

Тело больше лимита — второе слово [body_limit.md](body_limit.md),
не сюда: там триада `block|trim|pass`, и `trim` в исключении не
выражается. `waf_on_body_oversize` снята.

# pass и счёт

При `pass` ответы, что успели, применяются.
Молчание в сумму кладёт ноль: `waf_exception request timeout pass`
умеет увести запрос под [waf_score_deny](verdict.md). То же делает
breaker.

# правила

- нет фазы — `nginx -t`
- нет класса — строка задаёт все пять классов фазы
- класс на уровне назван дважды (в том числе один раз строкой без
  класса) — `nginx -t`: порядок строк ничего не решает, уточняют
  уровнем ниже
- нет строки для класса — класс родителя этой фазы, иначе умолчание
- нет `response` / `frame` — берёт `request`
- `frame` задаёт оба направления, `frame:c2s` — одно
- `frame` и `frame:s2c` на **одном** уровне — `nginx -t`:
  слот уже задан. На разных уровнях — обычное наследование
- `frame:` без направления и `frame:xxx` — `nginx -t`
- `response=` на незаявленную запись — `nginx -t`
- `response=` рядом с `pass` — `nginx -t`
- `waf_deadline <фаза> <time> block` — `nginx -t`: политика переехала
- `waf_on_absent` / `waf_on_bus_error` / `waf_on_body_unavailable`
  — `nginx -t`: сняты
- `waf_request_deadline` / `waf_response_deadline` / `waf_on_timeout`
  / `waf_on_body_oversize` — `nginx -t`

#TEST waf_deadline 50ms без фазы — nginx -t
#TEST waf_deadline request 50ms block — nginx -t: политика переехала
#TEST waf_exception deny без фазы — nginx -t
#TEST waf_exception request deny + waf_exception request bus pass на одном уровне — nginx -t
#TEST waf_exception request timeout deny response=nosuch — nginx -t
#TEST waf_exception request bus pass response=error — nginx -t
#TEST waf_on_absent — nginx -t
#TEST waf_request_deadline — nginx -t
#TEST waf_on_timeout — nginx -t
#TEST waf_on_body_oversize — nginx -t
#TEST timeout=15ms при deadline request 10ms: волна режется дедлайном
#TEST absent request: сразу класс absent, дедлайн не ждём
#TEST mode=passive молчит: deadline не истекает из-за него
#TEST exception request timeout pass + частичный набор: переопределения успевших стоят
#TEST нет exception response absent: как request
#TEST exception request timeout deny response=error: клиент видит статус записи, не 503
#TEST waf_deadline frame 5ms на сервере + frame:s2c 2ms на location: c2s 5ms, s2c 2ms
#TEST waf_deadline frame 5ms и frame:s2c 2ms на одном уровне — nginx -t
#TEST waf_deadline frame:both — nginx -t
#TEST две секции rewrite на одной волне при exception response body pass: клиент получил версию начала волны, applied:false у обеих
#TEST две секции rewrite на одной волне при exception response body deny: отказ записью response=
#TEST глубина цепочки версий сверх предела: класс body этой фазы
