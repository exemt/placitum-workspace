# waf_inspect

Кого опрашивать на фазе. Имя из реестра — [inspector.md](inspector.md).
Что видят все на маршруте — [capture.md](capture.md), одно на всех.

Фаза — первое слово, как у `waf_capture request`. Мы (`request`) →
приложение → мы (`response`). Кадры — `frame`, когда появится апгрейд;
направление у них в том же слове.

```
waf_inspect <фаза> <name> wave=<n> [timeout=<time>]
            [mode=active|passive|vote|off]
            [keep=on|off]                  # только request
            [resume=off|prefer|require]    # только response
            [if <значение> in|not in <набор>] ...;
waf_inspect <фаза> none;

<фаза> = request | response | frame | frame:c2s | frame:s2c
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
`weight=` снят: очки ложатся в сумму как присланы, рычаг — порог
`waf_score_deny` ([verdict.md](verdict.md)); инспектору, который должен
считать, а не решать, — `mode=vote`.
`waf_request_inspect` / `waf_response_inspect` / `waf_frame_inspect`
и `waf_frame_inspectors_c2s` сняты.

`frame` без направления — обе стороны одной строкой, `frame:c2s`
перекрывает одну. На проводе фаза остаётся `frame`, направление
едет в `stream.direction`: у инспектора одна форма сообщения.

`if <значение> in|not in <набор>` — звать не на всяком запросе:
инспектор пропускается, если условие не сошлось, и волна идёт дальше
без него. Синтаксис, наборы и селекторы запроса — общие с локальным
слоем, [dataset_ext.md](dataset_ext.md#условие-if).

Держим ли мы то, что инспектируем, — [hold.md](hold.md).

`response` бежит: ответ удерживается до вердикта, отказ отдаёт страницу
каталога, и ни один байт ответа приложения к клиенту не уходит. Снимка
этой фазы ещё нет — инспектор получает статус, заголовки ответа и
контекст запроса секцией `request_store` ([capture.md](capture.md)).

`frame` разбирается, обработчик апгрейда не поднят.

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
        waf_inspect request sqli      wave=1 timeout=15ms;
        waf_inspect request modsec    wave=1 timeout=1000ms;
        waf_inspect request challenge wave=2 timeout=10ms;

        location /api/ {
            waf_capture request body=4k;
            waf_inspect request allow_ip wave=0 timeout=5ms;
            waf_inspect request sqli     wave=1 timeout=15ms mode=passive;
        }

        location /strict/ {
            waf_inspect request strict_ip wave=0 timeout=5ms;
            waf_inspect request sqli      wave=1 timeout=15ms;
        }

        location /search/ {
            waf_score_deny request 200;
            waf_inspect request sqli   wave=1 timeout=15ms   mode=vote;
            waf_inspect request modsec wave=1 timeout=1000ms mode=vote;
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

        location /leaks/ {
            waf_inspect request  modsec wave=0 timeout=800ms keep=on;
            waf_inspect response modsec wave=0 timeout=800ms
                                 resume=prefer;
        }

        location /ws/ {
            waf_inspect frame:c2s ws_rules   wave=0 timeout=5ms;
            waf_inspect frame:s2c dlp_frames wave=0 timeout=5ms;
        }
    }
}
```

`/` — серверный request: ip → (sqli∥modsec) → challenge.  
`/api/` — свой request, без modsec и challenge. sqli смотрит, не гейтит.  
`/strict/` — тот же subject, что `allow_ip`, профиль `strict`.  
`/search/` — оба считают, ни один не решает: `deny` любого — сто
очков, отказ только при двух голосах (порог 200).  
`/static/` — request никого и capture сброшен: inherit снимка иначе
кладёт hdr/args (или тело) в redis без инспекторов.  
`/account/` — `json` дважды: request и response, волны фаз свои.  
`/leaks/` — тот же `modsec` на обеих фазах: `keep=on` велит ему не
выбрасывать транзакцию, ответив, а `resume=prefer` на ответе ведёт
фазу ответа в тот же экземпляр, где она живёт, и там доигрываются
фазы 3–4 движка.  
`/ws/` — своё имя на каждое направление кадров.

# опции

| | умолчание | |
| --- | --- | --- |
| фаза | обязательна | `request` `response` `frame` `frame:c2s` `frame:s2c` |
| `wave=` | обязателен | номер волны этой фазы |
| `timeout=` | `waf_deadline` этой фазы | ожидание одного |
| `mode=` | `active` | `active` — ждут и гейтит. `passive` — ждут ради лога, счёт в тень, молчание не двигает deadline. `vote` — совещательный: ждут как боевого, очки в живую сумму, `deny` как 100, сам не решает. `off` — не публикуют, пока сосед не поставит `active`/`passive`/`vote` |
| `keep=` | `off` | держать состояние после ответа. только `request` |
| `resume=` | `off` | что делать с удержанным состоянием. только `response` |

# mode=vote

Совещательный голос — четвёртая клетка раскладки «решает / не решает»
на «очки идут / не идут»: три остальные уже названы (`active`,
`passive` и `active` у инспектора, отвечающего `allow`). Инспектор
спрашивается и ждётся как боевой, его молчание и `error` включают
политику фазы как у боевого. Отличие одно — как читается вердикт:
`score` ложится в живую сумму как прислан, `deny` — сотней очков,
`redirect` не применяется и очков не даёт, правки трафика (заголовки,
cookie, args, rewrite) не применяются. Соседям он виден в `prior`
(вердикт как сказан, `score` — что легло в сумму), просить и управлять
вправе. Сколько таких голосов нужно на отказ, говорит `waf_score_deny`.

# mode=off

Режим вызова — `mode=` — умеет меняться на ходу: управляющие глаголы
канала действий ([inspector-actions.md](../../inspector-actions.md#управляющие-глаголы))
ставят вызову соседа `active`, `passive`, `vote` или `off` до конца запроса.
Исполняет их модуль, и адресат у них — не процесс, а **этот вызов**.
Разрешения не требуется: просить вправе любой инспектор, спрошенный на
этом маршруте. Проверяется одно — что адресат здесь действительно стоит
хоть в одной фазе; иначе просьба отбрасывается с `WARN` (однажды на
конфигурацию).

`mode=off` — записан, но не публикуется, пока сосед не поставит `active`
(либо `passive`, `vote`). Снять инспектора с маршрута — убрать строку, а не
выключить её. Выключенный стоит в аудите фазы со `state: "off"`. Кеш
вердикта кадров такие кадры не запоминает.

```nginx
location /ws/ {
    waf_inspect frame:c2s counter wave=0;
    waf_inspect frame:c2s rewrite wave=1 mode=off;
}
```

Срок действия — ось глагола: `request` до конца транзакции (на кадрах
— этого кадра), `conn` — до конца соединения кадров; первый кадр
наследует состояние рукопожатия. Просьба на фазе запроса действует и на
фазе ответа: `off` с запроса снимает и вызов на ответе, а удержанную
`keep=on` транзакцию модуль отпускает по концу запроса, как любое
непотреблённое продолжение.

# keep= и resume=

Одна договорённость, две строки, одно имя. Фаза запроса состояние
**выдаёт**, фаза ответа его **потребляет**, и у каждой стороны своя
опция — чтобы по любой из двух строк было видно, что за ней стоит
вторая.

`keep=on` на строке запроса — модуль шлёт инспектору признак
`resume.want` и ключ. Инспектор оставляет транзакцию открытой и
возвращает в вердикте продолжение: личный subject своего экземпляра и
срок. Без `keep=on` признака нет, и инспектор обязан выбросить
транзакцию, ответив: держать состояние на каждом запросе — платить
памятью за маршруты, которым липкость не нужна.

`resume=` на строке ответа — что делать с тем, что держали. На любой
маршрут с `resume=` модуль шлёт тот же ключ и `require`, в какой бы
subject сообщение ни шло; состояния под ключом может не быть —
экземпляр умер, реестр инспектора был полон, срок истёк.

Кадры продолжения не потребляют: каждый кадр инспектируется сам по
себе — инспектор видит полезную нагрузку и заголовки рукопожатия как
контекст, а транзакцию рукопожатия не продолжает (у GET с апгрейдом
нет тела, и кадр не его часть). `resume=` на `frame` — `nginx -t`;
`keep=on` на рукопожатии websocket-пути — `keep_without_resume`, у
такого пути потребителя нет и не будет. Состояние поперёк кадров
одного соединения — дело инспектора (счётчик по оси `conn`), а не
строки вызова.

| | состояние есть | состояния нет |
| --- | --- | --- |
| `off` | не спрашиваем: групповой subject, инспектор инициализируется заново | — |
| `prefer` | личный subject экземпляра. 503 no-responders — сразу перепубликация в групповой | инспектор переигрывает по контексту запроса, отметка в аудите (`resumed=false`) |
| `require` | личный subject. 503 — `waf_exception … absent` этой фазы, без отката | инспектор отказывает (`MODSEC_RESUME_LOST`), ошибка в его логе |

Пара обязательна в обе стороны и проверяется по **эффективным
маршрутам** — после слияния server/location, по листьям. `keep=on`
без `resume=` у того же имени на поздней фазе — `nginx -t`: память
держится впустую. `resume=` без `keep=on` у того же имени на запросе
— `nginx -t`: продолжать нечего никогда. Сервер с `keep=on` на
запросе и `resume=` в каждом своём location согласован: пара
проверяется там, куда попадает запрос, а не там, где написана строка.
Контроллер ловит то же до рассылки (`keep_without_resume`,
`resume_without_keep`).

Липкость — оптимизация, а не канал данных: сообщение одинаково с
продолжением и без, меняется только адрес. При `prefer` инспектор без
состояния отвечает тем же вердиктом меньшей полноты, а не ошибкой,
поэтому пару можно включить позже и снять в любой момент. `require`
— для маршрутов, где правила фазы ответа смотрят на тело запроса или
на настоящий входящий счёт: там переигровка — не проверка, и отказ
честнее. По умолчанию его не ставят.

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
- `resume=` на `request` — `nginx -t`: фаза запроса продолжение
  выдаёт, а не потребляет
- `resume=` на `frame` — `nginx -t`: кадры инспектируются сами по
  себе, транзакцию рукопожатия не продолжают
- `keep=` на `response` / `frame` — `nginx -t`: держать просят ту
  фазу, которая выдаёт
- `keep=on` без `resume=` у того же имени на поздней фазе того же
  маршрута — `nginx -t`
- `resume=` без `keep=on` у того же имени на `request` того же
  маршрута — `nginx -t`
- `frame` и `frame:c2s` на одном уровне — `nginx -t` для повторённого
  направления: `frame` уже задал оба
- `frame:xxx` — `nginx -t`
- `control=` — `nginx -t`: снят, управляющие глаголы принимает любой
  вызов от любого спрошенного соседа
- `when=` — `nginx -t`: снята, вызов, который ждёт включения, — `mode=off`
- `weight=` — `nginx -t`: снят, очки ложатся как присланы; считать, не
  решая, — `mode=vote`
- `mode=vote` `deny` исход не меняет: сто очков в сумму, дальше порог

#TEST неизвестное имя — nginx -t
#TEST weight=0.5 — nginx -t (inspect-weight-gone)
#TEST mode=vote на request и frame — принимается (inspect-mode-vote-ok)
#TEST mode=vote deny при выключенном пороге: запрос прошёл, score=100 (nginx/tests/bus, /vote/)
#TEST mode=vote deny при пороге 100: отказ по сумме, by=score (/vote-over/)
#TEST mode=vote score: заявка в живой сумме, не в тени (/vote-score/)
#TEST mode=vote в prior: вердикт deny, score 100, weighted нет (/vote-prior/)
#TEST без фазы / без wave= — nginx -t
#TEST waf_request_inspect / phase= — nginx -t
#TEST wave=0 и wave=1: 1 не публикуется, пока 0 не ответила
#TEST /api/: свой request, серверный request не действует, response не сброшен
#TEST нет строки фазы на location: берёт сервер этой фазы
#TEST request none: request не бежит, capture родителя всё ещё кладёт
#TEST request none + capture none: в redis ничего
#TEST mode=passive deny: запрос прошёл, вердикт в debug/аудите
#TEST resume= на request — nginx -t
#TEST resume= на frame — nginx -t
#TEST keep= на response — nginx -t
#TEST keep=on без resume= на маршруте — nginx -t
#TEST resume= без keep=on на маршруте — nginx -t
#TEST keep=on на server, resume= в каждом location — принимается
#TEST if по необъявленному набору — nginx -t
#TEST if не сошёлся — инспектор не публикуется, волна идёт без него
#TEST waf_inspect frame:c2s ws_rules wave=0 — принимается
#TEST waf_inspect frame x wave=0 и следом frame:s2c x wave=0 — nginx -t
#TEST keep=on: фаза запроса шлёт resume.want, инспектор держит транзакцию
#TEST без keep=on: want нет, инспектор выбрасывает транзакцию, ответив
#TEST resume=prefer: 503 no-responders — перепубликация в групповой subject
#TEST resume=prefer: ответ едет в личный subject, resumed=true
#TEST resume=prefer, состояния нет: переигровка, resumed=false
#TEST resume=require, состояния нет: deny MODSEC_RESUME_LOST, error в логе инспектора
#TEST resume=off: личного subject нет, инспектор инициализируется заново
#TEST истёкший ttl_ms продолжения — публикуем в групповой, без лишнего круга
#TEST mode=off — принимается (inspect-mode-off-ok)
#TEST control= — nginx -t (снят)
#TEST when=asked — nginx -t (снята)
#TEST mode=off без active: инспектор не публикуется, в аудите state off (nginx/tests/ws, /quota/)
#TEST active от соседа: следующая волна публикует адресата, mutate доходит
