# waf_local_dataset — как проверять

Слот — [dataset.md](dataset.md). Здесь `waf_local_check`: переменная против
списка, до шины. Первое сработавшее решает.

```
waf_local_check <name> <value> action=block|allow|wave [response=<name>]
                [if <value> in|not in <name>] ...;
waf_local_check none;
```

```
block   # отказать. response= — какая страница
allow   # мимо всего, в том числе волн
wave    # дальше локальный слой не смотрим, идём в waf_inspect request
```

`response=` только у `block`. У `allow` / `wave` задать — `nginx -t`.

`type=cidr` — `$binary_remote_addr` или `$remote_addr`.  
`type=string` — точное сравнение по байтам: `$http_user_agent`, `$http_x_api_key`, …

# бан с контроллера

Состав в UX, на край едет снапшотом. В конфиге адресов нет.

```nginx
waf_local_dataset blocklist type=cidr limit=1000000 ttl=5m active;

location / {
    waf_local_check blocklist $binary_remote_addr action=block
                    response=blocked;
    proxy_pass http://app;
}
```

`203.0.113.77` добавили в `blocklist` на контроллере — следующий запрос с
этого адреса: 403, инспекторы не вызываются. Убрали — снова идёт в волны.

# пропуск с контроллера

`action=allow` — мимо инспекции целиком. Ставить **выше** block.

```nginx
waf_local_dataset allowlist type=cidr limit=1024 active;
waf_local_dataset blocklist type=cidr limit=1000000 ttl=5m active;

location / {
    waf_local_check allowlist $binary_remote_addr action=allow;
    waf_local_check blocklist $binary_remote_addr action=block
                    response=blocked;
    proxy_pass http://app;
}
```

Адрес в обоих списках — побеждает allow: до block не доходим, волн нет.
Нет ни в одном — check молчит, смотрим следующие локальные, потом волны.

# переменная против списка

Строка как пришла. Не CIDR.

```nginx
waf_local_dataset badua type=string limit=65536 active;
waf_local_dataset tokens type=string limit=10000 active;

location / {
    waf_local_check badua  $http_user_agent action=block
                    response=suspicious;
    waf_local_check tokens $http_x_api_key  action=allow;
    proxy_pass http://app;
}
```

UA `sqlmap/1.0` есть в `badua` — отказ.  
Заголовок `X-Api-Key: good` есть в `tokens` — пропуск без волн.  
Ключа нет или другой — check не сработал, дальше инспекторы.

Своя переменная nginx — тот же механизм. `waf_var` сюда не нужна:
она едет инспекторам, [misc.md](misc.md).

# сессии: набор хранит md5

`hash=md5` у набора строк — в наборе лежит md5 значения, а не значение.
Сравнение хеширует само: строка check та же, что и без флага.

```nginx
waf_local_dataset sessions type=string limit=100000 ttl=1h hash=md5 active;

location / {
    waf_local_check sessions $cookie_session action=block
                    response=blocked;
    waf_local_rate  $cookie_session rate=10r/s burst=20 hash=md5
                    response=too_many list=sessions;
}
```

Cookie `session=abc…` — в наборе ищется `md5("abc…")`. Автобан кладёт туда
же md5, на провод уезжает событие с `hashed: true` — keeper второй раз не
считает; инспектор, приславший сырое значение, получит его захешированным
уже у keeper. Панель показывает хеши; вписывают в неё сырое значение.

`hash=md5` у самого `waf_local_rate` — про другое: корзина ведётся по md5
ключа, и JWT в cookie длиннее 255 байт перестаёт молча пропускать правило.
Флаги независимы: корзина по хешу, в набор — сырой ключ, и хеширует ли его
набор, решает набор. Зеркала инспекторов сравнивают сырое: набор с
`hash=md5` — для локального слоя, `if … in` включительно.

```nginx
waf_local_dataset ja3_bad type=string limit=10000 active;

location / {
    waf_local_check ja3_bad $http_x_ja3 action=block
                    response=blocked;
}
```

# подсеть в бане, токен — в волны

`allow` здесь нельзя: токен не должен обходить инспекторов. `wave` —
остальные локальные проверки (бан подсети, rate) не смотрим, идём в волны.

```nginx
waf_local_dataset tokens    type=string limit=10000 active;
waf_local_dataset blocknet  type=cidr   limit=1000000 ttl=5m active;

location / {
    waf_local_check tokens   $http_x_api_key      action=wave;
    waf_local_check blocknet $binary_remote_addr  action=block
                    response=blocked;
    waf_inspect request allow_ip wave=0 timeout=5ms;
    waf_inspect request sqli     wave=1 timeout=15ms;
}
```

Ключ из `tokens` — даже если адрес в `blocknet`, локальный бан и rate
ниже не трогаем: штатные инспекторы.  
Ключа нет, адрес в `blocknet` — 403.  
Нет ни ключа, ни адреса в списке — до волн дойдём сами, как обычно.

# внутренний allow, бан с контроллера

Офис в конфиге. Чёрный список — с контроллера.

```nginx
waf_local_dataset office type=cidr limit=1024 internal;
waf_local_dataset office 10.0.0.0/8;
waf_local_dataset office 192.168.0.0/16;

waf_local_dataset blocklist type=cidr limit=1000000 ttl=5m active;

location / {
    waf_local_check office    $binary_remote_addr action=allow;
    waf_local_check blocklist $binary_remote_addr action=block
                    response=blocked;
}
```

`10.1.2.3` в office — всегда allow, даже если попал в blocklist.  
Смена office — reload. Смена blocklist — без reload.

# автобан в тот же список

Rate кладёт ключ в overlay `blocklist` на `ttl=` списка (или свой).

```nginx
waf_local_dataset blocklist type=cidr limit=1000000 ttl=5m active;

location / {
    waf_local_check blocklist $binary_remote_addr action=block
                    response=blocked;
    waf_local_rate  $binary_remote_addr rate=5r/s burst=5
                    response=too_many list=blocklist;
}
```

Этот запрос уже закрыт 429. Следующие с того же адреса бьются в check —
пока не истечёт 5m. На другие ноды уезжает `.event`.

`action=pass` вместе с `list=` — `nginx -t`.

# снять на маршруте

Наследование заменой: маршрут без своей строки берёт родительские
проверки целиком. Отсутствием строк пустой список не выразить — для
этого есть слово.

```nginx
server {
    waf_local_check blocklist $binary_remote_addr action=block
                    response=blocked;
    waf_local_rate  $binary_remote_addr rate=5r/s burst=5;

    # ни проверок, ни лимитов: серверные сняты
    location /health {
        waf_local_check none;
        waf_local_rate  none;
    }

    # сняты только проверки: лимит сервера продолжает действовать
    location /open/ {
        waf_local_check none;
    }
}
```

`none` и правило на одном уровне — `nginx -t`: одна строка говорит
«здесь не проверяем», вторая называет проверку. Зона для `none` не
нужна: правил нет, в разделяемую память никто не ходит.

# условие if

К каким запросам правило вообще относится.

```
if <значение> in <набор>
if <значение> not in <набор>
```

Хвост строки, любое число раз. Несколько условий — **И**: строка
работает, только если сошлись все. Набор — тот же слот
`waf_local_dataset`, объявленный выше по файлу; неизвестное имя —
`nginx -t`.

Пустое значение — это «нет в наборе», а не отдельный случай: куки нет
— значит, её нет и среди доверенных, и `not in` на ней истинно. Иначе
клиент без куки — самый подозрительный — оставался бы без проверки,
которую условие как раз и включает.

```nginx
waf_local_dataset api_paths type=string limit=1000 internal;
waf_local_dataset api_paths /api/ /v2/;
waf_local_dataset trusted   type=string limit=10000 active;

location / {
    # лимит всюду, кроме путей из набора: второй location не нужен
    waf_local_rate $binary_remote_addr rate=5r/s burst=5
                   response=too_many if $uri not in api_paths;

    # бан только тех, у кого нет доверенной куки
    waf_local_check blocklist $binary_remote_addr action=block
                    response=blocked
                    if $waf_request_cookies.sid not in trusted;
}
```

То же условие принимает `waf_inspect` ([inspect.md](inspect.md)):
инспектора зовут не на всяком запросе.

# селекторы запроса

Значением может быть переменная nginx или селектор модуля.

```
$waf_request_args.<имя>      $waf_request_args.*
$waf_request_cookies.<имя>   $waf_request_cookies.*
$waf_request_headers.<имя>   $waf_request_headers.*
```

Селектор — не переменная nginx: имя переменной набирается только из
`A-Za-z0-9_`, и в `log_format` такая запись распалась бы на
`$waf_request_cookies` и текст `.sid`. Разбирают его сами директивы,
поэтому имя пары — какое пришло с провода: с дефисом, с точкой, в
своём регистре.

Разница с `$cookie_sid` не косметическая: селектор даёт **все**
значения, а не первое. `?sid=ok&sid=inject` — два значения, и набор
спрашивается о каждом. Проверка, смотрящая только на первое вхождение,
обходится добавлением одного параметра.

`*` — все пары объекта. Ключу `waf_local_rate` множество запрещено
(`nginx -t`): один запрос считался бы сразу в несколько счётчиков, и
`rate=` перестал бы значить написанное.

`$waf_response_*` — `nginx -t`: фазы ответа у селекторов ещё нет.

# на кадрах

Те же строки маршрута бегут и на каждом спрошенном кадре WebSocket —
до шины, как на рукопожатии. Проверки по наборам смотрятся все:
адрес, попавший в бан посреди сессии, отсекается на следующем кадре.
`allow` пускает кадр мимо инспекции, `wave` — к волнам, `block`
закрывает соединение записью `response=` (`type=websocket` — код и
причина кадра Close, иначе 1008 с именем правила).

Лимиты считают кадры только с `count=frames`; `requests` и `waves`
на кадрах не смотрятся. Ключ «на соединение» — `$waf_conn_id`, ray
рукопожатия. Переменные кадра: `$waf_frame_opcode`,
`$waf_frame_direction`, `$waf_frame_size` ([frame.md](frame.md)).

```nginx
waf_local_dataset ws_binary type=string limit=8 internal;
waf_local_dataset ws_binary binary;

location /ws/ {
    # двоичные кадры на этом маршруте не ждут: закрыть до шины
    waf_local_check ws_binary $waf_frame_opcode action=block
                    response=ws_policy;
    # бан адреса действует и на живую сессию
    waf_local_check blocklist $binary_remote_addr action=block
                    response=ws_policy;
    # частота кадров по соединению; ключ адреса считал бы все сессии клиента
    waf_local_rate  $waf_conn_id rate=50r/s burst=20 count=frames
                    action=block response=ws_flood;
}
```

Автобан (`list=`) работает и здесь: ключ уезжает в набор и событием на
шину. Направление без волн (`waf_inspect frame:s2c` нет) локальный слой
не видит: кадры там идут мимо всего.

#TEST waf_local_check none: серверные проверки на пути не действуют
#TEST none и проверка на одном уровне — nginx -t
#TEST waf_local_check blocklist без значения — nginx -t
#TEST if по необъявленному набору — nginx -t
#TEST if не сошёлся — строка молчит, запрос идёт дальше
#TEST два if на строке — работает только когда сошлись оба
#TEST ключ rate $waf_request_args.* — nginx -t
