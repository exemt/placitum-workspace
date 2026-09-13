# waf_local_dataset — как проверять

Слот — [dataset.md](dataset.md). Здесь `waf_local_check`: переменная против
списка, до шины. Первое сработавшее решает.

```
waf_local_check <name> <variable> action=block|allow|wave [response=<name>]
                [if <variable> in|not in <name>] ...;
```

```
block   # отказать. response= — какая страница
allow   # мимо всего, в том числе волн
wave    # дальше локальный слой не смотрим, идём в waf_inspect request
```

`response=` только у `block`. У `allow` / `wave` задать — `nginx -t`.

`type=cidr` — `$binary_remote_addr` или `$remote_addr`.  
`type=string` — точное сравнение по байтам: `$http_user_agent`, `$http_x_api_key`, …

Куки, аргументы и заголовки по имени, включая «любой из» — селекторы
`$waf_request_cookies.sid` и `$waf_request_args.*`, [select.md](select.md).
Там же `if`: когда эта строка вообще работает.

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

# условие на строку

`if` привязывает проверку к другому списку: не сошлось — строки на этом запросе
нет. Грамматика и правила — [select.md](select.md).

```nginx
waf_local_dataset trusted type=string limit=10000 active;

location / {
    # доверенную сессию бан не трогает
    waf_local_check blocklist $binary_remote_addr action=block
                    response=blocked
                    if $waf_request_cookies.sid not in trusted;
}
```

#TEST кука в trusted: адрес в blocklist, запрос прошёл
#TEST куки нет: "not in" истинно, бан работает как обычно
