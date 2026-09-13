# селекторы и if

Два дополнения локального слоя: чем достать значение из запроса и чем привязать
проверку к условию. Справа от сравнения — всегда набор
[waf_local_dataset](dataset.md), инлайн-списков нет.

# селекторы

```
$waf_request_args.<name>      значения аргумента строки запроса
$waf_request_cookies.<name>   значения куки
$waf_request_headers.<name>   значения заголовка

$waf_request_args.*           все значения аргументов
$waf_request_cookies.*        все значения кук
$waf_request_headers.*        все значения заголовков
```

Это **не переменная nginx**. `ngx_http_script_compile()` набирает имя только из
`A-Za-z0-9_`, поэтому в `log_format` или `map` такая запись распалась бы на
`$waf_request_args` и текст `.sid`. Селектор понимают три места: `waf_local_check`,
`waf_local_rate`, `if`. Обычные переменные там принимаются как раньше.

| | |
| --- | --- |
| `args` | percent-декод, `+` → пробел; имя тоже декодируется |
| `cookies` | trim пробелов, снятие кавычек по краям. декода нет |
| `headers` | значение как пришло |
| имя у `args` / `cookies` | точное |
| имя у `headers` | регистр не важен, `-` и `_` не смешиваются |
| несколько вхождений | проверяются все |
| ничего не нашли | проверка не срабатывает |

Все вхождения, а не первое: `?sid=ok&sid=' or 1=1` — два значения, набор
спрашивается о каждом. Первое-вхождение, как у `$arg_sid`, было бы дырой в один
лишний параметр.

Имя после первой точки берётся целиком: `$waf_request_cookies.sess.id` — кука
`sess.id`. Точка в имени объекта не разделитель.

Тела запроса здесь нет. Локальный слой бежит до чтения тела, и
`$waf_request_post_args` означал бы чтение тела до шины — ровно то, ради чего
локальный слой стоит раньше волн.

`request` в имени — фаза, не украшение: `$waf_response_headers.set-cookie` ляжет
сюда же, когда появится фаза response.

# проверка против списка

Строка как пришла, точное сравнение по байтам — набор `type=string`.

```nginx
waf_local_dataset badua   type=string limit=65536 active;
waf_local_dataset badsid  type=string limit=10000 active;
waf_local_dataset badargs type=string limit=10000 active;

location / {
    # заголовок по имени
    waf_local_check badua  $waf_request_headers.user-agent action=block
                    response=suspicious;
    # кука по имени
    waf_local_check badsid $waf_request_cookies.sid       action=block
                    response=blocked;
    # любой аргумент запроса
    waf_local_check badargs $waf_request_args.*           action=block
                    response=blocked;
}
```

`?q=1&debug=DROP%20TABLE` — в `badargs` спрашивается `1`, потом `DROP TABLE`
(декодированное). Совпало любое — отказ.

# if

```
if <селектор|$переменная> in <dataset>
if <селектор|$переменная> not in <dataset>
```

Принимают `waf_inspect`, `waf_local_check`, `waf_local_rate`. Условие — про
запуск: не сошлось — строка на этом запросе не работает вовсе.

```nginx
waf_local_dataset trusted type=string limit=10000 active;

server {
    # бан не трогает доверенную сессию
    waf_local_check blocklist $binary_remote_addr action=block response=blocked
                    if $waf_request_cookies.sid not in trusted;

    # дорогой инспектор — только для незнакомых
    waf_inspect request sqli   wave=1 timeout=15ms
                if $waf_request_cookies.sid not in trusted;
    # modsec — только подозрительным ua, и тоже не доверенным
    waf_inspect request modsec wave=1 timeout=1s
                if $waf_request_headers.user-agent in greyua
                if $waf_request_cookies.sid not in trusted;
}
```

- несколько `if` в строке — **И**: не сошлось хоть одно, строка не работает.
  ИЛИ пишется через `not in`;
- пустое значение — это «не в наборе», а не отдельный случай: куки нет, значит,
  её нет и в списке доверенных. Поэтому `in` на ней ложно, а `not in` —
  истинно. Направление выбрано так, что отсутствие данных никогда не снимает
  проверку: клиент без куки — самый подозрительный, и он обязан получить
  инспекцию, которую условие включает;
- набор ещё не приехал с контроллера — тоже промах, и по той же причине:
  `not in` на пустом наборе истинно, узел проверяет всех;
- набор объявлен выше по файлу, иначе `nginx -t`. Опечатка в имени иначе
  становится условием, которое никогда не сходится, — то есть тихо снятой
  проверкой;
- условия считаются один раз на запрос: разбор строки запроса и `Cookie`
  кэшируется в контексте, пять инспекторов не разбирают их пять раз.

# пропущенный инспектор

`if` не сошёлся — инспектор не публикуется: волна его не ждёт, дедлайн не
двигает, в счёт не входит, в аудите он `skipped`. Это не таймаут и не
разомкнутый предохранитель: `waf_on_absent` к нему не применяется, потому что
его не спрашивали.

Все инспекторы фазы пропущены — волн нет, запрос идёт как при
`waf_inspect request none`: снимок в Redis не кладётся, шина не трогается.

# правила

- `if` без трёх слов после него (`<значение> in|not in <набор>`) — `nginx -t`
- набор не объявлен выше — `nginx -t`
- селектор без имени (`$waf_request_args.`) — `nginx -t`
- неизвестный объект (`$waf_request_body.x`) — `nginx -t`
- `$waf_request_*.*` ключом `waf_local_rate` — `nginx -t`: у счётчика один ключ,
  а `*` — множество. По имени (`$waf_request_cookies.sid`) ключом можно, берётся
  первое вхождение
- селектор в `log_format` / `map` / `proxy_set_header` — это не переменная,
  nginx разберёт её по-своему; для лога есть [waf_var](misc.md)
- `type=cidr` со селектором — сравнение остаётся адресным: строка обязана быть
  адресом, иначе промах

#TEST waf_local_check badua $waf_request_headers.user-agent — ок
#TEST waf_local_check badargs $waf_request_args.* — ок
#TEST $waf_request_args. без имени — nginx -t
#TEST $waf_request_body.x — nginx -t
#TEST if $waf_request_cookies.sid in — nginx -t (нет набора)
#TEST if $waf_request_cookies.sid in nosuch — nginx -t (набор не объявлен)
#TEST waf_local_rate $waf_request_args.* — nginx -t
#TEST waf_local_rate $waf_request_cookies.sid — ок
#TEST waf_inspect request sqli wave=1 if $waf_request_cookies.sid not in trusted — ок
#TEST два if на одной строке — И
#TEST кука в trusted: sqli не публикуется, в аудите skipped, on_absent не применяется
#TEST куки нет вовсе при "not in trusted": инспектор спрашивается
#TEST ?sid=ok&sid=bad при bad в списке — отказ
#TEST ?q=%27+or+1 при "' or 1" в списке — отказ (декод до сравнения)
