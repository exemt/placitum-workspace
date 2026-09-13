# waf_redirect_allow

Куда инспектору можно увести клиента. Цель приезжает с провода —
жизненный цикл челленджа знает только сервис. Здесь граница:
без списка редирект запрещён, не «куда угодно».

```
waf_redirect_allow <шаблон> [<шаблон>...];
```

Контекст: `http`, `server`, `location`. Набор **заменяется** целиком:
своя строка на location — родительский список не действует.
Строки одного уровня складываются.

Умолчание: пусто. Код с провода — только `302` `303` `307`.
`301` нет: браузер закэширует навсегда.

Модуль к URL ничего не дописывает. Возврат собирает инспектор.

Не прошло ни один шаблон — ответ отброшен, для волны это молчание.
Дальше политика [waf_deadline](deadline.md).

В `response` редиректа нет: заголовки уже в пути.

```nginx
http {
    # везде запрещено: списка нет

    location /login {
        waf_redirect_allow /waf/captcha;
        waf_redirect_allow https://chal.example.com/c/;
        waf_redirect_allow https://*.chal.example.com/;

        waf_inspect request challenge wave=2 timeout=10ms weight=0;
    }
}
```

# шаблон

| | |
| --- | --- |
| `/waf/captcha` | локальный путь, этот префикс и ниже |
| `https://chal.example.com/c/` | схема, хост, порт, префикс пути |
| `https://*.chal.example.com/` | поддомены. сам `chal.example.com` — нет |
| пустой путь у абсолютного | весь хост |

Схема и порт — точно. `https://h` и `https://h:443` — одно.
Хост без регистра. Только `http://` и `https://`.

# правила

- нет списка — любой `redirect` отброшен
- `//host/…` — `nginx -t` (абсолютный без схемы, не путь)
- без `/` и без `http(s)://` — `nginx -t`
- нет хоста / плохой порт — `nginx -t`
- своя строка на location не дополняет родителя, а заменяет

#TEST нет waf_redirect_allow: redirect отброшен, решает deadline
#TEST /waf/captcha: /waf/captcha/x ок, https://evil/ нет
#TEST https://*.chal.example.com/: a.chal ок, chal.example.com нет
#TEST //cdn.example/ — nginx -t
#TEST ftp://… — nginx -t
#TEST код 301 / 200 с провода — ответ отброшен
