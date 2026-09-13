# waf

Главный выключатель. `off` — модуль ничего не делает, включая
локальный слой. `on` без сокета агента — `nginx -t`.

```
waf on|off;
```

Контекст: `http`, `server`, `location`, наследуемая.  
Умолчание: `off`.

```nginx
http {
    waf_agent_socket /run/waf/verdict.sock;
    waf on;                          # весь http

    location /health {
        waf off;                     # здесь пусто
    }
}
```

# страницы проверки: не `off`, а `on` без инспекторов

Страница капчи и форма входа не должны спрашивать инспекторов — иначе
капча требует капчу. Выключать ради этого модуль целиком не надо:
`off` снимает и локальный слой, а он там нужен — забаненный правилом
самой капчи адрес иначе молотит по генерации заданий, а отменённая
сессия ходит на форму.

```nginx
location ^~ /waf/captcha {
    waf on;
    waf_inspect request none;        # рекурсии нет
    waf_archive request none;        # без инспекторов архивировать нечего

    waf_local_check cap_ipban $binary_remote_addr action=block response=blocked;
    waf_local_rate  $binary_remote_addr rate=10r/s burst=10 response=too_many;

    proxy_pass http://captcha-http;
}
```

`waf_archive` без инспекторов — `nginx -t`: архивировать на таком
маршруте нечего.

# правила

- `on` требует `waf_agent_socket` в `http` — иначе аудит и preview
  никуда не уезжают, а конфиг выглядит пишущим
- `off` на location перекрывает родителя целиком
- шина, обменник, зона — отдельные директивы, этот флаг их не заводит
- `on` без инспекторов — обычный маршрут: тело запроса доезжает до
  апстрима, как при `off`. Выбрасывается оно только там, где отвечает
  сам модуль (отказ, редирект, сорванная политика)

#TEST waf on без waf_agent_socket — nginx -t
#TEST location waf off: capture / inspect / local_check не бегут
#TEST waf on + inspect none: POST доезжает до апстрима с телом
#TEST waf on + inspect none + waf_archive request headers — nginx -t
