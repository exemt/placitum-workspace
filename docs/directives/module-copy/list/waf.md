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

# правила

- `on` требует `waf_agent_socket` в `http` — иначе аудит и preview
  никуда не уезжают, а конфиг выглядит пишущим
- `off` на location перекрывает родителя целиком
- шина, обменник, зона — отдельные директивы, этот флаг их не заводит

#TEST waf on без waf_agent_socket — nginx -t
#TEST location waf off: capture / inspect / local_check не бегут
