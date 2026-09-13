# waf_agent_socket

Unix datagram до агента. Воркер кладёт итог фазы одним `sendto`
без ожидания: агент мёртв или очередь полна — событие потеряно,
запрос не ждёт. В `WAF_AUDIT` пишет агент, не модуль.

```
waf_agent_socket <path>;
```

Контекст: `http`. Умолчания нет.

Нужен при `waf on` и при непустом `waf_archive`. Без сокета
preview и аудит не уезжают.

Путь — тот же хост, что агент. Обычно `/run/waf/verdict.sock`.

```nginx
http {
    waf_agent_socket /run/waf/verdict.sock;
    waf on;
}
```

# правила

- `waf on`, сокета нет — `nginx -t`
- `waf_archive` непустой, сокета нет — `nginx -t`
- путь слишком длинный для sockaddr — `nginx -t`

#TEST waf on без сокета — nginx -t
#TEST archive без сокета — nginx -t
