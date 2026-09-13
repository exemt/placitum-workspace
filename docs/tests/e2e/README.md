# e2e — модуль на живом контуре

Проверяет то, что видит клиент: коды и `X-WAF-Debug`.
Инспекторы — `ip` и `modsec`, маршруты — `deploy/nginx/nginx.conf`.

```sh
cd deploy
docker compose exec -T nginx-1 sh /t/e2e/e2e.sh
```

Идёт из контейнера nginx: curl на `127.0.0.1:8080`. В конце подсказка
смотреть `docker compose logs nginx-1 | grep "waf:"`.

Блоки: вердикты ip/CRS, порог счёта, passive/shadow/ignore, локальный rate,
прокси на backend, диагностика, keepalive, 500 запросов на RSS.
