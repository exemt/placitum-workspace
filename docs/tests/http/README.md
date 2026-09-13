# http — директивы тела, архива и превью

Матрица `docs/directives/http.md`: `client_max_body_size`, `waf_body_limit`,
`waf_store`, `waf_archive`, `waf_preview`, `waf_capture` и их связки.
Маршруты — `/http/*` в `deploy/nginx/nginx.conf`, существующие `/body/*` и
`/preview/` не трогаются.

Три прогона. Конфиг — с хоста, остальное — из контейнеров: в nginx нет
клиента шины, в nats-box нет удобного Redis.

```sh
cd deploy
docker compose exec nginx-1 nginx -s reload

# с хоста, образ waf-nginx
sh ../tests/http/conf.sh

docker compose exec -T nginx-1 sh /t/http/http.sh
docker compose exec -T nats-box sh /t/http/audit.sh
```

| Скрипт | Откуда | Что видно |
| --- | --- | --- |
| [conf.sh](../../../tests/http/conf.sh) | хост | `nginx -t`: лимиты, синтаксис, сокет, обменник |
| [http.sh](../../../tests/http/http.sh) | nginx-1 | коды, `X-WAF-Debug`, ключи Redis |
| [audit.sh](../../../tests/http/audit.sh) | nats-box | превью и `store.archive` в `WAF_AUDIT` |

ClickHouse не нужен: срез уже в датаграмме. Если агент не доехал до MinIO,
`audit.sh` всё равно проверяет `store.archive.*.ttl` / `limit` (их пишет
модуль) и размер put; обрезку агента до `limit` — только когда локатор
уже `store=archive`.

На стенде в `http {}` стоит `waf_archive … when=deny`. Строка без `when=`
на location наследует этот исход, поэтому маршруты `/http/*`, которым архив
нужен и на allow, пишут `when=allow,deny` явно.
