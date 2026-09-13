# waf_store

Горячий обменник. Один на контур, имени нет: маршрут не выбирает.
Сюда кладутся объекты capture / archive / preview. Агент читает
отсюда в S3 и ClickHouse.

```
waf_store driver=<driver> [опции];
```

Контекст: `http`. Второй раз — `is duplicate`. Без `driver=` —
`nginx -t`.

Драйверы: `redis` — внешний, его и ставят. `none` / `inline` —
не кладут так, чтобы агент или инспектор могли прочитать:
непустой capture / archive / preview на маршруте — `nginx -t`.

```nginx
http {
    waf_store driver=redis
              url=redis://redis-1:6379,redis-2:6379
              ttl=30s retain_ttl=5m max=8m pool=4
              op_timeout=5ms;
}
```

Несколько `url` — failover, не шарды. Ключ живёт на одном узле,
инспектор находит его по локатору.

# redis

| | умолчание | |
| --- | --- | --- |
| `url=` | обязателен | один или несколько через запятую |
| `ttl=` | `30s` | жизнь объекта на волне |
| `retain_ttl=` | `5m` | пока агент не забрал archive / preview |
| `max=` | `8m` | потолок значения. `waf_body_limit` больше — `nginx -t` |
| `pool=` | `4` | соединений на воркер, `1`…`64` |
| `connect_timeout=` | `200ms` | |
| `op_timeout=` | `100ms` | GET/SET в бюджете запроса |

`retain_ttl=` меньше `ttl=` — `nginx -t`: архив терял бы ключ
раньше обычного put.

# правила

- обменник один. имени нет
- класть объекты (`waf on` + inspect / archive / preview) без
  внешнего драйвера — `nginx -t`
- маршрут ничего не кладёт — обменник можно не объявлять

#TEST второй waf_store — is duplicate
#TEST без driver= — nginx -t
#TEST capture+inspect при driver=none — nginx -t
#TEST archive при driver=inline — nginx -t
#TEST retain_ttl=10s при ttl=30s — nginx -t
#TEST waf_body_limit больше max= — nginx -t
