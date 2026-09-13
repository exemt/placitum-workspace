# waf_shm_zone

Зона shared memory локального слоя: rate, breaker, слоты
`waf_local_dataset`. Одна на контур.

```
waf_shm_zone <name> <size>;
```

Контекст: `http`. Второй раз — `nginx -t`. Минимум — `256k`.

Любая директива локального слоя без зоны — `nginx -t`, не
молчаливое «выкл». Зона ниже по файлу не помогает: маршрут
разбирается раньше.

Размер reload не меняет. Другой размер — restart воркеров.

```nginx
http {
    waf_shm_zone waf 32m;

    waf_local_dataset blocklist type=cidr ttl=5m active;
    waf_local_check blocklist action=block;
}
```

# что внутри

Счётчик rate — узел на ключ, порядка `64 + длина ключа`.
Набор cidr — плотный массив, на время обновления в зоне оба
набора. Зона кончилась — старые счётчики вытесняются, снапшот
набора отвергается целиком.

# правила

- нет зоны, есть dataset / check / rate — `nginx -t`
- зона объявлена после директивы, которая её требует — `nginx -t`
- меньше `256k` — `nginx -t`

#TEST waf_local_dataset без зоны — nginx -t
#TEST зона после dataset — nginx -t
#TEST вторая waf_shm_zone — nginx -t
#TEST size=128k — nginx -t
