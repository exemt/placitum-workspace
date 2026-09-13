# waf_body_limit

Сколько байт тела модуль вообще читает, и что делать с телом
крупнее. Capture / archive `reload` / preview больше этого —
`nginx -t`. То же, если больше `client_max_body_size` или
`max=` обменника.

```
waf_body_limit <size> [block|trim|pass];
```

Контекст: `http`, `server`, `location`, наследуемая.  
Умолчание: `1m block`.

`client_max_body_size 0` — у nginx нет потолка, сравнивать
не с чем. Иначе `waf_body_limit` больше него — `nginx -t`.

```nginx
http {
    client_max_body_size 1m;
    waf_body_limit 1m block;         # отказ, тело не проверено

    location /upload {
        client_max_body_size 64m;
        waf_body_limit 64m pass;     # крупные загрузки, тело не смотрим
    }
}
```

# политика

| | |
| --- | --- |
| `block` | отказать. сверх предела не проверено |
| `trim` | префикс в пределе, локатор `truncated`. sha256 — по целому телу |
| `pass` | пропустить без проверки тела |

`trim` на JSON/XML — не проверка начала: документ обрывается,
правила по `ARGS` пустые. Читается по частям urlencoded и сырой
текст.

# правила

- размер `<= 0` — `nginx -t`
- больше `client_max_body_size` (если тот не 0) — `nginx -t`
- больше `max=` redis — `nginx -t`
- `headers=2m` в capture при лимите `1m` — тоже `nginx -t`:
  модуль такого не читает
- второе слово не `block`/`trim`/`pass` — `nginx -t`

#TEST 2m при client_max_body_size 1m — nginx -t
#TEST 16m при store max=8m — nginx -t
#TEST capture headers=2m при waf_body_limit 1m — nginx -t
#TEST archive reload body=2m при лимите 1m — nginx -t
