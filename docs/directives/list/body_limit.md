# waf_body_limit

Сколько байт тела модуль вообще читает на фазе, и что делать с телом
крупнее. Capture / archive `reload` / preview этой фазы больше
этого — `nginx -t`. То же, если больше `client_max_body_size` или
`max=` обменника.

Фаза — первое слово, как у `waf_capture request`. У кадров
направление в том же слове.

```
waf_body_limit request|response|frame|frame:c2s|frame:s2c
               <size> [block|trim|pass];
```

Контекст: `http`, `server`, `location`, наследуемая.
Умолчание: `1m block`. Нет строки `response` / `frame` — берёт
`request`. Без первого слова — `nginx -t`.

Тело фазы — то, что фаза читает: у запроса тело запроса, у ответа
тело апстрима, у кадра полезная нагрузка кадра или собранного
сообщения при `waf_frame_reassemble on` ([frame.md](frame.md)).

`client_max_body_size 0` — у nginx нет потолка, сравнивать не с чем.
Иначе `waf_body_limit request` больше него — `nginx -t`. Ответ и
кадр с `client_max_body_size` не сверяются: у них его нет.

```nginx
http {
    client_max_body_size 1m;
    waf_body_limit request 1m block;      # отказ, тело не проверено

    location /upload {
        client_max_body_size 64m;
        waf_body_limit request 64m pass;  # крупные загрузки, тело не смотрим
    }

    location /api/ {
        waf_body_limit response 512k trim;  # хвост ответа не смотрим
    }

    location /ws/ {
        waf_frame_reassemble on;
        waf_body_limit frame 256k block;    # потолок сборки сообщения
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

На ответе `trim` обычно уместнее `block`: страница крупнее предела
не повод отдать клиенту отказ. На кадрах наоборот — сообщение,
которое не влезло в сборку, дальше не поедет.

# правила

- нет фазы — `nginx -t`
- размер `<= 0` — `nginx -t`
- `request` больше `client_max_body_size` (если тот не 0) — `nginx -t`
- больше `max=` redis — `nginx -t`
- `headers=2m` в capture этой фазы при лимите `1m` — тоже `nginx -t`:
  модуль такого не читает
- второе слово не `block`/`trim`/`pass` — `nginx -t`
- нет `response` / `frame` — берёт `request`
- `waf_frame_max_size` / `waf_message_max` — `nginx -t`

#TEST waf_body_limit 1m без фазы — nginx -t
#TEST request 2m при client_max_body_size 1m — nginx -t
#TEST request 16m при store max=8m — nginx -t
#TEST capture request headers=2m при waf_body_limit request 1m — nginx -t
#TEST archive reload body=2m при лимите 1m — nginx -t
#TEST response 2m при client_max_body_size 1m — принимается: у ответа его нет
#TEST waf_message_max — nginx -t
