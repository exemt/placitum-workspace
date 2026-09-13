# waf_cookie_defaults

Атрибуты cookie, которые ставит инспектор (`Set-Cookie` на любом
исходе -- пропуск, `deny`, `redirect`). Присланные `secure` /
`http_only` / `same_site` разбираются и выкидываются. Форс в обе
стороны, не только жёстче.

```
waf_cookie_defaults [secure=on|off] [http_only=on|off]
                    [same_site=Strict|Lax|None];
```

Контекст: `http`, `server`, `location`, наследуемая.  
Умолчание: `secure=on http_only=on same_site=Lax`.

`secure=off` нужен на контуре без TLS: иначе инспектор пришлёт
Secure, браузер не вернёт cookie по `http`, челлендж молча сломается.

`Domain` модуль не ставит. Cookie — host-only, текущий `server_name`.
`Path` и `Max-Age` — как прислал инспектор.

`mode=passive` и `mode=vote` cookie не ставят: с первого не берут
ничего, со второго — только очки. Позже объявленный инспектор
перекрывает раннего.

```nginx
http {
    waf_cookie_defaults secure=on http_only=on same_site=Lax;

    server {                          # внутренний http без TLS
        listen 80;
        waf_cookie_defaults secure=off http_only=on same_site=Lax;
    }
}
```

Челлендж: цель — [redirect.md](redirect.md), атрибуты cookie — здесь.

# правила

- неизвестная опция / опечатка в `on|off` / `same_site=` — `nginx -t`
- `same_site=` только `Strict` `Lax` `None`
- своей строкой можно назвать не все три: неназванное берётся
  у родителя, иначе умолчание

#TEST same_site=lax — nginx -t (нужен Lax)
#TEST secure=true — nginx -t
#TEST secure=off: Set-Cookie без Secure, челлендж по http жив
#TEST passive: Set-Cookie нет
