# waf_deny_response_default

Какая запись каталога, если отказ без своего `response`.
Каталог — [deny_response.md](deny_response.md).

```
waf_deny_response_default <name>;
```

Контекст: `http`, `server`, `location`, наследуемая.  
Умолчание: `blocked`.

```nginx
http {
    waf_deny_response blocked    status=403 page=@waf_deny;
    waf_deny_response too_many   status=429 page=@waf_deny;
    waf_deny_response grpc_denied type=grpc status=7
                      message="blocked by policy";

    waf_deny_response_default blocked;

    location /api/ {
        waf_deny_response_default too_many;
    }

    location /grpc/ {
        waf_deny_response_default grpc_denied;
    }
}
```

Своя строка на location перекрывает родителя целиком.

# правила

- умолчание `blocked`, записи нет, маршрут с инспекторами —
  предупреждение, отказ будет голым `403`
- явно назвали другое имя, записи нет — `nginx -t`
- `response=` на check / rate / score default не подменяет:
  там имя обязано быть в каталоге при `-t`

#TEST default=leak без waf_deny_response leak — nginx -t
#TEST нет blocked при default=blocked и waf on + inspect — warn, голый 403
