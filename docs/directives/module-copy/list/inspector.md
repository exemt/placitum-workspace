# waf_inspector

Реестр в `http`. Кто слушает шину. Что снимаем и в какой волне — не здесь:
снимок — [capture.md](capture.md), вызов фазы — [inspect.md](inspect.md).

```
waf_inspector <name> subject=<subject> [profile=<profile>]
              [audit=<subject>|off]
              [breaker=on|off] [breaker_threshold=<n>]
              [breaker_window=<time>] [breaker_probe=<time>];
```

Контекст: `http`. Имя уникально, без `:`. Максимум 64. Нет `subject=` /
повтор имени — `nginx -t`.

Два имени на один `subject` — один процесс, разный `profile`. В сообщении
поле `route.profile`. Какие профили есть, решает инспектор.

```nginx
http {
    waf_inspector allow_ip     subject=waf.req.ip     profile=allow;
    waf_inspector strict_ip    subject=waf.req.ip     profile=strict;

    waf_inspector sqli         subject=waf.req.sqli;
    waf_inspector modsec       subject=waf.req.modsec profile=strict;
    waf_inspector challenge    subject=waf.req.chal;
    waf_inspector json         subject=waf.req.json;
}
```

`allow_ip` и `strict_ip` — один сервис адреса, на `/` мягкий профиль, на
`/strict/` жёсткий. Не два процесса.

# опции

| | умолчание | |
| --- | --- | --- |
| `subject=` | обязателен | тема публикации |
| `profile=` | `default` | строка → `route.profile` |
| `audit=` | `waf.audit.inspector.<name>` | подробности; `off` — не пишет |
| `breaker=` | `on` | circuit breaker этого имени |
| `breaker_threshold=` | `0.5` | доля таймаутов на окне |
| `breaker_window=` | `10s` | окно |
| `breaker_probe=` | `5s` | период пробы, когда открыт |

# не здесь

`needs=`, `sample=`, `placement=`, `after=`, `role=`, `body=`, `headers=`,
`timeout=`, `weight=`, `phase=`, `mode=` — `nginx -t`. Это вызов
(`waf_inspect request|response|frame`), не реестр.

# правила

- имя один раз на конфигурацию
- больше 64 — `nginx -t`
- без `subject=` — `nginx -t`
- `allow_headers` / `allow_cookies` нет

#TEST повтор имени — nginx -t
#TEST без subject= — nginx -t
#TEST 65-й инспектор — nginx -t
#TEST allow_ip и strict_ip: один subject, в сообщении разный route.profile
#TEST needs= / after= / timeout= на реестре — nginx -t
