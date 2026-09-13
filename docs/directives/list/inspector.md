# waf_inspector

Реестр в `http`. Кто слушает шину. Что снимаем и в какой волне — не здесь:
снимок — [capture.md](capture.md), вызов фазы — [inspect.md](inspect.md).

```
waf_inspector <name> subject=<subject> [profile=<profile>]
              [audit=<subject>|off] [vars=<field>,...|all]
              [breaker=on|off] [breaker_threshold=<n>]
              [breaker_window=<time>] [breaker_probe=<time>];
```

Контекст: `http`. Имя уникально, без `:`. Максимум 64. Нет `subject=` /
повтор имени — `nginx -t`.

Два имени на один `subject` — один процесс, разный `profile`. В сообщении
поле `route.profile`. Какие профили есть, решает инспектор.

Панель это моделирует без копий: каталог перечисляет процессы (тема, фазы,
inspector.conf — по строке на процесс), а второе имя — объявление в
`*.waf.inspectors` со ссылкой `process` и своим `profile`
(controller/src/compile/waf-directives.md). Маршруты зовут только
объявленные имена.

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

# фазы здесь не пишутся

Реестр говорит, **кто** слушает шину, а не **когда** его спрашивают: фазы у
`waf_inspector` нет и не будет. Фаза — первое слово вызова
([inspect.md](inspect.md)), и одно имя спокойно стоит в двух вызовах:

```nginx
waf_inspector modsec subject=waf.req.modsec;

location /api/ {
    waf_inspect request  modsec wave=0 timeout=30ms keep=on;
    waf_inspect response modsec wave=0 timeout=30ms resume=prefer;
}
```

Это не два инспектора и не два процесса: та же тема, тот же профиль, та же
транзакция движка — фазы 1–2 на первом вызове, 3–4 на втором. Связывает их
имя: `keep=on` на первой строке и `resume=` на второй -- одна пара, и
`nginx -t` требует обе половины ([inspect.md](inspect.md#keep-и-resume)).

Что процесс **умеет** вести, знает контроллер: у записи каталога набор фаз, и
набор маршрута предлагает на фазе только тех, кто её умеет. В конфигурацию это
не едет — nginx проверяет не «умеет ли», а «ответил ли», и заявка возможностей
ему ничего не добавляет.

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
| `vars=` | нет | поля секции `vars` в сообщении этому имени: стандартный набор, `waf_var`, `all` ([misc.md](misc.md#кому-что-едет)); без опции секции нет, незнакомое имя — `nginx -t` |

# не здесь

`needs=`, `sample=`, `placement=`, `after=`, `role=`, `body=`, `headers=`,
`timeout=`, `phase=`, `mode=` — `nginx -t`. Это вызов
(`waf_inspect request|response|frame`), не реестр. `weight=` — `nginx -t`
и там, и тут: множителя к счёту больше нет нигде.

# mutate= снят

Права на подмену больше нет: секцию `rewrite` реплая и заголовки фазы
ответа принимают от любой декларации, а версию объекта называет тот, кто
опубликовал новую ссылку ([verdict-protocol.md](../../verdict-protocol.md#секция-rewrite)).
Ключ `mutate=on|off` терпится одно поколение — строка пишется в лог как
снятая и игнорируется, чтобы модуль, раскатанный раньше контроллера, не
уронил пак. Следующим поколением — `nginx -t`, как у прочих снятых имён.

Проверка «маршрут с подменой обязан держать `waf_hold response gate`»
из `nginx -t` ушла: право теперь у всех, и ошибкой на любой `monitor`
она валила бы законные маршруты. Подмена, пришедшая на `monitor`,
выбрасывается в рантайме со строкой WARN — байты у клиента, менять
нечего.

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
#TEST mutate=on в реестре: строка WARN «снят, игнорируется», конфигурация принята
#TEST mutate=on + waf_hold response monitor на листе: nginx -t проходит
#TEST подмена от декларации без всякого mutate=: применена
