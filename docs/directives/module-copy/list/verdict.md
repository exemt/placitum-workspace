# вердикт

Как из ответов волны получается исход. Бюджет и `pass|block`
без вердикта — [deadline.md](deadline.md). Страница `deny` —
[deny_response.md](deny_response.md).

Фаза — первое слово, как у `waf_capture request`. Режим и порог
у каждой нашей фазы свои.

```
waf_deny_mode request|response|frame fast|deterministic;
waf_score_deny request|response|frame <n> [response=<name>];
```

Контекст: `http`, `server`, `location`, наследуемая.

`response` первым словом — фаза. `response=` — страница каталога.
Это разные токены.

Лестница после закрытия волны, не по мере прихода:

```
1  явный deny
2  сумма >= waf_score_deny <фаза>   # 0 — порог выкл
3  redirect                         # в response нет
4  иначе allow
```

`mode=passive` ни на одной ступени не гейтит: счёт в тень, в лог.

Челлендж модуль сам не ставит. Кому капчу — решает сервис,
он видит счёт в `score` и шлёт `redirect`. Цель —
[redirect.md](redirect.md), cookie — [cookie.md](cookie.md).

```nginx
http {
    waf_deny_response blocked     status=403 page=@waf_deny;
    waf_deny_response suspicious  status=403 page=@waf_deny;

    waf_deny_mode request fast;
    waf_score_deny request 0;        # копим, не режем. подбор порога

    location /api/ {
        waf_deny_mode request deterministic;
        waf_score_deny request 100 response=suspicious;

        waf_inspect request allow_ip  wave=0 timeout=5ms;
        waf_inspect request sqli      wave=1 timeout=15ms weight=1.0;
        waf_inspect request modsec    wave=1 timeout=1000ms;
        waf_inspect request challenge wave=2 timeout=10ms weight=0;
    }
}
```

Челлендж — поздняя волна: к вызову счёт уже есть, его `redirect`
не перебивает будущий `deny` соседей по волне.

Нет строки `response` / `frame` — как `request`. Фаз ещё нет.
В response `redirect` запрещён: заголовки уже в пути.

`waf_request_deny_mode` / `waf_response_deny_mode` /
`waf_request_score_deny` / `waf_response_score_deny` сняты.
Без фазы — `nginx -t`.

# waf_deny_mode

`fast` — первый пришедший `deny` (или `redirect`) замыкает фазу.
Два почти одновременных `deny` — гонка страниц.

`deterministic` — ждём всю волну, победитель по порядку
`waf_inspector` в `http` (меньший индекс). Не по `waf_inspect`.

Умолчание: `fast`. Аудит в обоих режимах видит все ответы волны.

# waf_score_deny

Порог. Сравнение нестрогое: `сумма >= n`. `0` — выкл: вердикты
`score` едут в аудит, исход не меняют.

`response=` — запись каталога на отказ по порогу. Нет —
[deny_default.md](deny_default.md). Обычно своя страница:
ложные срабатывания чаще всего отсюда.

Порог смотрим после волны, не по каждому ответу. Гонки нет:
вклады неотрицательны, пересечение необратимо.

Промежуточной ступени «челлендж при 60» в модуле нет.

# правила

- нет фазы — `nginx -t`
- порог меньше 0 — `nginx -t`
- `response=` на несуществующее имя — `nginx -t`
- нет `response` / `frame` — берёт `request`
- `passive` `deny` исход не меняет
- набранный на ранних волнах порог — дальние волны не публикуются
- `waf_request_deny_mode` / `waf_request_score_deny` — `nginx -t`

#TEST waf_score_deny 100 без фазы — nginx -t
#TEST waf_request_score_deny — nginx -t
#TEST score_deny request -1 — nginx -t
#TEST response=неттакой — nginx -t
#TEST score_deny request 0: сумма 200, запрос прошёл, в аудите score
#TEST сумма 100 при пороге 100 — deny, страница suspicious
#TEST fast: два deny, страница того, кто пришёл первым
#TEST deterministic: два deny, страница первого waf_inspector в http
#TEST challenge в волне 1 со sqli: redirect может обогнать deny
#TEST passive deny: запрос прошёл
#TEST waf_score_deny response 80 response=suspicious — фаза response, страница suspicious
