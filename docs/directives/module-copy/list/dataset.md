# waf_local_dataset

Слот списка в `http`. Имя — единственный ключ. Записи в директиве не живут
у активного: их шлёт шина. Внутренний список — записи в конфиге, смена
через reload. Проверки — [dataset_ext.md](dataset_ext.md).

Два режима, один из двух обязателен:

```
active     # шина: snapshot / add / remove, без reload nginx
internal   # записи в конфиге. в шину не подписан
```

```
waf_local_dataset <name> type=cidr|string [limit=<n>] [ttl=<time>]
                  active [subject=<subject>];
waf_local_dataset <name> type=cidr|string [limit=<n>] internal;
waf_local_dataset <name> <entry> ...;
```

Контекст: `http`. Имя уникально, до 128 слотов (больше -- `nginx -t` падает). Нужна `waf_shm_zone` раньше
по файлу — иначе `nginx -t`.

`type=regex` — `nginx -t`. Умолчание `type=` — `cidr`. `limit=` — миллион.
`ttl=` — срок overlay: автобан и точечный add без своего ttl. Нет `ttl=` —
живых записей нет, только база снапшота.

Тема `active` набора — `waf.sets.<name>`: её ведёт keeper
([docs/keeper.md](https://github.com/exemt/placitum-keeper/blob/develop/docs/spec.md)) и выводит из имени. `subject=`
директива не принимает — `nginx -t`.

```nginx
waf_shm_zone waf 32m;

# активный: состав с keeper, без reload; тема waf.sets.blocklist -- по имени
waf_local_dataset blocklist type=cidr limit=1000000 ttl=5m active;
waf_local_dataset badua     type=string limit=65536 active;

# внутренний: записи здесь. add/remove с шины нет
waf_local_dataset office type=cidr limit=1024 internal;
waf_local_dataset office 10.0.0.0/8;
waf_local_dataset office 192.168.0.0/16 172.16.0.0/12;
```

# active и internal

| | active | internal |
| --- | --- | --- |
| состав | keeper: дельты и тики на `waf.sets.<name>`, снапшот и хвост по запросу | строки `waf_local_dataset <name> <entry>` |
| смена | без reload | reload nginx |
| `ttl=` | срок overlay (автобан, live add) | нет. задать — `nginx -t` |
| автобан `list=` у rate | да, `.event` на subject | нет: писать некуда |
| пустой слот | пока нет снапшота — промах | нет ни одной `<entry>` — промах |

Оба проверяет `waf_local_check`. Порядок check — приоритет, не режим списка.

Наборы ip-компилятора (`in_nginx=false`) в конфиг не едут: это не слот модуля.

# правила

- повтор имени — `nginx -t`. больше 32 — `nginx -t`
- нет `active` и нет `internal` — `nginx -t`. оба сразу — `nginx -t`
- `<entry>` на `active` — `nginx -t`. состав не из конфига
- `<entry>` на чужое имя / до объявления слота — `nginx -t`
- `type=cidr`: запись — адрес или префикс. иначе `-t`
- `type=string`: точное сравнение по байтам, длина до 256
- снапшот active больше `limit=` — отвергается целиком, действующий остаётся
- internal больше `limit=` — `nginx -t`
- `ttl=` на internal — `nginx -t`
- `waf_local_rate … list=` без `ttl=` берёт ttl списка. нет ни там, ни там — `nginx -t`

#TEST без waf_shm_zone — nginx -t
#TEST без active/internal — nginx -t
#TEST internal с subject= — nginx -t
#TEST entry на active — nginx -t
#TEST office 10.0.0.0/8 до слота — nginx -t
#TEST type=regex — nginx -t
#TEST повтор имени — nginx -t
#TEST internal 1025 записей при limit=1024 — nginx -t
#TEST internal с ttl= — nginx -t
#TEST rate list=blocklist без ttl при списке без ttl= — nginx -t
