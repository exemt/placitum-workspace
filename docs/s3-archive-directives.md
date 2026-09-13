# Директивы архивации headers/args/body в S3

Сводка по всем директивам и переменным окружения, которые влияют на выгрузку
заголовков, тела запроса или параметров (query string) в S3-совместимое
хранилище (MinIO). Собрано из `nginx/module/directives.md`,
`docs/body-storage.md`, `docs/audit.md` и `nginx/agent/internal/retain`.

> Важно: директива `waf_preview headers|args|body` в этот список **не входит** —
> она кладёт срез данных в саму запись аудита (ClickHouse) и с S3 никак не
> связана. См. раздел [«Что не является архивом»](#что-не-является-архивом-в-s3)
> в конце.

## Главная директива

### `waf_archive request`

```nginx
waf_archive request none | <headers|args|body>[=<size>|none]... [ttl=<time>] [when=allow|deny];
```

- Контекст: `http`, `server`, `location`, наследуемая
- По умолчанию: `none` (архивация выключена)
- Парсинг — `nginx/module/src/core/ngx_http_waf_directives.c`,
  `ngx_http_waf_archive()`

Что делает: после вынесения вердикта модуль **не удаляет** перечисленные
объекты из горячего обменника (Redis), а помечает их в записи аудита полем
`store.archive`. Агент `nginx/agent` забирает объект из Redis, кладёт его в S3
(`PUT`), подменяет локатор в опубликованной записи на `store=archive,
driver=s3` и чистит Redis.

Архив ни от кого не зависит: названный здесь объект снимается потому, что его
назвали, а не потому, что его разрешил `waf_capture`. Тело ради архива читается
принудительно — с той же оговоркой, что и
всегда: больше `waf_body_limit` не прочитает никто.

Первое слово — область: пока только `request`. `response` разбирается и
отвергается при `nginx -t` с «not implemented yet».

Строка настраивает только названные в ней объекты. Строки одного уровня
складываются: так размер (`body=8k`) и `ttl=` называются объекту отдельно, не
заставляя переписывать остальные. Голое `none` очищает набор уровня целиком и
наследуется наравне с непустым. Без `=` — весь объект; `headers=none` — этот
вид выкл.

Параметры:

| Параметр | Значения | Описание |
|---|---|---|
| объект | `headers`, `args`, `body` без `=`, с `=<size>` или `=none`; либо голое `none` | Что архивировать. Без `=` — весь объект, размер режет агент, `=none` выключает вид. Строки уровня складываются, голое `none` очищает уровень |
| `ttl=` | время nginx (`180d`, `1h`, `15s`) или число секунд | Срок хранения в архиве. Едет "на проводе" секундами и становится тегом `waf-retain-ttl` объекта. Без параметра объект хранится вечно. Сам nginx не знает ни бакета, ни адреса |
| `when=` | `allow`, `deny` или оба через запятую | При каких вердиктах архивировать. Без `when=` — любой исход, включая redirect |

Примеры:

```nginx
# выключено (по умолчанию)
waf_archive request none;

# архивировать заголовки и тело только при отказе, хранить полгода
waf_archive request headers ttl=180d when=deny;
waf_archive request body    ttl=180d when=deny;

# то же, но тело в архиве обрезать до 8k
waf_archive request headers ttl=180d when=deny;
waf_archive request body=8k ttl=180d when=deny;

# архивировать всё и всегда, хранить вечно
waf_archive request headers args body;
```

Формат ключа в S3: `<yyyy>/<mm>/<dd>/<node>/<ray>[.<фаза>].<hdr|arg|body>` (у фазы запроса сегмента фазы нет, у ответа — `.response`: ray у них общий). Срока в
ключе нет — удалением занимается lifecycle-правило бакета по тегу
`waf-retain-ttl`, и дублировать ту же величину в имени значило бы иметь два
источника правды.

Пример опубликованной записи (`docs/messages/examples/agent-archive-published.json`):

```json
"store": {
  "headers": { "store": "archive", "driver": "s3",
    "key": "2026/08/15/nginx-1/3f9c1e77-....hdr" },
  "body": { "store": "archive", "driver": "s3",
    "key": "2026/08/15/nginx-1/3f9c1e77-....body" },
  "archive": { "headers": 2592000, "body": 15552000 }
}
```

## Предпосылки (без них `waf_archive request` не работает)

### `waf_store`

```nginx
waf_store driver=redis [url=... ttl=... retain_ttl=... max=... pool=...];
```

- Контекст: `http`, ровно один на конфигурацию
- Драйверы в модуле: `none`, `inline`, `redis`. Драйвера `s3` в модуле **нет**
  — архив в S3 делает только агент.

Горячий обменник, откуда агент забирает объекты. Без него `waf_archive request` —
ошибка при `nginx -t`. Второй `waf_store` — тоже ошибка: обменник один на контур,
и маршруту выбирать не из чего.

`retain_ttl=` — срок хранения в Redis для объектов, ожидающих архивации
агентом. Он длиннее обычного `ttl=`, потому что рассчитан не на волну, а на
GET и PUT агента под нагрузкой.

### `waf_agent_socket`

```nginx
waf_agent_socket /run/waf/verdict.sock;
```

- Контекст: `http`

Unix dgram, по которому уезжает запись аудита вместе с полем `store.archive`.
Без него архивировать некому: объекты пролежали бы в обменнике до конца
`retain_ttl` без единого читателя, и `nginx -t` это отвергает.

### Маршрут с инспекторами

`waf_archive request` на маршруте, где не выбран ни один инспектор, — ошибка
при `nginx -t`: вердикта там не будет, а с ним не будет и записи аудита, к
которой архив привязан.

### `waf_capture` — архиву не нужен

```nginx
waf_capture request headers args body | off;
```

`waf_capture` решает, что видят **инспекторы**, и на архив не влияет ни в какую
сторону. Маршрут с `waf_capture off` и `waf_archive request body` тело
прочитает и в архив отправит — просто ни один инспектор его не увидит.
Эффективная маска снятия — объединение трёх осей:
`capture | archive | preview`. Заданное `waf_preview` само означает «извлечь»;
отдельного `force` нет.

Единственное, что архив не переступает, — абсолютные пределы чтения самого
WAF: `waf_body_limit`, `client_max_body_size`, `large_client_header_buffers`.
Больше прочитанного в архив не попадёт.

## Конфиг агента архивации (`nginx/agent`)

Куда писать и как копить PUT — в [nginx/agent/agent.conf](../nginx/agent/agent.conf),
не в nginx. Путь задаёт `WAF_AGENT_CONFIG`. Окружение перекрывает файл
(три ноды — один файл, разный `WAF_NODE_ID`).

```
s3 {
    endpoint    http://minio:9000
    region      us-east-1
    credentials /run/secrets/waf_s3_creds
    bucket headers waf-headers
    bucket args    waf-args
    bucket body    waf-bodies
}

archive {
    batch headers size=32 timeout=50ms
    batch args    size=32 timeout=50ms
    batch body    size=8  timeout=100ms
}
```

Корзины по видам независимы: S3 не умеет пакетный PUT, поэтому «batch» —
накопить объекты секции и вспышкой сделать N обычных `PutObject`. Запись
аудита публикуется, когда уедут все её секции. `off` — сразу.

Те же поля по-прежнему читаются из окружения, если файла нет.

| Переменная | Тип / default | Назначение |
|---|---|---|
| `WAF_RETAIN_S3_ENDPOINT` | URL | S3 API (MinIO). Если задан, но не хватает бакетов/реквизитов — ошибка на старте |
| `WAF_RETAIN_S3_REGION` | string, `us-east-1` | Регион подписи SigV4 |
| `WAF_RETAIN_S3_CREDENTIALS_FILE` | путь к файлу | `aws_access_key_id` / `aws_secret_access_key` |
| `WAF_RETAIN_BUCKET_HEADERS` | string | Бакет для заголовков (напр. `waf-headers`) |
| `WAF_RETAIN_BUCKET_ARGS` | string | Бакет для query string (напр. `waf-args`) |
| `WAF_RETAIN_BUCKET_BODY` | string | Бакет для тела (напр. `waf-bodies`) |
| `WAF_RETAIN_REDIS_URL` | `redis://...` | Горячий обменник, откуда агент забирает объекты |
| `WAF_RETAIN_REDIS_NODES` | список через запятую | Разрешённые узлы Redis по подсказке локатора |
| `WAF_RETAIN_WORKERS` | int, `4` | Число воркеров архивации |
| `WAF_RETAIN_QUEUE` | int, `1024` | Размер очереди; переполнение → `overload` в записи |
| `WAF_RETAIN_OP_TIMEOUT` | duration, `5s` | Таймаут GET/PUT к Redis/S3 |

Если бакет для конкретного вида объекта пустой, архивация этого вида
выключена — объект уйдёт в записи как `archive_error`, а не молча пропадёт.

Правила удаления настраиваются в бакете по тегу `waf-retain-ttl`, значение
которого агент берёт из `ttl=`. Пример для MinIO —
`core/config/minio/lifecycle.json`; каждому сроку, встречающемуся в конфигурации
nginx, нужно своё правило.

## Что не является архивом в S3

Эти директивы часто путают с архивацией, но они пишут срез данных **в саму
запись аудита** (ClickHouse), а не в S3:

| Директива | По умолчанию | Что делает |
|---|---|---|
| `waf_preview headers=<size>[/<item>] \| none` | `off` | Бюджет для среза заголовков в записи аудита |
| `waf_preview args=<size>[/<item>] \| none` | `off` | Бюджет для среза query string в записи аудита |
| `waf_preview body=<size> \| none` | `off` | Префикс тела (UTF-8) в записи аудита |

Заданное превью само означает «извлечь», даже если объект не просит ни один
инспектор. Размер обязателен; `=none` выключает секцию. Второй размер есть
только у заголовков и строки запроса.

Также `agents/s3/` — это отдельный сервис-сайдкар для health-check MinIO
(пишет присутствие в `WAF_STATUS`), он **не** архивирует headers/body/args и
не связан с `waf_archive request`.
