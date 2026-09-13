# runner — e2e по фазам, с хоста

В отличие от остальных `tests/*` (шелл-сценарии внутри контейнеров compose),
этот раннер — Node.js (ESM, без сборки, как [deploy/loadgen](../../../deploy/loadgen))
и гоняется с хоста через опубликованные порты
[deploy/docker-compose.yml](../../../deploy/docker-compose.yml): controller
`:8080`, haproxy `:8081`, redis `:6379`, clickhouse `:8123`. Не требует
нового контейнера.

Каждый сценарий — 4 фазы:

1. **Сброс/заливка конфига** — идемпотентный upsert нужных сущностей через
   API контроллера (rule-files, rule-sets, датасеты и т.п.) и `send`.
2. **Проверка через API** — конфигурация реально применилась (например,
   флот инспекторов сошёлся по `config_hash`/`rev`), а не "подождали и
   надеемся".
3. **Трафик** — ручные HTTP-запросы (или k6) по матрице кейсов.
4. **Проверка хранилищ** — записи в ClickHouse (через API `waf-search` и
   напрямую), housekeeping Redis, и т.п.

В конце — текстовая сводка по фазам в stdout и JSON+txt артефакт в
`reports/` (не в git). Код выхода процесса — число проваленных проверок.

## Запуск

```sh
cd deploy
docker compose up -d --wait

cd ../tests/runner
npm install
npm run test:modsec
```

## Конфигурация окружения

Все адреса — с дефолтами на локальные опубликованные порты, переопределяются
переменными окружения:

| Переменная | По умолчанию |
| --- | --- |
| `WAF_E2E_CONTROLLER` | `http://127.0.0.1:8080` |
| `WAF_E2E_EDGE` | `http://127.0.0.1:8081` |
| `WAF_E2E_REDIS` | `redis://127.0.0.1:6379` |
| `WAF_E2E_CLICKHOUSE` | `http://127.0.0.1:8123` |
| `WAF_E2E_CLICKHOUSE_USER` / `WAF_E2E_CLICKHOUSE_PASSWORD` | `waf` / `waf` |
| `WAF_E2E_CLICKHOUSE_DB` | `waf` |
| `WAF_E2E_SPACE` | `default` |

## Структура

```
lib/
  env.mjs         — адреса сервисов из env с дефолтами
  http.mjs        — fetchJson() к API, rawRequest() к краю nginx
  controller.mjs  — spaces, ruleFiles/ruleSets (list/get/create/update/upsert), rules.send, fleet
  audit.mjs       — клиент waf-search через прокси контроллера (/api/search/audit...)
  clickhouse.mjs  — прямой HTTP-запрос к ClickHouse, мимо API
  redis.mjs       — housekeeping: подсчёт ключей модуля, best-effort
  wait.mjs        — pollUntil() — поллинг до сходимости с таймаутом
  report.mjs      — Report: фазы, проверки ok/FAIL, текстовая сводка, JSON-артефакт
scenarios/
  modsec.mjs      — сценарий WAF modsec (см. ниже)
reports/          — артефакты прогонов, gitignore
```

## Сценарий `modsec`

Проверяет связку "конфиг через API → сходимость флота modsec-инспекторов →
трафик → аудит/обменник" на маршрутах `/modsec-e2e/` и `/modsec-e2e-body/`
([deploy/nginx/nginx.conf](../../../deploy/nginx/nginx.conf)) и профиле `e2e`,
которым владеет только этот тест (профили `default/strict/api/allow/deny` —
общая фикстура, их не трогаем; они и так покрыты [tests/modsec](../modsec/README.md)).

Обе ручки называют один и тот же набор архива — `headers args body` с
`ttl=1h` (час в S3), — и отличаются условием: у `/modsec-e2e/` стоит
`when=deny`, у `/modsec-e2e-body/` условия нет, то есть архив едет на любом
исходе. Исход смотрится один на маршрут, поэтому `when=` решает судьбу всего
набора сразу: на `allow` в `/modsec-e2e/` в S3 не уезжает ничего, а в записи
остаётся описание объекта без адреса — `size` есть, `store`/`driver`/`key`
нет ([directives/list/archive.md](../../directives/list/archive.md)). Поиск
читает объекты из `waf-headers` / `waf-args` / `waf-bodies`. Фаза 4
достаёт каждый заархивированный объект через
`/api/search/audit/:node/:ray/{headers,args,body}` и сверяет содержимое, а не
только размер локатора.

Инспектор в аудите называется `modsec-e2e` — это имя **записи реестра**
(`waf_inspector modsec-e2e subject=waf.req.modsec profile=e2e`), а не имя
сервиса `modsec`. Имя едет в сообщении и возвращается инспектором как есть:
под каким именем процесс объявлен в nginx, знает только само сообщение. Им
маршрут отличает профили одного сервиса, поэтому и `inspectors` в записи, и
`inspector` у находки — `modsec-e2e`. Во флоте (фаза 2) наоборот: там
инстансы сервиса, и они называются `modsec`.

Фаза 1 заводит (или, если содержимое не изменилось, оставляет как есть —
`ruleFiles.upsert`/`ruleSets.upsert` идемпотентны) два rule-файла:

- `e2e-engine` — `SecRuleEngine On` + `SecRequestBodyAccess On`.
- `e2e-canary` — два правила, детектящих фиксированный маркер
  `e2e-modsec-canary-x7q9` в `ARGS` (запрос и тело urlencoded-формы) и в
  заголовке `X-E2E-Canary`. Маркер стабилен между прогонами специально: это
  позволяет повторным запускам не трогать конфиг и не ждать заново сходимость
  флота. Уникальность конкретного прогона обеспечивает не маркер, а `runId` в
  пути запроса.

Фаза 3 бьёт по `/modsec-e2e/<runId>/<case>` или `/modsec-e2e-body/<runId>/<case>`
(уникальный путь — ключ корреляции для фазы 4, без необходимости знать `ray`
заранее) с `User-Agent: waf-e2e-modsec/<runId>`:

| Кейс | Ручка | Запрос | Ожидание |
| --- | --- | --- | --- |
| `clean-no-body` | `/modsec-e2e/` | `GET`, без тела | `200`, `body_size=0`, в S3 ничего: `allow` при `when=deny`, в записи только описание headers |
| `clean-with-body` | `/modsec-e2e-body/` | `POST` urlencoded, безобидное содержимое | `200`, `body_size>0`, тело в S3 |
| `canary-query` | `/modsec-e2e/` | `GET ?q=<маркер>` | `403`, query в обменнике |
| `canary-header` | `/modsec-e2e/` | `GET` + заголовок с маркером | `403`, headers в обменнике |
| `canary-body` | `/modsec-e2e-body/` | `POST` urlencoded, маркер только в теле | `403` **только если тело реально прочитано**, тело в S3 |
| `canary-body-large` | `/modsec-e2e-body/` | то же, тело ~40 КБ | `403`, `body_size≈40000`, тело в S3 |

Фаза 4 сверяет через `/api/search/audit` (прокси в waf-search), напрямую в
ClickHouse (`waf.audit`, независимая сверка количества записей) и через
`/api/search/audit/:node/:ray/findings` — что находки `modsec-e2e` есть на
канареечных кейсах и отсутствуют на чистых. По каждому виду (`headers`
всегда, `args` на query, `body` там, где тело есть) ждёт локатор
`store=archive`/`driver=s3` и читает объект: заголовки должны содержать
`User-Agent` прогона, query — маркер, тело — ровно отправленные байты. Там,
где архив не полагается (`clean-no-body`), ждёт обратного — локатор есть,
адреса в нём нет, — и за содержимым не ходит: объект удалён вместе с
вердиктом. Redis: ключи модуля после архива должны вернуться к числу до
трафика.

### Отказ по не-GET-методам

На `canary-body` и `canary-body-large` клиент получает `403`, как и на
`GET`-кейсах. Так было не всегда: пока страница отказа отдавалась через
именованный location, POST доезжал до статики как есть и получал от неё `405`
при `403` в аудите. Метод на `GET` nginx меняет только в форме `error_page` с
URI, и [deploy/nginx/nginx.conf](../../../deploy/nginx/nginx.conf) теперь
пользуется именно ей — `expectClientStatus` и `expectAuditStatus` на deny
совпадают.

### Что не входит в этот сценарий

- Lifecycle-правила бакета на `1h/` — класс в ключе есть, срок удаления
  задаёт сам MinIO/S3, на стенде правило не навешано.
- Полная матрица профилей `strict/api/allow/deny/passive` и находки самого
  CRS — это [tests/modsec](../modsec/README.md).
