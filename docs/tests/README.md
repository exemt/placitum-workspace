# E2E-прогоны

Сквозные проверки живого контура `deploy/`. Каталог монтируется в nginx и
nats-box как `/t`. Генератор нагрузки (wrk) живёт в `deploy/loadgen/` и гоняет
кейсы из `tests/load` через страницу «Трафик» панели.

```
cd deploy
docker compose up -d --wait
```

Папки ниже — самодостаточные шелл-сценарии, гоняются изнутри контейнеров
(`docker compose exec`). Новые разделы `load` и `logic` устроены иначе:
прогон автономен и заводит всё, что ему нужно, через API контроллера, а в
конце сносит. Ни ручных правок конфигов, ни записей в базу, ни отдельно
поднятых процессов. [runner](runner/README.md) — отдельный от них
Node.js e2e-раннер с хоста: структурирован по фазам (заливка конфига через
API → проверка сходимости флота → трафик → проверка хранилищ) и пишет
структурированный отчёт. Не заменяет существующие `.sh` — первый сценарий
(`modsec`) покрывает связку "конфиг через API → флот → аудит/обменник", а не
повторяет матрицу находок CRS из [modsec](modsec/README.md).

| Папка | Что проверяет | Откуда гонять |
| --- | --- | --- |
| [e2e](e2e/README.md) | Модуль на ip и modsec: вердикты, счёт, режимы, прокси, локальный слой | nginx-1 |
| [dataset](dataset/README.md) | Наборы в JetStream: снапшот, дельты, разрыв seq | nats-box |
| [lists](lists/README.md) | Списки контроллера под k6: бан и снятие | nats-box |
| [body](body/README.md) | Тело и заголовки в Redis, предел, удержание под архив | nginx-1 |
| [http](http/README.md) | Директивы `docs/directives/http.md`: лимиты, archive, preview, capture и связки | nginx-1 + nats-box |
| [audit](audit/README.md) | Запись в WAF_AUDIT: подмена локаторов после архивации, превью запроса до ClickHouse | nats-box |
| [ip](ip/README.md) | IP фильтр: probe + HTTP, большой список | хост |
| [auth](auth/README.md) | Калитка второго фактора: вердикты и вход, каталог LDAP, активный список | хост |
| [modsec](modsec/README.md) | CRS: находки и профили | nginx-1 |
| [vlai](vlai/README.md) | Классификатор серьёзности | nginx-1 |
| [modsec-vlai](modsec-vlai/README.md) | Связка CRS → vlai | nginx-1 |
| [combo](combo/README.md) | Комбинации ip → CRS → vlai, нагрузка всех наборов | nginx-1 |
| [procs](procs/README.md) | Процессы nginx после reload | nginx-1 |
| [streams](streams/README.md) | Потоки JetStream при старте nats-box | nats-box |
| [pulse](pulse/README.md) | Фикстура секции `io`: темп, байты и время по каналам | nats-box |
| [runner](runner/README.md) | Node.js e2e-раннер по фазам (конфиг → флот → трафик → обменник); сценарий `modsec` | хост |
| [load](load/README.md) | Нагрузочные кейсы: полный цикл через API — завести с нуля, издать, нагрузить, рассудить, снести. Стенд до и после пуст | хост |
| [logic](logic/README.md) | Логические кейсы: что решает контур на конкретном запросе. Отказ одного из многих, выключение соседа просьбой, отказ по сумме очков | хост |
