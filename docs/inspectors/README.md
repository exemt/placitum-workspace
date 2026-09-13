# Инспекторы

Референсные реализации инспекторов — процессов, подписанных на шину и отвечающих вердиктом по
[docs/verdict-protocol.md](../verdict-protocol.md). Контракт, общий для всех, — в
[docs/inspectors.md](../inspectors.md).

| Каталог | Роль | Статус |
| --- | --- | --- |
| [`ip/`](ip/README.md) | IP фильтр: гео и списки в памяти, горячая перезагрузка файлов | Реализован |
| [`modsec/`](modsec/README.md) | Движок правил SecLang (Coraza со встроенным CRS 4) как инспектор | Фаза запроса реализована; фаза ответа и тело из Redis — нет |
| [`vlai/`](vlai/README.md) | Классификатор серьёзности уязвимости по русскому описанию (CIRCL ruRoBERTa) | Инспектор шины на Python; в e2e не входит |
| [`challenge/`](challenge/README.md) | JS-челлендж: два контейнера, один образ | Черновик; кода нет |
| [`captcha/`](captcha/README.md) | Капча: два контейнера, один образ, не JS | Черновик; кода нет |
| [`auth/`](auth/README.md) | Второй фактор: калитка входа перед приложением, код / список / LDAP / NTLM | Реализован |
| [`json/`](https://github.com/exemt/placitum-json/blob/develop/docs/README.md) | Контракт API: тело и вызов против OpenAPI или JSON Schema, обе фазы | Реализован |
| [`action/`](action/README.md) | Отправитель действий: ничего не проверяет, рассказывает соседям по правилам маршрута | Реализован |
| [`counter/`](counter/README.md) | Счётчик: меряет ответы в именованные корзины (GCRA), судит по уровням на запросе | Реализован |
| [`cookie/`](cookie/README.md) | Кука: выдаёт и снимает Set-Cookie, пишет её значение в живые наборы, рассказывает соседям | Реализован |
| [`rewrite`](../../inspectors/rewrite/README.md) | Правка ответов: тело переписывает сам процесс через обменник, модуль поднимает его на шве фазы ответа | Реализован; спека живёт рядом с кодом |

Общая для всех обвязка живёт копией в каждом модуле — так же, как `flow`, `host` и `pulse`:
`logkit.Sink` из `placitum-shared` (Go) и `src/logsink.py` (Python) уносят журнал процесса в `waf.log` пачкой
`kind=log`. Это требование контракта, а не удобство отдельного инспектора:
[logger/logs.md](../logger/logs.md#требование).

`ip`, `modsec` и `json` написаны на Go по
[nginx/module/README.md#язык](https://github.com/exemt/placitum-node/blob/develop/docs/module/README.md#язык), как и остальные боевые инспекторы и
сайдкары. `vlai` — исключение: классификатор живёт только как Python/PyTorch.

Поднимаются в локальном окружении [../deploy](../../deploy) и проверяются оттуда же:
[`e2e`](../tests/e2e/README.md) — модуль на живых `ip` и `modsec`,
[`ip`](../tests/ip/README.md) — списки и гео IP фильтра,
[`auth`](../tests/auth/README.md) — калитка второго фактора,
[`modsec`](../tests/modsec/README.md) — вердикты по настоящим правилам,
[`json`](../tests/json/README.md) — контракт API на обеих фазах,
[`counter`](../../tests/counter/counter.sh) — счётчик: учёт, суд и отказ по уровню,
[`vlai`](../tests/vlai/README.md) — классификатор серьёзности описания,
[`loadgen/vlai.js`](../../deploy/loadgen/vlai.js) — нагрузка k6 по `/vlai*`.
