# Logger

Компонент уехал в свой репозиторий: **[github.com/exemt/placitum-logger](https://github.com/exemt/placitum-logger)**.
Там же его документация — устройство, таблицы ClickHouse, типы сообщений, поиск и установка.

| Документ | Где |
| --- | --- |
| Устройство: два потребителя, почему не движок NATS, что не его | [docs/design.md](https://github.com/exemt/placitum-logger/blob/develop/docs/design.md) |
| Таблицы `waf.audit`, `waf.audit_finding`, `waf.log`, словари | [docs/tables.md](https://github.com/exemt/placitum-logger/blob/develop/docs/tables.md) |
| Типы сообщений на шине | [docs/types.md](https://github.com/exemt/placitum-logger/blob/develop/docs/types.md) |
| Поиск и агрегация инцидентов, ручки | [docs/search.md](https://github.com/exemt/placitum-logger/blob/develop/docs/search.md) |
| Установка: переменные, потоки, compose и Kubernetes | [INSTALL.md](https://github.com/exemt/placitum-logger/blob/develop/INSTALL.md) |

В платформе остаётся то, у чего хозяин — контур, а не логгер:

- [logs.md](logs.md) — журнал процессов: дорога от сокета nginx и от процессов до `waf.log`,
  уровни и отладка. Логгер там только приёмник, писателей больше десятка.
- [../audit.md](../audit.md) — формат событий аудита и каталог полей: контракт всех писателей.
- [../messages/](../messages) — схемы сообщений шины.

Копия кода остаётся в дереве платформы (`logger/`) — она и есть источник выкладки: правки
делаются здесь, ветка компонента собирается из неё ([../delivery.md](../delivery.md)).
