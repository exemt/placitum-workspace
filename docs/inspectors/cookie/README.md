# Инспектор куки

Компонент уехал в свой репозиторий: **[github.com/exemt/placitum-cookie](https://github.com/exemt/placitum-cookie)**.

Выдаёт клиенту подписанную куку, снимает её, пишет значение в живой набор и рассказывает об этом
соседям каналом действий ([inspector-actions.md](../../inspector-actions.md)). Сам ничего не
проверяет и никого не блокирует: по выданной куке решают другие — локальный слой на краю,
автодействия соседей, счётчик.

| Документ | Где |
| --- | --- |
| Профиль, состояния, подпись, запись в наборы, коды причин | [docs/README.md](https://github.com/exemt/placitum-cookie/blob/develop/docs/README.md) |
| Установка: ключ подписи, переменные, требования к маршруту | [INSTALL.md](https://github.com/exemt/placitum-cookie/blob/develop/INSTALL.md) |

В платформе остаётся то, у чего хозяин — контур: канал действий
([inspector-actions.md](../../inspector-actions.md)) и директива
[`waf_cookie_defaults`](../../directives/list/cookie.md), которой маршрут ставит атрибуты куки.

Копия кода остаётся в дереве платформы (`inspectors/cookie/`) — она и есть источник выкладки.
