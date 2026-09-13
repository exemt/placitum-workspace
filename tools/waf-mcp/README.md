# waf-mcp — MCP-сервер оператора WAF

Даёт агенту рабочее место оператора: разбирать атаки по журналу и
подстраивать контур под клиента через API контроллера. Внутрь контура
(база, NATS, ClickHouse) сервер не лезет — только REST контроллера,
те же ручки, что у панели.

## Запуск

Node ≥ 24, сборки нет — типы стрипаются на лету:

```
npm install
node src/main.ts
```

Окружение:

| Переменная     | Значение                                                       |
| -------------- | -------------------------------------------------------------- |
| `WAF_URL`      | адрес контроллера, по умолчанию `http://127.0.0.1:8080`        |
| `WAF_SPACE`    | имя или uuid пространства; не нужно, если пространство одно    |
| `WAF_READONLY` | `1` — только анализ и чтение, пишущие инструменты не поднимать |

Подключение к Claude Code — `.mcp.json` в корне проекта:

```json
{
  "mcpServers": {
    "waf-operator": {
      "command": "node",
      "args": ["tools/waf-mcp/src/main.ts"]
    }
  }
}
```

Дымовой прогон против живого контроллера (только чтение):

```
node scripts/smoke.ts
```

## Инструменты

Документация (читать до первой правки): `waf_doc` — overview, journal,
inspectors, playbooks. Те же тексты лежат в `docs/` и раздаются ресурсами
MCP.

Ориентация: `waf_map`, `fleet_status`.

Анализ атак: `attacks_search`, `attacks_top`, `attack_card`,
`attack_content`, `findings_search`, `waf_logs`.

Чтение конфигурации: `profile_list`, `profile_get`, `route_get`,
`auth_source_list`, `inspector_declarations`, `dataset_list`, `dataset_get`,
`address_find`, `nginx_preview`, `convergence_status`.

Правки (отключаются `WAF_READONLY=1`): `profile_save`, `profile_restore`,
`profile_delete`, `addresses_add`, `addresses_remove`, `dataset_content_set`,
`dataset_delete`, `route_update`, `route_create`, `route_delete`,
`auth_source_delete`, `inspector_declare`, `publish`.

Удаления необратимы; `409 in_use` — ответ, а не сбой: тело перечисляет,
кто держит объект, ссылки снимаются раньше удаления.

Модель записи как в панели: правка сохраняется, `publish` издаёт её
участникам, сходимость подтверждает применение. Записи адресных наборов —
исключение, они доезжают живьём.
