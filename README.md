# placitum-workspace

Рабочее место разработки Placitum: всё, что не едет клиенту, — стенды, e2e, скрипты,
инструменты, документы платформы. Код компонентов живёт в своих репозиториях
`github.com/exemt/placitum-*`. Их клоны лежат рядом, в этом же каталоге, каждый на своей ветке
(`develop`), и в git рабочего места не попадают.

## Раскладка

```
/opt/placitum/
  core/ shared/ node/ controller/ logger/ crypto/ geo/ keeper/ agents/
  ip/ action/ auth/ captcha/ cookie/ counter/ json/ modsec/ rewrite/ vlai/
                   клоны компонентов, под .gitignore
  go.work          все Go-модули клонов: правка в shared видна соседям сразу
  stand/           стенды: preprod/ — стенд mvm (stand.sh, smoke.sh, stand.env);
                   sources.local.env — сборка из клонов; остальное — стенд Windows из монорепы
  e2e/             сквозные прогоны, витрина, генератор нагрузки — см. e2e/README.md
  tools/           waf-mcp — MCP оператора поверх API
  docs/            документы платформы из монорепы: контракты, планы, справочники
  trusted-docs/    выверенные заметки по NATS и Redis
  landing/ brand/  сайт и знак
  logs/            журналы прогонов стенда, не в git
```

## Клоны компонентов с нуля

```sh
for r in core shared node controller logger crypto geo keeper agents ip action auth captcha cookie counter json modsec rewrite vlai; do
  git clone --branch develop git@github.com:exemt/placitum-$r.git $r
done
```

## Стенд из клонов

```sh
core/install.sh install --sources "$PWD/stand/sources.local.env"
stand/preprod/stand.sh smoke
```

Монорепа `github.com/exemt/AWaf` выведена 13.09.2026: последний коммит `db0ea6a`, выкладка
из неё закрыта. Всё, что было в ней вне компонентов, перенесено сюда из этого коммита; кроме
`private/` (в git монорепы его не было) и `deploy/deliver.mjs` (выкладка больше не нужна).
