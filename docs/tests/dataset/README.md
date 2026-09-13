# dataset — наборы модуля

Состав активных наборов держит keeper ([../../keeper.md](https://github.com/exemt/placitum-keeper/blob/develop/docs/spec.md)),
модуль применяет дельты без reload. Прогон — сквозняк через keeper и
управляемые края стенда, `tests/dataset/dataset.sh` делегирует ему:

```sh
sh tests/keeper/keeper.sh
```

Проверяет: запись событием с ответом, дельту на всех краях, `waf_local_check`,
снятие, истечение дельтой keeper, новую эпоху после рестарта keeper и
отсутствие `diverged` в логах краёв. Разбор и сборку наборов на C проверяют
unit-конфиги: `WAF_NGINX_IMAGE=waf-edge-01 node nginx/tests/unit/run.mjs`.
