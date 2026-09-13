#!/bin/sh
#
# Списки локального слоя через контроллер.
#
# Прежняя версия заводила наборы e2e_cidr/e2e_ua/e2e_key через API и била в
# маршрут /lists/ риги разработчика (nginx-1..3). Риги на стенде нет, а
# состав активных наборов теперь держит keeper (docs/keeper.md): путь
# «панель → контроллер → keeper → край» проверяется в tests/keeper/keeper.sh
# (набор banned_by_counter, waf_local_check на сервере juice.waf.test,
# дельты, снятие, истечение, новая эпоха, сверка хешей), а правка записей
# из панели -- в tests/auth/list.sh (удаление записи завершает сессию).
#
#     sh tests/lists/lists.sh

exec sh "$(dirname -- "$0")/../keeper/keeper.sh" "$@"
