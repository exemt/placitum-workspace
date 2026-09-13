# lists — списки контроллера под нагрузкой

Три `active` набора (`e2e_cidr`, `e2e_ua`, `e2e_key`) на маршруте `/lists/`.
Сначала точечная проверка кодов, затем soak: тысячи адресов и сотни
add/remove в секунду в обе стороны.

```sh
cd deploy
docker compose exec -T nats-box sh /t/lists/lists.sh
```

Риги `nginx-1..3` с маршрутом `/lists/` на стенде нет, поэтому
`tests/lists/lists.sh` делегирует `tests/keeper/keeper.sh`: путь «панель →
контроллер → keeper → край» проверяется на наборе, объявленном в
`waf_local_check` сервера. Сервер `juice.waf.test` и набор `banned_by_counter`,
на которых это было написано, снесены -- прогон ждёт нового тестового
приложения. Нагрузка — `deploy/loadgen/lists.js`
(рига).

По умолчанию: 200 rps на `/lists/`, пул 2000 CIDR (`10.201.*`, `ttl=0`),
250 пар add+remove/с на `e2e_ua` и на `e2e_key` (`ttl>0`, overlay).
Это около 1000 событий шины в секунду. Крутилки: `K6_RATE`, `K6_DUR`,
`LOAD_POOL`, `LOAD_MUTATE`.

Сценарий: пустые списки → 200, бан адреса / UA / ключа → 403 только у
своего признака, снятие по одному, префикс CIDR, TTL 3 с на строке,
заливка пула, soak, очистка.
