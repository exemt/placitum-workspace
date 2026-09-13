# combo — ip → CRS → vlai

Три новых маршрута и один нагрузочный прогон на все семь наборов сразу:
соло `/ip/`, `/modsec/`, `/vlai-deny/` и цепочки `/ip-modsec/`, `/ip-vlai/`,
`/modsec-vlai/`, `/ip-modsec-vlai/`.

Волна 0 — адрес. Заблокированный IP не кормит CRS и модель. Волна 1 — CRS
на `/ip-modsec/` и `/ip-modsec-vlai/`. Волна 2 — модель: то, чего нет в
PL1 (русское описание бюллетеня), закрывает vlai.

Заголовки, query и тело на цепочках кладутся в общий обменник (`waf_store`,
`ttl=15s`, `retain_ttl=5m`) и архивируются на любой исход
(`waf_archive request headers args body ttl=15s`) в бакеты `waf-headers` /
`waf-args` / `waf-bodies`. `when=deny` здесь нарочно нет: иначе allow в карточке
выглядит пустым, хотя якорь в ClickHouse есть.

```sh
cd deploy
docker compose exec -T nginx-1 sh /t/combo/combo.sh
docker compose exec -T loadgen k6 run /app/combo.js
```

Контейнер модели поднимается профилем compose (`docker compose --profile vlai
up -d inspector-vlai`) и в обычном стенде не запущен. Тогда волны модели
пропускаются одной строкой: инспектора нет в заголовке диагностики, а провалом
это быть не должно. Проверки адреса и CRS идут как обычно.

Ступени, классы, наборы и размер тел — `STEPS`, `KINDS`, `PROFILES`, `BODIES`.
Пустой `BODIES` и `orig` оставляют тела как в корпусе; `1k`…`1m` добирают
только POST. С UX то же на `/traffic`, сценарий **ip → CRS → AI**.
