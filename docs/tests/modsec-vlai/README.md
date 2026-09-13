# modsec-vlai — связка CRS → модель

То, что не закрыл PL1, смотрит vlai. Одни и те же тела на `/modsec/`
проходят, на `/modsec-vlai/` дают 403. Host не числовой: иначе 920350
набирает 30 баллов на каждом запросе.

```sh
cd deploy
docker compose exec -T nginx-1 sh /t/modsec-vlai/modsec-vlai.sh
docker compose exec -T loadgen k6 run /app/chain.js
```

Фикстуры — бюллетени без синтаксиса SQLi/XSS: `bdu.json`, `ticket.json`,
`rce.json`, `auth.json`, `priv.json`, `mild.json`.
