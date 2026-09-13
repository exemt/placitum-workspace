# vlai — классификатор серьёзности

Probe кладёт описание в инлайновое тело на шину. HTTP — `/vlai*`, тело и
query. Точный score модели не фиксируем: Critical ≥ 70, мягкое ниже 50
на `/vlai-deny/`.

```sh
cd deploy
docker compose exec -T nginx-1 sh /t/vlai/vlai.sh
docker compose exec -T loadgen k6 run /app/vlai.js
```

Фикстуры в этой папке: `critical.json`, `mild.json`, `advisory.json`,
`plain.txt`. С хоста скрипт сам ходит в compose; из nginx probe не гоняет.
