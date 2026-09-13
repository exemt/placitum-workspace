# modsec — инспектор правил (CRS)

Вердикты по настоящему CRS на маршрутах `/modsec*`. Тестовых инспекторов
там нет: код и счёт целиком от Coraza.

```sh
cd deploy
docker compose exec -T nginx-1 sh /t/modsec/modsec.sh
docker compose exec -T loadgen k6 run /app/modsec.js
```

Профили default / strict / api, фикстуры allow / deny, пассивный режим,
неизвестный тег. Порог на маршрутах — `waf_score_deny 50`.
