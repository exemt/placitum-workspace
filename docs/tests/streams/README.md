# streams — потоки JetStream

Скрипт уехал в фундамент: [`core/bootstrap/streams.sh`](../../../core/bootstrap/streams.sh).
Это не прогон и никогда им не был — подготовка шины, без которой не стартует логгер, поэтому
место ему в `core`, а не в тестах ([docs/repos.md](../../repos.md)).

`nats-box` гоняет его при старте и остаётся жить для `exec`:

```sh
cd deploy
docker compose exec -T nats-box sh /etc/waf/streams.sh
docker compose exec -T nats-box nats stream ls
```

Создаёт `WAF_AUDIT` (`waf.audit.>`, сутки, 256 МБ) и `WAF_LOG` (`waf.log.>`, сутки, 128 МБ),
оба с `discard old`. Наборы данных потока не требуют: их ведёт keeper по core NATS. Идемпотентно:
существующий поток не трогает. Healthcheck `nats-box` — `nats stream info WAF_AUDIT`.
