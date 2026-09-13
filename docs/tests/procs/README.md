# procs — процессы nginx

В образе нет `ps`. После reload нужно видеть, что старые воркеры ушли.

```sh
cd deploy
docker compose exec -T nginx-1 sh /t/procs/procs.sh
```

Печатает pid и cmdline из `/proc`.
