# Ключ контура

Одна RSA-4096 пара на окружение. Браузер шифрует объекты store на публичную
половину (RSA-OAEP SHA-256). Приватную открывают агенты и crypto-сервис
(спецификация — `docs/spec.md` репозитория crypto) — оба держат один и тот же Secret. Контроллер видит
только публичный PEM и fingerprint — приватный туда не монтируется.

```
node gen.mjs           # если файлов ещё нет
node gen.mjs --force   # заменить пару; старые blob больше не откроются
```

| Файл | Кто видит |
| --- | --- |
| `contour.key` | агенты и crypto-сервис, Secret `waf_node_key` → `WAF_NODE_KEY` |
| `contour.pub` | контроллер, Secret `waf_node_pub` → `CONTROLLER_CRYPTO_PUBLIC_KEY` |

Публичный ключ дальше отдаёт `GET /api/<scope_uuid>/crypto`. Оба файла в
`.gitignore`: это локальный контур, не заготовка для чужого стенда.
