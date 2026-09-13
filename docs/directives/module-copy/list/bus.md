# waf_bus

Шина NATS. Одна на контур. Без неё инспекторы не публикуют:
есть `waf_inspector`, нет `waf_bus` — `nginx -t`.

```
waf_bus <url>[,<url>...] [опции];
```

Контекст: `http`. Второй раз — `is duplicate`.

Адреса резолвятся при загрузке, не на запросе. Префикс `nats://`
можно не писать. Порт по умолчанию — `4222`.

`waf_node_id` рядом — [misc.md](misc.md). Нет строки — hostname.

```nginx
http {
    waf_node_id edge-07;
    waf_bus nats://nats-1:4222,nats-2:4222,nats-3:4222
            pending_max=16m payload_max=1m;
}
```

# опции

| | умолчание | |
| --- | --- | --- |
| `name=` | `waf-<hostname>` | имя подключения в мониторинге |
| `user=` `pass=` | — | пароль |
| `token=` | — | токен |
| `connect_timeout=` | `1s` | соединение |
| `reconnect_wait=` | `100ms` | пауза между попытками |
| `ping_interval=` | `10s` | keepalive |
| `pending_max=` | `8m` | исходящий буфер воркера |
| `payload_max=` | `1m` | потолок inspect-пакета. меньше худшего захвата — `nginx -t` |

`tls=` `tls_ca=` `tls_cert=` `tls_key=` `creds=` — ещё нет.
Задать — `nginx -t`, не молчаливый ignore.

# правила

- нет ни одного адреса — `nginx -t`
- имя в адресе не резолвится при `-t` — `nginx -t`
- инспекторы есть, шины нет — `nginx -t`

#TEST второй waf_bus — is duplicate
#TEST инспекторы без waf_bus — nginx -t
#TEST tls=on / creds= — nginx -t (не реализовано)
#TEST пустой список адресов — nginx -t
