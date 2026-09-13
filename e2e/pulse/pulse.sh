#!/bin/sh
#
# Фикстура кадра присутствия: секции `io` и `errors`, hash/rev инспекторов.
# Гоняется из контейнера с клиентом шины, потому что публикует кадры за
# производителей:
#
#     docker compose exec -T nats-box sh /t/pulse/pulse.sh
#
# Команды:
#     run    -- публиковать кадры, пока не прервут (по умолчанию)
#     once   -- один кадр каждого вида и выход
#
# Зачем это есть: секции `io` и `errors` разбирает контроллер и рисует UX, но
# `errors` ни один производитель пока не пишет -- [docs/messages/fleet-pulse.md].
# До тех пор карточки смотреть не на чем, а посмотреть на них надо: форма одна
# на все kind, и ломается она сразу везде.
#
# Участники здесь свои, с приставкой io-: перебивать кадры настоящих нельзя,
# они придут через свои четыре секунды и затрут фикстуру, а карточка будет
# мигать. Через минуту после остановки контроллер уберёт их сам по тишине.

set -u

NATS=${NATS_URL:-nats://nats:4222}
EVERY=${EVERY:-2}
WINDOW=${WINDOW:-10}

say() { printf '%s\n' "$*"; }

pub() {
    nats --server "$NATS" pub "$1" "$2" >/dev/null
}

now() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

# Разброс вокруг основания, чтобы график шевелился, а не стоял полкой.
# $RANDOM есть не во всякой оболочке; секунды есть везде и для графика годятся.
jitter() {
    spread=${RANDOM:-}
    [ -n "$spread" ] || spread=$(date -u +%S)
    echo $(( $1 + spread % $2 ))
}

frame_agent() {
    ops=$(jitter 900 400)
    arch=$(jitter 3 6)
    deny=$(jitter 20 30)
    pub "WAF_STATUS.node.io-edge.agent" '{
        "v":1,"kind":"agent","id":"io-agent-1","node_id":"io-edge",
        "hostname":"io-edge","at":"'"$(now)"'",
        "rps":'"$ops"'.0,
        "codes":{"2xx":'"$ops"'.0,"3xx":0,"4xx":12.5,"5xx":0.5},
        "waf":{"allow":'"$(( ops - deny ))"'.0,"deny":'"$deny"'.0,"challenge":2.5,
               "deadline_hits":0.4,"fail_open":0.2,"fail_closed":0.2},
        "host":{"cpu":{"cores":8,"usage":0.34,"load1":1.2,"load5":1.1,"load15":0.9},
                "memory":{"total":16777216000,"used":5368709120,"available":11408506880},
                "disk":{"total":214748364800,"used":150323855360},
                "uptime_s":86400},
        "bus":{"reconnects":1,"rtt_ms":0.9},
        "window_s":'"$WINDOW"',
        "io":{
          "audit":{"ops":'"$ops"'.0,"in":'"$(( ops * 640 ))"'},
          "archive":{"ops":'"$arch"'.2,"in":'"$(( arch * 1048576 ))"',"out":'"$(( arch * 1048576 ))"',
                     "err":0.1,"p50_ms":12.4,"p95_ms":44.0,"max_ms":118.2}
        },
        "errors":[
          {"at":"'"$(now)"'","msg":"s3: PUT waf-archive/aa10 timeout after 2.0s",
           "count":3,"source":"archive"}
        ]}'
}

frame_inspector() {
    ops=$(jitter 300 200)
    pub "WAF_STATUS.inspector.io-probe.rep1" '{
        "v":1,"kind":"inspector","id":"io-insp-1","name":"io-probe",
        "subject":"waf.req.io-probe","queue":"io-probe","hostname":"io-probe-1",
        "ready":true,"at":"'"$(now)"'",
        "host":{"cpu":{"cores":4,"usage":0.41,"load1":0.8,"load5":0.7,"load15":0.6},
                "memory":{"total":4294967296,"used":1073741824,"available":3221225472},
                "disk":{"total":53687091200,"used":9663676416},
                "uptime_s":3600},
        "bus":{"reconnects":0,"rtt_ms":0.6},
        "work":{"workers":8,"queue_depth":256,"queued":3,"accepted":91240,"shed":0,"expired":2},
        "window_s":'"$WINDOW"',
        "io":{"inspect":{"ops":'"$ops"'.0,"in":'"$(( ops * 2048 ))"',"err":0.4,
                         "p50_ms":1.1,"p95_ms":6.8,"max_ms":31.0}},
        "config_hash":"sha256:aa100000000000000000000000000001","rev":7,"apply":"ok"}'
    pub "WAF_STATUS.inspector.io-probe.rep2" '{
        "v":1,"kind":"inspector","id":"io-insp-2","name":"io-probe",
        "subject":"waf.req.io-probe","queue":"io-probe","hostname":"io-probe-2",
        "ready":true,"at":"'"$(now)"'",
        "host":{"cpu":{"cores":4,"usage":0.29,"load1":0.6,"load5":0.6,"load15":0.5},
                "memory":{"total":4294967296,"used":939524096,"available":3355443200},
                "disk":{"total":53687091200,"used":10737418240},
                "uptime_s":3600},
        "bus":{"reconnects":'"$(jitter 2 3)"',"rtt_ms":1.4},
        "work":{"workers":8,"queue_depth":256,"queued":1,"accepted":88010,"shed":0,"expired":0},
        "window_s":'"$WINDOW"',
        "io":{"inspect":{"ops":'"$(( ops - 40 ))"'.0,"in":'"$(( ops * 1900 ))"',
                         "p50_ms":1.0,"p95_ms":5.2,"max_ms":22.0}},
        "config_hash":"sha256:bb200000000000000000000000000002","rev":6,"apply":"ok",
        "errors":[
          {"at":"'"$(now)"'","msg":"rules: parse profile strict: invalid operator @rxx",
           "source":"apply"}
        ]}'
}

frame_redis() {
    ops=$(jitter 4000 2000)
    pub "WAF_STATUS.store.redis.io-store" '{
        "v":1,"kind":"redis","id":"io-redis-1","name":"io-redis",
        "hostname":"io-redis","ready":true,"at":"'"$(now)"'",
        "host":{"cpu":{"cores":8,"usage":0.18,"load1":0.9,"load5":0.8,"load15":0.7},
                "memory":{"total":8589934592,"used":2147483648,"available":6442450944},
                "disk":{"total":107374182400,"used":32212254720},
                "uptime_s":172800},
        "bus":{"reconnects":0,"rtt_ms":0.3},
        "redis":{"ok":true,"version":"7.4.1","role":"master","used_memory":268435456,
                 "maxmemory":2147483648,"maxmemory_policy":"noeviction","keys":1842,
                 "evicted":'"$(jitter 100 200)"',
                 "hits":91024,"misses":311,"clients":24,"uptime_s":172800},
        "window_s":'"$WINDOW"',
        "io":{"cmd":{"ops":'"$ops"'.0,"in":'"$(( ops * 512 ))"',"out":'"$(( ops * 1400 ))"',
                     "p50_ms":0.2,"p95_ms":0.9,"max_ms":7.0}}}'
}

frame_s3() {
    ops=$(jitter 80 40)
    pub "WAF_STATUS.store.s3.io-store" '{
        "v":1,"kind":"s3","id":"io-s3-1","name":"io-s3",
        "hostname":"io-s3","ready":true,"at":"'"$(now)"'",
        "host":{"cpu":{"cores":8,"usage":0.11,"load1":0.5,"load5":0.5,"load15":0.4},
                "memory":{"total":8589934592,"used":1610612736,"available":6979321856},
                "disk":{"total":107374182400,"used":10737418240},
                "uptime_s":172800},
        "bus":{"reconnects":0,"rtt_ms":0.4},
        "s3":{"ok":true,"version":"2025-04-22","endpoint":"minio:9000","bucket":"waf-archive",
              "region":"us-east-1","objects":48211,"used_bytes":10737418240,
              "capacity":107374182400,"buckets":3,"uptime_s":172800},
        "window_s":'"$WINDOW"',
        "io":{"api":{"ops":'"$ops"'.0,"in":'"$(( ops * 4096 ))"',"out":'"$(( ops * 8192 ))"',
                     "err":0.1}}}'
}

frame_service() {
    ops=$(jitter 700 300)
    pub "WAF_STATUS.service.io-logger.svc1" '{
        "v":1,"kind":"service","id":"io-logger-1","name":"io-logger",
        "hostname":"io-logger","ready":true,"at":"'"$(now)"'",
        "host":{"cpu":{"cores":8,"usage":0.22,"load1":1.0,"load5":0.9,"load15":0.8},
                "memory":{"total":8589934592,"used":2684354560,"available":5905580032},
                "disk":{"total":107374182400,"used":75161927680},
                "uptime_s":43200},
        "bus":{"reconnects":0,"rtt_ms":0.5},
        "work":{"inserted":1204885,"last_batch":512,"lag":'"$(jitter 200 40000)"',
                "clickhouse_ok":true},
        "window_s":'"$WINDOW"',
        "io":{
          "consume":{"ops":'"$ops"'.0,"in":'"$(( ops * 1800 ))"',"p50_ms":0.4,"p95_ms":2.1,"max_ms":9.0},
          "insert":{"ops":'"$ops"'.0,"out":'"$(( ops * 1200 ))"',"err":0.2,
                    "p50_ms":18.0,"p95_ms":96.0,"max_ms":340.0}
        },
        "errors":[
          {"at":"'"$(now)"'","msg":"clickhouse: insert batch 512: connection reset",
           "count":2,"source":"insert"}
        ]}'
}

wave() {
    frame_agent
    frame_inspector
    frame_redis
    frame_s3
    frame_service
}

case "${1:-run}" in
    once)
        wave
        say "кадры опубликованы"
        ;;
    run)
        say "публикую кадры io каждые ${EVERY} с, Ctrl-C для остановки"
        while :; do
            wave
            sleep "$EVERY"
        done
        ;;
    *)
        say "неизвестная команда: $1"
        exit 2
        ;;
esac
