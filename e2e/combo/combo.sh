#!/bin/sh
# Комбинации ip → CRS → vlai: соло не трогаем, проверяем три новых
# маршрута и то, что волна 0 режет раньше дорогих.
#
# vlai поднимается профилем compose ("--profile vlai"): это тяжёлый контейнер
# с моделью, и в обычном стенде его нет. Проверки с моделью тогда пропускаются
# -- отсутствие контейнера видно в диагностическом заголовке, где просто нет
# слова vlai, и молчаливым провалом это быть не должно.
#
#     docker compose exec -T nginx-1 sh /t/combo/combo.sh
#     docker compose exec -T loadgen k6 run /app/combo.js
#
# Фикстуры бюллетеней — те же, что у t/modsec-vlai. Host не числовой:
# иначе 920350 смазывает порог 50.

set -eu

fail=0
BASE=http://127.0.0.1:8080
FIXTURES=/t/modsec-vlai
HOST='Host: shop.example.com'
SQLI='id=1%27+or+1%3D1--'
ALLOW='X-Forwarded-For: 10.1.2.3'
BLOCK='X-Forwarded-For: 203.0.113.10'
GEO='X-Forwarded-For: 5.8.8.10'

if [ -f /t/e2e/e2e.sh ]; then
    curl_http() { curl "$@"; }
else
    ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
    cd "$ROOT/deploy"
    curl_http() { docker compose exec -T nginx-1 curl "$@"; }
fi

fetch() {
    path=$1
    shift
    raw=$(curl_http -s -D - -o /dev/null -w 'CODE:%{http_code}' -H "$HOST" "$@" "$BASE$path")
    got=$(printf '%s\n' "$raw" | sed -n 's/^CODE://p' | tail -n 1)
    debug=$(printf '%s\n' "$raw" | tr -d '\r' | grep -i '^X-WAF-Debug:' | sed 's/^[^:]*: //')
}

# код игла имя путь [curl]
http() {
    want=$1
    needle=$2
    name=$3
    path=$4
    shift 4

    fetch "$path" "$@"
    if [ "$got" = "$want" ] && printf '%s' "$debug" | grep -q "$needle"; then
        printf 'ok   %-50s %s  %s\n' "$name" "$got" "$needle"
    else
        printf 'FAIL %-50s %s, ожидался %s и %s\n' "$name" "$got" "$want" "$needle"
        printf '     %s\n' "$debug"
        fail=$((fail + 1))
    fi
}

# код есть нет имя путь [curl]
http2() {
    want=$1
    yes=$2
    no=$3
    name=$4
    path=$5
    shift 5

    fetch "$path" "$@"
    if [ "$got" = "$want" ] && printf '%s' "$debug" | grep -q "$yes" \
        && ! printf '%s' "$debug" | grep -q "$no"
    then
        printf 'ok   %-50s %s  %s без %s\n' "$name" "$got" "$yes" "$no"
    else
        printf 'FAIL %-50s %s, ожидался %s, %s, не %s\n' \
            "$name" "$got" "$want" "$yes" "$no"
        printf '     %s\n' "$debug"
        fail=$((fail + 1))
    fi
}

# Поднят ли инспектор модели: на маршруте /ip-vlai/ его слово обязано быть в
# заголовке диагностики. Нет слова -- нет контейнера.
fetch /ip-vlai/ -H "$ALLOW"

if printf '%s' "$debug" | grep -q 'vlai='; then
    HAVE_VLAI=1
else
    HAVE_VLAI=0
fi

echo '--- ip-modsec: адрес режет до CRS ---'
http2 403 'ip=deny' 'modsec=' 'blocklist, волна 0' /ip-modsec/ -H "$BLOCK"
http2 403 'ip=deny' 'modsec=' 'geo RU, волна 0' /ip-modsec/ -H "$GEO"
http 200 'ip=allow' 'allowlist, чисто' /ip-modsec/ -H "$ALLOW"
http 403 'modsec=' "SQLi после ip" "/ip-modsec/?$SQLI" -H "$ALLOW"
http 200 'modsec=' 'RCE JSON, CRS не знает' /ip-modsec/ \
    -H "$ALLOW" -H 'Content-Type: application/json' \
    --data-binary "@$FIXTURES/rce.json"

if [ "$HAVE_VLAI" = 0 ]; then
    echo 'skip волны модели: контейнер vlai не поднят (docker compose --profile vlai up -d)'
else

echo '--- ip-vlai: адрес режет до модели ---'
http2 403 'ip=deny' 'vlai=' 'blocklist, без модели' /ip-vlai/ -H "$BLOCK"
http2 403 'vlai=score/' 'ip=deny' 'RCE JSON, цепочка' /ip-vlai/ \
    -H "$ALLOW" -H 'Content-Type: application/json' \
    --data-binary "@$FIXTURES/rce.json"
http 200 'vlai=score/' 'мягкое описание' /ip-vlai/ \
    -H "$ALLOW" -H 'Content-Type: application/json' \
    --data-binary "@$FIXTURES/mild.json"
http 200 'VLAI_NO_TEXT' 'GET без текста' /ip-vlai/ -H "$ALLOW"

echo '--- ip-modsec-vlai: три волны ---'
http2 403 'ip=deny' 'modsec=' 'blocklist, до CRS' /ip-modsec-vlai/ -H "$BLOCK"
http 403 'modsec=' "SQLi, отказ по CRS" "/ip-modsec-vlai/?$SQLI" -H "$ALLOW"
http2 403 'vlai=score/' 'modsec=deny' 'RCE JSON, модель' /ip-modsec-vlai/ \
    -H "$ALLOW" -H 'Content-Type: application/json' \
    --data-binary "@$FIXTURES/rce.json"
http2 403 'vlai=score/' 'modsec=deny' 'тикет, модель' /ip-modsec-vlai/ \
    -H "$ALLOW" -H 'Content-Type: application/json' \
    --data-binary "@$FIXTURES/ticket.json"
http2 403 'vlai=score/' 'modsec=deny' 'BDU, модель' /ip-modsec-vlai/ \
    -H "$ALLOW" -H 'Content-Type: application/json' \
    --data-binary "@$FIXTURES/bdu.json"
http 200 'VLAI_NO_TEXT' 'GET без текста' /ip-modsec-vlai/ -H "$ALLOW"
http 200 'vlai=score/' 'мягкое описание' /ip-modsec-vlai/ \
    -H "$ALLOW" -H 'Content-Type: application/json' \
    --data-binary "@$FIXTURES/mild.json"

fi

echo '--- диагностика ---'
fetch /ip-modsec/ -H "$BLOCK"
printf '     %-50s %s\n' '/ip-modsec/ block' "$debug"
fetch "/ip-modsec/?$SQLI" -H "$ALLOW"
printf '     %-50s %s\n' '/ip-modsec/ sqli' "$debug"
if [ "$HAVE_VLAI" = 1 ]; then
    fetch /ip-vlai/ -H "$ALLOW" -H 'Content-Type: application/json' \
        --data-binary "@$FIXTURES/rce.json"
    printf '     %-50s %s\n' '/ip-vlai/ rce' "$debug"
    fetch /ip-modsec-vlai/ -H "$ALLOW" -H 'Content-Type: application/json' \
        --data-binary "@$FIXTURES/rce.json"
    printf '     %-50s %s\n' '/ip-modsec-vlai/ rce' "$debug"
    fetch "/ip-modsec-vlai/?$SQLI" -H "$ALLOW"
    printf '     %-50s %s\n' '/ip-modsec-vlai/ sqli' "$debug"
fi

if [ "$fail" -ne 0 ]; then
    echo "провалено: $fail"
    exit 1
fi
echo 'ok'
