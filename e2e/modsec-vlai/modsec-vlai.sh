#!/bin/sh
# Связка CRS → vlai: то, что не закрыл modsec, смотрит модель.
#
#     docker compose exec -T nginx-1 sh /t/modsec-vlai/modsec-vlai.sh
#     docker compose exec -T loadgen k6 run /app/chain.js
#
# Host не числовой: иначе 920350 даёт 30 баллов на каждом запросе и смазывает
# порог 50. Фикстуры -- бюллетени без синтаксиса SQLi/XSS, их PL1 не знает.

set -eu

fail=0
BASE=http://127.0.0.1:8080
FIXTURES=/t/modsec-vlai
HOST='Host: shop.example.com'
SQLI='id=1%27+or+1%3D1--'

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

# код иглы имя путь [curl]
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

# код есть нет имя путь [curl]  -- есть и нет подстроки в debug
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

echo '--- CRS один: бюллетень проходит, инъекция нет ---'
http 200 'modsec=' 'RCE JSON на /modsec/' /modsec/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/rce.json"
http 200 'modsec=' 'тикет на /modsec/' /modsec/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/ticket.json"
http 200 'modsec=' 'BDU на /modsec/' /modsec/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/bdu.json"
http 200 'modsec=' 'обход auth на /modsec/' /modsec/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/auth.json"
http 200 'modsec=' 'ключ описание на /modsec/' /modsec/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/priv.json"
http 403 'modsec=' "SQLi на /modsec/" "/modsec/?$SQLI"

echo '--- цепочка: то же тело, модель закрывает ---'
http2 403 'vlai=score/' 'modsec=deny' 'RCE JSON, цепочка' /modsec-vlai/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/rce.json"
http2 403 'vlai=score/' 'modsec=deny' 'тикет, цепочка' /modsec-vlai/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/ticket.json"
http2 403 'vlai=score/' 'modsec=deny' 'BDU, цепочка' /modsec-vlai/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/bdu.json"
http2 403 'vlai=score/' 'modsec=deny' 'обход auth, цепочка' /modsec-vlai/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/auth.json"
http2 403 'vlai=score/' 'modsec=deny' 'описание, цепочка' /modsec-vlai/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/priv.json"
http 403 'vlai=score/' 'query description, цепочка' \
    '/modsec-vlai/?description=%D0%A3%D0%B4%D0%B0%D0%BB%D1%91%D0%BD%D0%BD%D1%8B%D0%B9%20%D0%B7%D0%BB%D0%BE%D1%83%D0%BC%D1%8B%D1%88%D0%BB%D0%B5%D0%BD%D0%BD%D0%B8%D0%BA%20%D0%BC%D0%BE%D0%B6%D0%B5%D1%82%20%D0%B2%D1%8B%D0%BF%D0%BE%D0%BB%D0%BD%D0%B8%D1%82%D1%8C%20%D0%BF%D1%80%D0%BE%D0%B8%D0%B7%D0%B2%D0%BE%D0%BB%D1%8C%D0%BD%D1%8B%D0%B9%20%D0%BA%D0%BE%D0%B4.'

echo '--- цепочка: CRS набрал порог сам ---'
# Аномалия PL1 на одной инъекции -- ровно 50. Волна 1 всё равно уходит:
# порог замыкает фазу как deny, но ai уже видит пустое тело и отвечает allow.
http 403 'modsec=score/' 'SQLi, отказ по CRS' "/modsec-vlai/?$SQLI"
http 403 'vlai=allow/VLAI_NO_TEXT' 'SQLi, модель без текста' "/modsec-vlai/?$SQLI"

echo '--- цепочка: пустое и мягкое ниже порога ---'
http 200 'VLAI_NO_TEXT' 'GET без текста' /modsec-vlai/
http 200 'vlai=score/' 'мягкое описание' /modsec-vlai/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/mild.json"

echo '--- диагностика ---'
fetch /modsec/ -H 'Content-Type: application/json' --data-binary "@$FIXTURES/rce.json"
printf '     %-50s %s\n' '/modsec/ rce' "$debug"
fetch /modsec-vlai/ -H 'Content-Type: application/json' --data-binary "@$FIXTURES/rce.json"
printf '     %-50s %s\n' '/modsec-vlai/ rce' "$debug"
fetch "/modsec-vlai/?$SQLI"
printf '     %-50s %s\n' '/modsec-vlai/ sqli' "$debug"
fetch /modsec-vlai/ -H 'Content-Type: application/json' --data-binary "@$FIXTURES/mild.json"
printf '     %-50s %s\n' '/modsec-vlai/ mild' "$debug"

if [ "$fail" -ne 0 ]; then
    echo "провалено: $fail"
    exit 1
fi
echo 'ok'
