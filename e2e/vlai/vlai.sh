#!/bin/sh
# Прогон инспектора vlai (inspectors/vlai).
#
#     docker compose exec -T nginx-1 sh /t/vlai/vlai.sh
#     sh tests/vlai/vlai.sh
#     docker compose exec -T loadgen k6 run /app/vlai.js
#
# Два слоя, как у ip. Probe кладёт описание в инлайновое тело на шину —
# без nginx. HTTP идёт через модуль: /vlai* читает тело и query.
# Точный score модели не фиксируем: Critical-описание должно быть >= 70,
# мягкое — ниже порога 50 на /vlai-deny/.

set -eu

fail=0

# HTTP всегда через nginx: фикстуры лежат в смонтированном /t/vlai.
FIXTURES=/t/vlai
BASE=http://127.0.0.1:8080

if [ -f /t/e2e/e2e.sh ]; then
    curl_http() { curl "$@"; }
    do_probe=0
else
    ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
    cd "$ROOT/deploy"
    curl_http() { docker compose exec -T nginx-1 curl "$@"; }
    do_probe=1
fi

if [ "$do_probe" -eq 1 ]; then
    if docker compose ps --status running --services 2>/dev/null | grep -qx inspector-vlai; then
        vlai() { docker compose exec -T inspector-vlai "$@"; }
    elif docker inspect waf-vlai >/dev/null 2>&1; then
        vlai() { docker exec waf-vlai "$@"; }
    else
        echo 'нет контейнера inspector-vlai / waf-vlai' >&2
        exit 1
    fi
fi

probe() {
    want=$1
    name=$2
    shift 2

    if vlai python /app/src/probe.py --quiet --timeout 8000 --deadline 2000 --expect "$want" "$@"
    then
        printf 'ok   %-46s %s\n' "$name" "$want"
    else
        printf 'FAIL %-46s ожидался %s\n' "$name" "$want"
        fail=$((fail + 1))
    fi
}

# Заголовки на stdout: curl может идти через compose exec.
fetch() {
    path=$1
    shift
    raw=$(curl_http -s -D - -o /dev/null -w 'CODE:%{http_code}' "$@" "$BASE$path")
    got=$(printf '%s\n' "$raw" | sed -n 's/^CODE://p' | tail -n 1)
    debug=$(printf '%s\n' "$raw" | tr -d '\r' | grep -i '^X-WAF-Debug:' | sed 's/^[^:]*: //')
    score=$(printf '%s' "$debug" | sed -n 's/.* score=\([0-9][0-9]*\).*/\1/p')
}

# ожидаемый_код подстрока_debug имя путь [curl...]
http() {
    want=$1
    needle=$2
    name=$3
    path=$4
    shift 4

    fetch "$path" "$@"
    if [ "$got" = "$want" ] && printf '%s' "$debug" | grep -q "$needle"; then
        printf 'ok   %-46s %s  %s\n' "$name" "$got" "$needle"
    else
        printf 'FAIL %-46s %s, ожидался %s и %s\n' "$name" "$got" "$want" "$needle"
        printf '     %s\n' "$debug"
        fail=$((fail + 1))
    fi
}

# мин_счёт имя путь [curl...]
http_score_ge() {
    min=$1
    name=$2
    path=$3
    shift 3

    fetch "$path" "$@"
    if [ "$got" = "200" ] && [ -n "$score" ] && [ "$score" -ge "$min" ] \
        && printf '%s' "$debug" | grep -q 'vlai=score/'
    then
        printf 'ok   %-46s %s  score=%s>=%s\n' "$name" "$got" "$score" "$min"
    else
        shown=$score
        [ -n "$shown" ] || shown=-
        printf 'FAIL %-46s %s  score=%s, ожидался 200 и >=%s\n' \
            "$name" "$got" "$shown" "$min"
        printf '     %s\n' "$debug"
        fail=$((fail + 1))
    fi
}

# макс_счёт имя путь [curl...]
http_score_lt() {
    max=$1
    name=$2
    path=$3
    shift 3

    fetch "$path" "$@"
    if [ "$got" = "200" ] && [ -n "$score" ] && [ "$score" -lt "$max" ] \
        && printf '%s' "$debug" | grep -q 'vlai=score/'
    then
        printf 'ok   %-46s %s  score=%s<%s\n' "$name" "$got" "$score" "$max"
    else
        shown=$score
        [ -n "$shown" ] || shown=-
        printf 'FAIL %-46s %s  score=%s, ожидался 200 и <%s\n' \
            "$name" "$got" "$shown" "$max"
        printf '     %s\n' "$debug"
        fail=$((fail + 1))
    fi
}

show() {
    name=$1
    path=$2
    shift 2

    value=$(curl_http -s -o /dev/null -D - "$@" "$BASE$path" \
        | tr -d '\r' | grep -i '^X-WAF-Debug:' | cut -d' ' -f2-)
    printf '     %-46s %s\n' "$name" "${value:-<нет>}"
}

if [ "$do_probe" -eq 1 ]; then
    echo '--- probe ---'
    probe score 'JSON description, RCE' \
        --body '{"description":"Удалённый злоумышленник может выполнить произвольный код."}'
    probe score 'JSON advisory' \
        --body '{"advisory":"Удалённый злоумышленник может выполнить произвольный код."}'
    probe score 'сырое тело' \
        --body 'Удалённый злоумышленник может выполнить произвольный код.'
    probe score 'query description' \
        --method GET --uri '/?description=Удалённый+злоумышленник+может+выполнить+произвольный+код.'
    probe allow 'пустое тело' --method GET --uri /
    probe allow 'короткий дедлайн' \
        --deadline 1 --body '{"description":"Удалённый злоумышленник может выполнить произвольный код."}'
    probe allow 'фаза frame' \
        --phase frame --body '{"description":"Удалённый злоумышленник может выполнить произвольный код."}'
fi

echo '--- http: /vlai/ ---'
http 200 'VLAI_NO_TEXT' 'GET без текста' /vlai/
http_score_ge 70 'POST JSON description, RCE' /vlai/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/critical.json"
http_score_ge 70 'POST JSON advisory' /vlai/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/advisory.json"
http_score_ge 70 'POST сырое тело' /vlai/ \
    -H 'Content-Type: text/plain' --data-binary "@$FIXTURES/plain.txt"
http_score_ge 70 'GET query description' \
    '/vlai/?description=%D0%A3%D0%B4%D0%B0%D0%BB%D1%91%D0%BD%D0%BD%D1%8B%D0%B9%20%D0%B7%D0%BB%D0%BE%D1%83%D0%BC%D1%8B%D1%88%D0%BB%D0%B5%D0%BD%D0%BD%D0%B8%D0%BA%20%D0%BC%D0%BE%D0%B6%D0%B5%D1%82%20%D0%B2%D1%8B%D0%BF%D0%BE%D0%BB%D0%BD%D0%B8%D1%82%D1%8C%20%D0%BF%D1%80%D0%BE%D0%B8%D0%B7%D0%B2%D0%BE%D0%BB%D1%8C%D0%BD%D1%8B%D0%B9%20%D0%BA%D0%BE%D0%B4.'
http_score_lt 50 'POST мягкое описание' /vlai/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/mild.json"

echo '--- http: /vlai-deny/ (порог 50) ---'
http 403 'vlai=score/' 'RCE выше порога' /vlai-deny/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/critical.json"
http 403 'vlai=score/' 'query RCE выше порога' \
    '/vlai-deny/?description=%D0%A3%D0%B4%D0%B0%D0%BB%D1%91%D0%BD%D0%BD%D1%8B%D0%B9%20%D0%B7%D0%BB%D0%BE%D1%83%D0%BC%D1%8B%D1%88%D0%BB%D0%B5%D0%BD%D0%BD%D0%B8%D0%BA%20%D0%BC%D0%BE%D0%B6%D0%B5%D1%82%20%D0%B2%D1%8B%D0%BF%D0%BE%D0%BB%D0%BD%D0%B8%D1%82%D1%8C%20%D0%BF%D1%80%D0%BE%D0%B8%D0%B7%D0%B2%D0%BE%D0%BB%D1%8C%D0%BD%D1%8B%D0%B9%20%D0%BA%D0%BE%D0%B4.'
http 200 'VLAI_NO_TEXT' 'пустое не обвиняет' /vlai-deny/
http_score_lt 50 'мягкое ниже порога' /vlai-deny/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/mild.json"

echo '--- диагностика ---'
show 'пусто' /vlai/
show 'RCE' /vlai/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/critical.json"
show 'RCE, deny' /vlai-deny/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/critical.json"
show 'мягкое, deny' /vlai-deny/ \
    -H 'Content-Type: application/json' --data-binary "@$FIXTURES/mild.json"

if [ "$fail" -ne 0 ]; then
    echo "провалено: $fail"
    exit 1
fi
echo 'ok'
