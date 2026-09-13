#!/bin/sh
#
# Усечённое структурированное тело: что инспектор правил сообщает о префиксе.
# Гоняется из nats-box -- из контейнера nginx шину не видно, клиента там нет:
#
#     docker compose exec -T nats-box sh /t/audit/truncate.sh
#
# Маршрут /body/truncate/ (deploy/nginx/nginx.conf) держит waf_body_limit 1k
# trim: тело больше предела размещается префиксом, а локатор помечается
# truncated.
#
# Дальше начинается свойство, ради которого этот прогон и существует. Префикс
# JSON обрывается посреди строки и перестаёт быть документом: движок на нём
# сообщил бы об ошибке разбора, ARGS остались бы пустыми, и 942100, которое
# ищет SQLi именно в ARGS, промолчало бы о признаке, целиком попавшем в префикс.
# Поэтому инспектор правил на префикс движок не запускает, а отвечает
# verdict:error с кодом MODSEC_BODY_TRUNCATED: отказ от проверки сказан вслух,
# и что с ним делать, решает waf_exception ... inspector маршрута. Умолчание
# класса -- deny, клиент видит 503; маршрут с `waf_exception request inspector
# pass` отдаёт 200 -- тогда EXPECT_STATUS=200.
#
# Само размещение префикса -- в tests/body: отсюда Redis не виден.

set -u

NATS=${NATS_URL:-nats://nats:4222}
EDGE=${EDGE:-http://nginx-1:8080}
NODE=${NODE:-edge-01}

# Датаграмма уходит агенту вдогонку ответу клиенту, инспектор публикует свою
# запись сам и раньше.
SETTLE=${SETTLE:-2}

REQUEST="waf.audit.request.$NODE"
INSPECTOR=${INSPECTOR_SUBJECT:-waf.audit.inspector.modsec}

# waf_body_limit на маршруте.
LIMIT=1024

# Признак, на который смотрит CRS 942100. Стоит в начале тела: в префикс он
# попадает целиком, и всё же не находится.
MARK='1 union select 1'

pass=0
fail=0

say() { printf '%s\n' "$*"; }

ok() {
    pass=$((pass + 1))
    say "ok   $1"
}

bad() {
    fail=$((fail + 1))
    say "FAIL $1: $2"
}

eq() {
    if [ "$2" = "$3" ]; then
        ok "$1"
    else
        bad "$1" "$3, ожидалось $2"
    fi
}

done_with() {
    say ''
    say "итог: $pass ok, $fail fail"
    say "запись инспектора целиком: nats --server $NATS stream get WAF_AUDIT --last-for=$INSPECTOR"
    [ "$fail" -eq 0 ] || exit 1
    exit 0
}

# Тело вдвое больше предела: обрыв гарантированно приходится на строку pad.
pad=$(awk 'BEGIN { while (i++ < 2048) printf "a" }')
body="{\"q\":\"$MARK\",\"pad\":\"$pad\"}"

say '--- запрос с телом больше предела ---'

code=$(printf '%s' "$body" \
       | curl -s -o /dev/null -w '%{http_code}' -X POST \
              -H 'content-type: application/json' \
              --data-binary @- "$EDGE/body/truncate/")

# Умолчание класса inspector -- deny без записи каталога, то есть 503.
eq 'вердикт клиенту' "${EXPECT_STATUS:-503}" "$code"

sleep "$SETTLE"

say '--- запись запроса: префикс размещён ---'

raw=$(nats --server "$NATS" stream get WAF_AUDIT --last-for="$REQUEST" -j \
      2>/dev/null)

if [ -z "$raw" ]; then
    bad 'запись в WAF_AUDIT' "нет сообщений на $REQUEST"
    done_with
fi

record=$(printf '%s' "$raw" | jq -r '.data' | base64 -d)

eq 'маршрут той же записи' '/body/truncate/' \
   "$(printf '%s' "$record" | jq -r '.route.location')"

eq 'локатор помечен префиксом' 'true' \
   "$(printf '%s' "$record" | jq -r '.store.body.truncated')"

eq 'тело целиком не размещено' 'false' \
   "$(printf '%s' "$record" | jq -r '.store.body.complete')"

eq 'размещён ровно waf_body_limit' "$LIMIT" \
   "$(printf '%s' "$record" | jq -r '.store.body.size')"

ray=$(printf '%s' "$record" | jq -r '.ray')

say '--- запись инспектора: ошибка разбора вместо находки ---'

# По ray, а не по --last-for: на ту же тему пишет пульс инспектора, и последним
# сообщением темы легко оказывается он, а не наш запрос.
last=$(nats --server "$NATS" stream info WAF_AUDIT -j 2>/dev/null \
       | jq -r '.state.last_seq // 0')

seq=$last
seen=0
verdict=''

while [ "$seq" -gt 0 ] && [ "$seen" -lt 40 ]; do
    msg=$(nats --server "$NATS" stream get WAF_AUDIT "$seq" -j 2>/dev/null)
    seq=$((seq - 1))
    seen=$((seen + 1))

    [ -n "$msg" ] || continue
    [ "$(printf '%s' "$msg" | jq -r '.subject')" = "$INSPECTOR" ] || continue

    data=$(printf '%s' "$msg" | jq -r '.data' | base64 -d)

    if [ "$(printf '%s' "$data" | jq -r '.ray')" = "$ray" ]; then
        verdict=$data
        break
    fi
done

if [ -z "$verdict" ]; then
    bad 'запись инспектора найдена' "нет сообщения с ray=$ray на $INSPECTOR"
    done_with
fi

eq 'инспектор знает, что перед ним префикс' 'truncated' \
   "$(printf '%s' "$verdict" | jq -r '.engine.body')"

# Движок не запускался: ни находок о содержимом, ни ошибки разбора, ни счёта.
eq 'находок нет' '0' \
   "$(printf '%s' "$verdict" | jq -r '.findings | length')"

eq 'счёта нет' 'null' \
   "$(printf '%s' "$verdict" | jq -r '.engine.crs_anomaly_score')"

# То, ради чего всё это проверяется: отказ от проверки сказан вслух, а не
# спрятан в allow, неотличимый от чистого запроса.
eq 'вердикт инспектора' 'error' \
   "$(printf '%s' "$verdict" | jq -r '.verdict')"

done_with
