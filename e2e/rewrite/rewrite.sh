#!/bin/sh
# Модификатор ответов на живом контуре: подмена тела через обменник, заголовки,
# управление просьбами соседей.
#
#     docker compose up -d --wait
#     sh tests/rewrite/rewrite.sh
#
# Гоняется с хоста. HTTP-часть идёт через одноразовый край waf-e2e-rw на
# синтетическом конфиге (deploy/nginx/nginx.conf, нода nodes/e2e-rw.conf):
# управляемые edge-01..03 живут на джус-конфиге контроллера, и e2e-маршрутов
# модификатора там нет. Край поднимается сам и уносится прогоном -- иначе его
# воркеры висят «вне списка» на странице состояния (агента у ноды e2e-rw нет).
# KEEP_EDGE=1 оставляет край поднятым для разбора.
#
# Шинная часть -- внутри nats-box, ручными конвертами той же формы, что шлёт
# модуль: она проверяет приём просьб (mutate/skip), условия групп и отказ по
# несостоявшейся подмене без зависимости от контроллера.

set -eu

export MSYS_NO_PATHCONV=1

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

fail=0

check() {
    want=$1; name=$2; got=$3
    if [ "$got" = "$want" ]; then
        printf "ok   %-56s %s\n" "$name" "$got"
    else
        printf "FAIL %-56s %s, ожидался %s\n" "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

# --- одноразовый край -------------------------------------------------------

EDGE=waf-e2e-rw

# Уборка ловушкой, а не хвостом скрипта: край уходит и на ранних выходах
# (`set -e`, провал /healthz), иначе он живёт неделями и его воркеры торчат
# на странице состояния карточкой «Воркеры без агента».
drop_edge() {
    if [ "${KEEP_EDGE:-0}" = 0 ]; then
        docker rm -f "$EDGE" >/dev/null 2>&1 || true
    fi
}
trap drop_edge EXIT

if ! docker ps --format '{{.Names}}' | grep -qx "$EDGE"; then
    echo "поднимаю одноразовый край $EDGE (waf-nginx + deploy/nginx/nginx.conf)"
    docker rm -f "$EDGE" >/dev/null 2>&1 || true
    docker run -d --name "$EDGE" --network waf_default \
        -v "$ROOT/deploy/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
        -v "$ROOT/deploy/nginx/nodes/e2e-rw.conf:/etc/nginx/waf-node.conf:ro" \
        -v "$ROOT/deploy/nginx/www:/var/www:ro" \
        waf-nginx >/dev/null
    sleep 3
fi

if ! docker exec "$EDGE" curl -sf -o /dev/null http://127.0.0.1:8080/healthz; then
    echo "FAIL край $EDGE не отвечает на /healthz"
    exit 1
fi

# --- часть A: HTTP через край ----------------------------------------------

# Канарейка едет заголовком запроса; echo печатает её в JSON тела ответа.
# Профиль stand: mask (canary->masked, только 200 + json/html), hdrs
# (X-Rewrote: yes, снятый Server), prefixed (выключена, включается mutate).

run_edge() { docker exec "$EDGE" sh -c "$1"; }

A=$(run_edge 'curl -s -D /tmp/h -H "X-E2E-Canary: canary-shpart1" \
        http://127.0.0.1:8080/rewrite-e2e/a -o /tmp/b
    grep -o "masked-shpart1\|canary-shpart1" /tmp/b | sort -u | tr "\n" ";"
    printf "%s;" "$(grep -ci "^x-rewrote: yes" /tmp/h || true)"
    printf "%s;" "$(grep -ci "^server:" /tmp/h || true)"
    cl=$(sed -n "s/^[Cc]ontent-[Ll]ength: *\([0-9]*\).*/\1/p" /tmp/h)
    [ "$cl" = "$(wc -c < /tmp/b | tr -d " ")" ] && printf ok || printf len-mismatch')
check "masked-shpart1;1;0;ok" "A1 маска + заголовки + Content-Length" "$A"

A2=$(run_edge 'curl -s -D /tmp/h -H "X-E2E-Canary: canary-shpart2" \
        http://127.0.0.1:8080/rewrite-e2e-observe/a -o /tmp/b
    grep -o "masked-shpart2\|canary-shpart2" /tmp/b | sort -u | tr "\n" ";"
    grep -ci "^x-rewrote:" /tmp/h || true')
check "canary-shpart2;0" "A2 observe: тело и заголовки нетронуты" "$A2"

A3=$(run_edge 'curl -s -H "X-E2E-Canary: canary-shpart3" \
        http://127.0.0.1:8080/rewrite-e2e-timeout/a | \
        { grep -o "masked-shpart3\|canary-shpart3" || true; } | sort -u')
check "canary-shpart3" "A3 таймаут: fail-open, оригинал" "$A3"

# Управление от вышестоящего: инспектор action шлёт mutate/skip по суффиксу
# пути (профиль stand-rewrite канала /actions). До издания канала контроллером
# просьб нет -- эти два кейса тогда честно падают.
A4=$(run_edge 'curl -s -H "X-E2E-Canary: canary-shpart4" \
        http://127.0.0.1:8080/rewrite-e2e-action/mutate-x | \
        { grep -o "PFX-masked-shpart4\|masked-shpart4\|canary-shpart4" || true; } | sort -u | head -1')
check "PFX-masked-shpart4" "A4 mutate включил группу prefixed" "$A4"

A5=$(run_edge 'curl -s -H "X-E2E-Canary: canary-shpart5" \
        http://127.0.0.1:8080/rewrite-e2e-action/skip-x | \
        { grep -o "masked-shpart5\|canary-shpart5" || true; } | sort -u')
check "canary-shpart5" "A5 skip: ответ не правится" "$A5"

# --- часть B: шина, ручные конверты ----------------------------------------

# Форма сообщения -- docs/messages/inspector.schema.json. Тело кладётся в
# обменник руками; ключ произвольный -- инспектор читает по локатору, а префикс
# сверяет модуль, которого здесь нет.

docker compose exec -T redis redis-cli SET "e2e-rw:00000000deadbeef:rsp" \
    '{"x":"canary-bus1"}' EX 120 >/dev/null

envelope() {
    # $1 -- status, $2 -- prior actions json (пустая строка -- без prior)
    prior=""
    if [ -n "$2" ]; then
        prior=",\"prior\":[{\"phase\":\"request\",\"inspector\":\"action\",\"verdict\":\"allow\",\"actions\":[$2]}]"
    fi

    printf '{"v":2,"rid":"00000000deadbeef","ray":"00000000-e2e0-4000-8000-000000000000","phase":"response","wave":0,"inspector":"rewrite","deadline_ms":1000,"audit_subject":null,"node":"e2e-rw","conn":{"client_ip":"192.0.2.9","client_port":1,"server_ip":"10.0.0.1","server_port":8080},"http":{"method":"GET","scheme":"http","host":"e2e.local","uri":"/bus/x","args_size":0,"version":"HTTP/1.1"},"needs":["body"],"store":{"headers":null,"args":null,"body":{"store":"hot","driver":"redis","key":"e2e-rw:00000000deadbeef:rsp"}},"route":{"server_name":"e2e.local","location":"/bus/","profile":"stand"},"score":{"total":0,"deny_at":100},"response":{"status":%s,"headers":[["content-type","application/json"]]}%s}' \
        "$1" "$prior"
}

ask() {
    docker compose exec -T nats-box nats --server nats://nats:4222 request \
        --timeout 2s waf.req.rewrite "$1" 2>/dev/null | { grep '^{' || true; } | tail -1
}

R=$(ask "$(envelope 200 '{"do":"mutate","apply":"request","code":"E2E_MUTATE","group":"prefixed","set":"on"}')")
B1=$(printf '%s' "$R" | grep -o '"groups":\[[^]]*\]')
check '"groups":["mask","hdrs","prefixed"]' "B1 prior mutate включает prefixed" "$B1"

OUT=$(docker compose exec -T redis redis-cli GET "e2e-rw:00000000deadbeef:rsp:out")
check '{"x":"PFX-masked-bus1"}' "B2 объект :out переписан по порядку групп" "$OUT"

R=$(ask "$(envelope 404 '')")
B3=$(printf '%s' "$R" | grep -c '"key"' || true)
check "0" "B3 промах статуса: mask снята условиями, тела нет" "$B3"

R=$(ask "$(envelope 200 '{"do":"skip","apply":"request","code":"E2E_SKIP"}')")
B4=$(printf '%s' "$R" | grep -o 'REWRITE_SKIPPED\|rewrite' | sort -u | head -1)
check "REWRITE_SKIPPED" "B4 prior skip: без правок" "$B4"

# Подмена решена (маска активна, тело хочет), а тела нет: инспектор отказывает.
R=$(ask "$(envelope 200 '' | \
    sed 's/{"store":"hot","driver":"redis","key":"e2e-rw:00000000deadbeef:rsp"}/{"unavailable":"store_error"}/')")
B5=$(printf '%s' "$R" | grep -o '"verdict":"deny"\|rewrite_failed\|REWRITE_BODY_UNAVAILABLE' | sort -u | tr '\n' ';')
check '"verdict":"deny";REWRITE_BODY_UNAVAILABLE;rewrite_failed;' \
    "B5 тело недоступно: отказ страницей профиля" "$B5"

docker compose exec -T redis redis-cli DEL "e2e-rw:00000000deadbeef:rsp" \
    "e2e-rw:00000000deadbeef:rsp:out" >/dev/null

# --- часть C: проба ---------------------------------------------------------

if docker compose exec -T inspector-rewrite rewrite-probe --quiet --timeout 2s \
    --uri /rewrite-sh-probe; then
    printf "ok   %-56s\n" "C1 проба: конвейер жив, группа _probe применена"
else
    printf "FAIL %-56s\n" "C1 проба"
    fail=$((fail + 1))
fi

# --- итог (край уносит ловушка drop_edge) -----------------------------------

if [ "$fail" != 0 ]; then
    echo "ПРОВАЛОВ: $fail"
    exit 1
fi

echo "все проверки прошли"
