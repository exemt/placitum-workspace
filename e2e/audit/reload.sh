#!/bin/sh
# Оригинал после вердикта: снимок кладётся в размере снимка и под масками,
# reload докладывает оригинал только тому исходу, которому он нужен, маска
# архива поверх маски снимка не хеширует дважды, снятое целиком в архив едет
# куском.
#
#     docker compose up -d --wait
#     sh tests/audit/reload.sh
#
# Маршруты заводит сам прогон через контроллер на juice.waf.test (апстрим
# backend, /echo/) и убирает в конце, что бы ни случилось:
#
#   /reload/        capture headers args body=4k, mask x-reload-secret / token;
#                   archive when=deny, reload headers=capture body=64k;
#                   archive headers mask=x-reload-secret, args mask=token
#   /reload-piece/  capture body целиком, archive body=1k when=deny
#
# Что проверяется, по пути объекта:
#
#   put до волн  -- SET заголовков с хешем секрета вместо значения, SET тела
#                   в 4k: инспекторы видят снимок и только его;
#   reload       -- на отказе второй SET заголовков уже с секретом и второй SET
#                   тела целиком (20k); на допуске при when=deny второго SET нет
#                   ни у одного объекта;
#   архив        -- заголовки: секрет под маской архива -- один sha256 от
#                   оригинала; args: token без reload -- тот же sha256, что
#                   видели инспекторы, а не хеш от хеша; тело -- 20k целиком;
#                   запись называет hashed у args и не называет у headers;
#   кусок        -- снято целиком, в архив 1k: один SET, в S3 1024 байта.
#
# SET-ы считаются по MONITOR обменника: с хоста через docker compose exec redis.
# Ходовая часть -- в nats-box: с хоста трафик до края не доходит, а jq и nats
# есть только там. S3 читается через minio-mc. Тело едет text/plain, признак
# для CRS -- в строке запроса (942100, 50 баллов): снимок тела в 4k не должен
# решать исход, он тут ради размера.

set -u

export MSYS_NO_PATHCONV=1

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

NODE=${NODE:-edge-01}
ID="rl-$(date +%s)-$$"
SECRET="secret-$ID"
TOKEN="tok-$ID"

pass=0
fail=0

check() {
    want=$1; name=$2; got=$3
    if [ "$got" = "$want" ]; then
        printf 'ok   %-62s %s\n' "$name" "$got"
        pass=$((pass + 1))
    else
        printf 'FAIL %-62s %s, ожидался %s\n' "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

sha() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

SECRET_SHA=$(sha "$SECRET")
TOKEN_SHA=$(sha "$TOKEN")

box() {
    docker compose exec -T -e NODE="$NODE" -e ID="$ID" -e SECRET="$SECRET" \
        -e TOKEN="$TOKEN" -e P="${1:-}" -e CASE="${2:-}" -e KIND="${3:-}" nats-box sh
}

# --- маршруты: завести, издать, дождаться края -----------------------------

fixture() {
    box <<'BOXED'
set -u
CTRL=http://controller:8080
scope=$(curl -s "$CTRL/api/spaces" | jq -r '.spaces[] | select(.name=="default") | .uuid')
api="$CTRL/api/$scope"
srv=$(curl -s "$api/servers" | jq -r '.servers[] | select(.name=="juice.waf.test") | .uuid')
ups=$(curl -s "$api/upstreams" | jq -r '.upstreams[] | select(.name=="backend") | .uuid')

# Остатки прошлого прогона, если он не убрал за собой.
curl -s "$api/servers/$srv/locations" \
    | jq -r '.locations[] | select(.path=="/reload/" or .path=="/reload-piece/") | .uuid' \
    | while read -r u; do curl -s -o /dev/null -X DELETE "$api/locations/$u"; done

route() {  # путь, waf-json
    curl -s -X POST "$api/servers/$srv/locations" -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg p "$1" --arg ups "$ups" --argjson waf "$2" '{
            match: "prefix", path: $p, upstream_id: $ups, upstream_uri: "/echo/",
            nginx: { proxySetHeaders: [{name: "Host", value: "$host"}], proxyHttpVersion: "1.1" },
            waf: $waf,
            position: 25, enabled: true, handler: "proxy", protocol: "http",
            return_status: null, return_page: null, return_url: null,
            raw: false, raw_nginx: ""
        }')" | jq -r '.uuid // ("error: " + (. | tostring))'
}

common='{"localChecks":[],"requestInspectors":[{"name":"modsec","wave":0}],"responseInspectors":"none","scoreDeny":{"threshold":50,"response":"suspicious"},"preview":["request headers=2k/256 args=512 body=64"]'

echo "route_reload=$(route /reload/ "$common"',
    "capture":["request headers args body=4k","request headers mask=x-reload-secret","request args mask=token"],
    "archive":["request headers args body ttl=1h when=deny","request reload headers=capture body=64k",
               "request headers mask=x-reload-secret","request args mask=token"]}')"
echo "route_piece=$(route /reload-piece/ "$common"',
    "capture":["request headers args body"],
    "archive":["request headers args ttl=1h when=deny","request body=1k ttl=1h when=deny"]}')"

echo "publish=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$api/config/send")"

# Край берёт поколение сам; пока маршрута нет, префикс / отдаёт 404 от Juice.
i=0
while [ $i -lt 30 ]; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: juice.waf.test' \
                "http://$NODE:8080/reload/probe")
    [ "$code" = 200 ] && break
    i=$((i + 1)); sleep 1
done
echo "converged=$code"
BOXED
}

cleanup() {
    box <<'BOXED' >/dev/null 2>&1
CTRL=http://controller:8080
scope=$(curl -s "$CTRL/api/spaces" | jq -r '.spaces[] | select(.name=="default") | .uuid')
api="$CTRL/api/$scope"
srv=$(curl -s "$api/servers" | jq -r '.servers[] | select(.name=="juice.waf.test") | .uuid')
curl -s "$api/servers/$srv/locations" \
    | jq -r '.locations[] | select(.path=="/reload/" or .path=="/reload-piece/") | .uuid' \
    | while read -r u; do curl -s -o /dev/null -X DELETE "$api/locations/$u"; done
curl -s -o /dev/null -X POST "$api/config/send"
BOXED
}

trap 'cleanup' EXIT

echo "=== маршруты ==="
fx=$(fixture)
printf '%s\n' "$fx" | sed 's/^/     /'
case $fx in
*converged=200*) ;;
*) echo "FAIL маршруты не доехали до $NODE"; exit 1 ;;
esac

# --- обменник под MONITOR --------------------------------------------------

MON=$(mktemp)

# MONITOR на 45 секунд: три запроса с ожиданием записи укладываются. timeout --
# busybox в образе redis. Файл дочитывается после wait, когда поток закрыт.
docker compose exec -T redis sh -c 'timeout 45 redis-cli monitor' > "$MON" 2>/dev/null &
MONPID=$!
sleep 2

# Запрос из nats-box и запись по нему. Аргументы: путь, случай, признак
# (attack|clean). Печатает строки key=value, которые разбирает хост.
shoot() {
    box "$1" "$2" "$3" <<'BOXED'
set -u
EDGE="http://$NODE:8080"
NATS=nats://nats:4222
SUBJECT="waf.audit.request.$NODE"

case=$ID-$CASE
q="case=$case&token=$TOKEN"
if [ "$KIND" = attack ]; then
    q="$q&q=1%20union%20select%201"
fi

# Тело: маркер случая в начале, дальше 'A' до 20000 байт. text/plain: CRS
# его не разбирает, исход решает строка запроса.
awk -v m="$case" 'BEGIN { printf "%s ", m; n = 20000 - length(m) - 1; while (i++ < n) printf "A" }' \
    > /tmp/rl-body.txt

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
            -H 'Host: juice.waf.test' \
            -H 'Content-Type: text/plain' \
            -H "X-Reload-Case: $case" \
            -H "X-Reload-Secret: $SECRET" \
            --data-binary @/tmp/rl-body.txt \
            "$EDGE$P?$q")
echo "code=$code"

# Датаграмма уходит агенту вдогонку ответу; агент кладёт объекты в S3 и
# публикует запись уже с архивными локаторами.
sleep 4

# Агент шлёт записи пачкой: последнее сообщение темы -- конверт batch, внутри
# items. Своя запись -- по пути маршрута, последняя из подходящих.
raw=$(nats --server "$NATS" stream get WAF_AUDIT --last-for="$SUBJECT" -j 2>/dev/null)
record=$(printf '%s' "$raw" | jq -r '.data' | base64 -d 2>/dev/null \
         | jq -c --arg p "$P" \
              'if .kind == "batch" then ([.items[] | select(.http.uri == $p)] | last) else . end' \
           2>/dev/null)

if [ -z "$record" ] || [ "$record" = null ]; then
    echo "record=none"
    exit 0
fi

echo "record=ok"
echo "verdict=$(printf '%s' "$record" | jq -r '.verdict')"
echo "hdr_store=$(printf '%s' "$record" | jq -r '.store.headers.store // ""')"
echo "hdr_key=$(printf '%s' "$record" | jq -r '.store.headers.key // ""')"
echo "arg_key=$(printf '%s' "$record" | jq -r '.store.args.key // ""')"
echo "body_key=$(printf '%s' "$record" | jq -r '.store.body.key // ""')"
echo "body_limit=$(printf '%s' "$record" | jq -r '.store.archive.body.limit // ""')"
echo "arg_hashed=$(printf '%s' "$record" | jq -r '(.store.archive.args.hashed // []) | join(",")')"
echo "hdr_hashed=$(printf '%s' "$record" | jq -r '(.store.archive.headers.hashed // []) | join(",")')"
echo "archive_objs=$(printf '%s' "$record" | jq -r '(.store.archive // {}) | keys | join(",")')"
BOXED
}

field() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1; }

s3cat() {
    docker compose exec -T minio-mc mc cat "waf/$1/$2" 2>/dev/null
}

echo "=== /reload/: отказ -- оригинал докладывается, архив собирает всё ==="

deny=$(shoot /reload/ deny attack)
check 403 'вердикт клиенту'                       "$(field "$deny" code)"
check ok  'запись на шине'                        "$(field "$deny" record)"
check deny 'вердикт в записи'                     "$(field "$deny" verdict)"
check archive 'заголовки уехали в архив'          "$(field "$deny" hdr_store)"
check 'args,body,headers' 'набор архива в записи' "$(field "$deny" archive_objs)"
check token 'hashed у args: token уже хеш'        "$(field "$deny" arg_hashed)"
check ''    'hashed у headers пуст: лёг оригинал' "$(field "$deny" hdr_hashed)"

hdr_key=$(field "$deny" hdr_key)
arg_key=$(field "$deny" arg_key)
body_key=$(field "$deny" body_key)

hdr_s3=$(s3cat waf-headers "$hdr_key")
case $hdr_s3 in
*"$SECRET_SHA"*) check yes 'S3 headers: секрет под маской архива -- sha256' yes ;;
*)               check yes 'S3 headers: секрет под маской архива -- sha256' "no: $(printf '%s' "$hdr_s3" | head -c 160)" ;;
esac
case $hdr_s3 in
*"$SECRET"*) check no 'S3 headers: секрета в открытом виде нет' yes ;;
*)           check no 'S3 headers: секрета в открытом виде нет' no ;;
esac

arg_s3=$(s3cat waf-args "$arg_key")
case $arg_s3 in
*"token=$TOKEN_SHA"*) check yes 'S3 args: token -- один sha256, не хеш от хеша' yes ;;
*)                    check yes 'S3 args: token -- один sha256, не хеш от хеша' "no: $arg_s3" ;;
esac

check 20000 'S3 body: тело целиком (reload body=64k шире снимка)' \
      "$(s3cat waf-bodies "$body_key" | wc -c | tr -d ' ')"

echo "=== /reload/: допуск при when=deny -- оригинал не кладётся ==="

allow=$(shoot /reload/ allow clean)
check 200 'вердикт клиенту' "$(field "$allow" code)"
if [ "$(field "$allow" record)" = ok ]; then
    check allow 'вердикт в записи' "$(field "$allow" verdict)"
    check '' 'набор архива пуст' "$(field "$allow" archive_objs)"
fi

echo "=== /reload-piece/: снято целиком, в архив кусок ==="

piece=$(shoot /reload-piece/ piece attack)
check 403  'вердикт клиенту'                "$(field "$piece" code)"
check deny 'вердикт в записи'               "$(field "$piece" verdict)"
check 1024 'предел тела в записи (archive)' "$(field "$piece" body_limit)"
check 1024 'S3 body: первые 1024 байта'     "$(s3cat waf-bodies "$(field "$piece" body_key)" | wc -c | tr -d ' ')"

echo "=== обменник: SET по MONITOR ==="

wait "$MONPID" 2>/dev/null

# Строки SET своего объекта: ключ узла с суффиксом, значение с маркером случая.
sets() {  # суффикс, маркер
    grep -E "\"SET\" \"$NODE:[0-9a-f]+:req$1\" " "$MON" | grep -F "$2"
}
count() { printf '%s\n' "$1" | grep -c .; }
len() { printf '%s\n' "$1" | awk 'NR == 1 { print length($0) }'; }

# --- отказ ---
hdr=$(sets ':hdr' "$ID-deny")
check 2 'deny: SET заголовков -- снимок и оригинал'    "$(count "$hdr")"
check 1 'deny: первый SET заголовков -- секрет хешем'  "$(printf '%s\n' "$hdr" | head -n 1 | grep -c "$SECRET_SHA")"
check 0 'deny: первый SET заголовков -- без секрета'   "$(printf '%s\n' "$hdr" | head -n 1 | grep -c "$SECRET")"
check 1 'deny: второй SET заголовков -- секрет целым'  "$(printf '%s\n' "$hdr" | tail -n 1 | grep -c "$SECRET")"

arg=$(sets ':arg' "case=$ID-deny")
check 1 'deny: SET строки запроса -- один, без reload' "$(count "$arg")"
check 1 'deny: token в обменнике -- хеш'               "$(printf '%s\n' "$arg" | grep -c "token=$TOKEN_SHA")"

body=$(sets '' "$ID-deny ")
check 2 'deny: SET тела -- снимок и оригинал' "$(count "$body")"
first=$(len "$body")
second=$(len "$(printf '%s\n' "$body" | tail -n 1)")
check yes 'deny: первый SET тела -- снимок в 4k'  "$([ "${first:-0}" -gt 4000 ] && [ "${first:-0}" -lt 6000 ] && echo yes || echo "no: $first")"
check yes 'deny: второй SET тела -- целиком 20k'  "$([ "${second:-0}" -gt 20000 ] && echo yes || echo "no: $second")"

# --- допуск ---
check 1 'allow: SET заголовков -- только снимок'     "$(count "$(sets ':hdr' "$ID-allow")")"
check 1 'allow: снимок заголовков -- секрет хешем'   "$(sets ':hdr' "$ID-allow" | grep -c "$SECRET_SHA")"
check 1 'allow: SET строки запроса -- один'          "$(count "$(sets ':arg' "case=$ID-allow")")"
check 1 'allow: SET тела -- только снимок'           "$(count "$(sets '' "$ID-allow ")")"
one=$(len "$(sets '' "$ID-allow ")")
check yes 'allow: снимок тела -- 4k, оригинала нет'  "$([ "${one:-0}" -gt 4000 ] && [ "${one:-0}" -lt 6000 ] && echo yes || echo "no: $one")"

# --- кусок ---
check 1 'piece: SET тела -- один, целиком' "$(count "$(sets '' "$ID-piece ")")"
whole=$(len "$(sets '' "$ID-piece ")")
check yes 'piece: тело в обменнике целиком, режет агент' "$([ "${whole:-0}" -gt 20000 ] && echo yes || echo "no: $whole")"

rm -f "$MON"

echo
echo "итог: $pass ok, $fail fail"
[ "$fail" -eq 0 ]
