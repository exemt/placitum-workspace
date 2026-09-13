#!/bin/sh
# Инспектор контракта на живом контуре: обе фазы, все политики, усечение тела.
#
#     docker compose up -d --wait
#     sh tests/json/json.sh
#
# Гоняется с хоста, ходовая часть -- внутри nats-box: с хоста край виден через
# HAProxy, а маршруты стенда живут на nginx-1:8080 (см. memory стенда).
#
# Спека контура -- inspectors/json/profiles/*/schema-stand: /orders,
# /orders/{id}, /report, /fail, /healthz. Приложение за маршрутом -- эхо,
# поэтому ответ на /orders совпадает с объявленным, а на /report -- нет: это и
# есть проверка фазы ответа.

set -eu

# docker compose exec с хоста под MSYS: иначе /dev/null уезжает в путь Windows.
export MSYS_NO_PATHCONV=1

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

docker compose exec -T nats-box sh -s <<'BOXED'
fail=0
BASE=http://nginx-1:8080
JSON='Content-Type: application/json'

check() {
    want=$1; name=$2; got=$3
    if [ "$got" = "$want" ]; then
        printf "ok   %-46s %s\n" "$name" "$got"
    else
        printf "FAIL %-46s %s, ожидался %s\n" "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

status() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

# Полей у записи разное число: allow печатается как <вердикт>/<мс>, deny -- как
# <вердикт>/<код>/<мс>, score -- как <вердикт>/<счёт>/<взвешенный>/<код>/<мс>.
# Общее у всех одно: код стоит перед полем длительности, если он есть вообще.
code() {
    awk -F/ '{
        out = $1
        for (i = 2; i <= NF; i++) {
            if ($i ~ /ms$/) {
                if (i > 2 && $(i - 1) !~ /^[0-9]+$/) out = out "/" $(i - 1)
                break
            }
        }
        print out
    }'
}

gate() {
    curl -s -o /dev/null -D - "$@" \
        | tr " " "\n" | sed -n "s/^json[a-z-]*=//p" | head -1 | tr -d "\r" | code
}

rgate() {
    curl -s -o /dev/null -D - "$@" \
        | tr " " "\n" | sed -n "s/^json[a-z-]*=//p" | tail -1 | tr -d "\r" | code
}

echo "--- фаза запроса: тело против схемы ---"

check 200 'валидное тело проходит' \
    "$(status -X POST -H "$JSON" -d '{"id":1,"item":"boots","qty":2}' $BASE/json/orders)"
check 'allow' 'инспектор: allow без причины' \
    "$(gate -X POST -H "$JSON" -d '{"id":1,"item":"boots","qty":2}' $BASE/json/orders)"

check 400 'строка вместо числа -- отказ' \
    "$(status -X POST -H "$JSON" -d '{"id":"one","item":"boots"}' $BASE/json/orders)"
check 'deny/JSON_SCHEMA_MISMATCH' 'инспектор: не сошлось со схемой' \
    "$(gate -X POST -H "$JSON" -d '{"id":"one","item":"boots"}' $BASE/json/orders)"

check 400 'нет обязательного поля -- отказ' \
    "$(status -X POST -H "$JSON" -d '{"id":1}' $BASE/json/orders)"
check 400 'лишнее поле при additionalProperties: false' \
    "$(status -X POST -H "$JSON" -d '{"id":1,"item":"boots","colour":"red"}' $BASE/json/orders)"

check 400 'тело не разбирается как JSON' \
    "$(status -X POST -H "$JSON" -d '{"id":1,' $BASE/json/orders)"
check 'deny/JSON_UNPARSABLE' 'инспектор: документ не разобран' \
    "$(gate -X POST -H "$JSON" -d '{"id":1,' $BASE/json/orders)"

echo
echo "--- фаза запроса: параметры ---"

check 200 'параметр пути -- целое' "$(status $BASE/json/orders/7)"
check 400 'параметр пути не целое' "$(status $BASE/json/orders/abc)"
check 400 'параметр строки запроса не boolean' \
    "$(status "$BASE/json/orders/7?verbose=maybe")"
check 200 'параметр строки запроса валиден' \
    "$(status "$BASE/json/orders/7?verbose=true")"

echo
echo "--- путь вне контракта ---"

check 200 'api пропускает неописанный путь' "$(status $BASE/json/nothing-here)"
check 'allow/JSON_UNKNOWN_OPERATION' 'инспектор: операции нет в спеке' \
    "$(gate $BASE/json/nothing-here)"
check 400 'strict отказывает неописанному пути' "$(status $BASE/json-strict/nothing-here)"
check 'deny/JSON_UNKNOWN_OPERATION' 'strict: белый список путей' \
    "$(gate $BASE/json-strict/nothing-here)"

echo
echo "--- наблюдение ---"

check 200 'observe пропускает невалидное тело' \
    "$(status -X POST -H "$JSON" -d '{"id":"one"}' $BASE/json-observe/orders)"
check 'allow/JSON_OBSERVE' 'observe: модулю allow с кодом наблюдения, решение в аудите' \
    "$(gate -X POST -H "$JSON" -d '{"id":"one"}' $BASE/json-observe/orders)"

echo
echo "--- усечённое тело ---"

BIG=$(awk 'BEGIN{printf "{\"id\":1,\"item\":\""; for(i=0;i<400;i++) printf "x"; printf "\"}"}')

check 400 'префикс тела: api не пропускает непроверяемое' \
    "$(status -X POST -H "$JSON" -d "$BIG" $BASE/json/trim)"
check 'deny/JSON_BODY_TRUNCATED' 'инспектор: документ оборван' \
    "$(gate -X POST -H "$JSON" -d "$BIG" $BASE/json/trim)"

check 200 'префикс тела: soft пропускает с пометкой' \
    "$(status -X POST -H "$JSON" -d "$BIG" $BASE/json-soft/trim)"
check 'allow/JSON_BODY_TRUNCATED' 'soft: причина остаётся в аудите' \
    "$(gate -X POST -H "$JSON" -d "$BIG" $BASE/json-soft/trim)"

echo
echo "--- фаза ответа ---"

check 200 'ответ совпал с объявленным' \
    "$(status -X POST -H "$JSON" -d '{"id":1,"item":"boots"}' $BASE/json/orders)"
check 'allow' 'фаза ответа: сошлось' \
    "$(rgate -X POST -H "$JSON" -d '{"id":1,"item":"boots"}' $BASE/json/orders)"

check 'score/JSON_SCHEMA_MISMATCH' 'api: ответ не по спеке -- счёт' \
    "$(rgate $BASE/json/report)"
check 200 'счёт порога не берёт, клиент получает ответ' "$(status $BASE/json/report)"

check 502 'strict: ответ не по спеке -- отказ' "$(status $BASE/json-strict/report)"
check 'deny/JSON_SCHEMA_MISMATCH' 'strict: вердикт фазы ответа' \
    "$(rgate $BASE/json-strict/report)"

check 502 'strict: код ответа вне спеки' "$(status $BASE/json-strict/fail)"
check 'deny/JSON_STATUS_UNDECLARED' 'strict: 503 не объявлен операцией' \
    "$(rgate $BASE/json-strict/fail)"

echo
echo "--- инициаторы по исходу ---"

# Профиль soft просит капчу на счёте выше порога и пишет адрес в набор.
# Капча стоит на /json-soft/ второй волной -- ровно чтобы просьба была
# проверяема насквозь, а не только по логу инспектора.
check 'score/JSON_SCHEMA_MISMATCH' 'тело не по спеке: счёт выше порога'     "$(gate -X POST -H "$JSON" -d '{"bad":true}' $BASE/json-soft/orders)"
check 403 'просьба доехала: капча требует проверку'     "$(status -X POST -H "$JSON" -H 'Accept: text/html' -d '{"bad":true}'        $BASE/json-soft/orders)"

# Чистое тело -- ни просьбы, ни записи: инициатор смотрит на решение.
check 200 'тело по спеке: соседа не просят'     "$(status -X POST -H "$JSON" -H 'Accept: text/html'        -d '{"id":1,"item":"boots"}' $BASE/json-soft/orders)"

echo
if [ "$fail" -ne 0 ]; then
    echo "провалено: $fail"
    exit 1
fi
echo "все проверки прошли"
BOXED

# Вторая половина инициатора -- запись адреса в живой набор. Её видно из базы:
# инспектор публикует событие, контроллер всасывает его и переиздаёт набор.
echo
echo "--- запись в набор ---"

row=$(docker compose exec -T postgres psql -U waf -d waf -t -A -F'|' -c     "select a.origin, a.reason from dataset_addresses a
       join datasets d on d.id = a.dataset_id
      where d.name = 'cap_ipban' and a.origin = 'json'" 2>/dev/null | head -1 | tr -d "\r")

if [ "$row" = "json|JSON_CONTRACT_HOT" ]; then
    echo "ok   адрес уехал в cap_ipban правилом профиля"
else
    echo "FAIL записи от json в cap_ipban нет: $row"
    exit 1
fi

# Подчищаем за собой: запись режет /captcha-fast/ и /captcha-cluster/, и
# соседний прогон начался бы с чужого бана.
ids=$(docker compose exec -T postgres psql -U waf -d waf -t -A -c     "select a.id from dataset_addresses a
       join datasets d on d.id = a.dataset_id
      where d.name = 'cap_ipban' and a.origin = 'json'" 2>/dev/null | tr -d "\r")

for id in $ids; do
    curl -s -o /dev/null -X DELETE         "http://127.0.0.1:8080/api/${SCOPE:-31291282-a50c-4107-9164-e2ae46cd8b36}/addresses/$id" || true
done

echo
echo "--- проба ---"
docker compose exec -T inspector-json json-probe --timeout 2s
docker compose exec -T inspector-json json-probe --timeout 2s \
    --profile api --uri /json/healthz --expect allow
