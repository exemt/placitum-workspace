#!/bin/sh
# Маркеры в аудите: метка события от инспектора до поиска и группировки.
#
#     docker compose up -d --wait
#     sh tests/audit/markers.sh
#
# Что проверяется, по пути метки:
#
#   профиль   -- контроллер принимает у modsec инициатор `do: mark` с меткой
#                и печатает её в policy.yaml ноды;
#   провод    -- инспектор шлёт просьбу, модуль её исполняет сам: метка
#                уезжает в секцию markers записи, а сама просьба -- в actions
#                с полем marker и без адресата;
#   соседи    -- маркер им не доставляют: исходов у просьбы нет вовсе
#                (получателю нечего было бы применить);
#   журнал    -- логгер кладёт метку в колонку markers, `marker=` находит
#                запись целиком, `by=marker` сворачивает окно в группы.
#
# Гоняется с хоста, ходовая часть -- в nats-box: с хоста трафик до haproxy не
# доходит. Профиль правится и возвращается на место самим прогоном: метка
# уникальна на запуск, поэтому параллельные прогоны друг другу не мешают.

set -eu

export MSYS_NO_PATHCONV=1

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

docker compose exec -T nats-box sh <<'BOXED'
set -u
fail=0

BASE=http://haproxy:8080
CTRL=http://controller:8080
HOST='Host: juice.waf.test'
IP='X-Forwarded-For: 10.0.0.31'
MARK="e2e-marker-$$"

check() {
    want=$1; name=$2; got=$3
    if [ "$got" = "$want" ]; then
        printf 'ok   %-58s %s\n' "$name" "$got"
    else
        printf 'FAIL %-58s %s, ожидался %s\n' "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

scope=$(curl -s "$CTRL/api/spaces" | jq -r '.spaces[] | select(.name=="default") | .uuid')
api="$CTRL/api/$scope"
set_id=$(curl -s "$api/rule-sets" | jq -r '.rule_sets[] | select(.name=="default") | .uuid')

# Политика до правки: её же вернём в конце, что бы ни случилось.
before=$(curl -s "$api/rule-sets/$set_id" | jq -c '.policy')

restore() {
    curl -s -o /dev/null -X PUT "$api/rule-sets/$set_id" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --argjson p "$before" '{policy: $p}')"
    curl -s -o /dev/null -X POST "$api/rules/send"
}

trap 'restore' EXIT

echo '=== профиль: инициатор с меткой ==='

# Тот же триггер, что у живого инициатора набора: счёт modsec не ниже 50.
patch=$(printf '%s' "$before" | jq -c --arg m "$MARK" \
    '.outcomes += [{on:"score", at:50, do:"mark", apply:"request", marker:$m}]')

code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$api/rule-sets/$set_id" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --argjson p "$patch" '{policy: $p}')")
check 200 'контроллер принял mark с меткой' "$code"

saved=$(curl -s "$api/rule-sets/$set_id" | jq -r --arg m "$MARK" \
    '[.policy.outcomes[] | select(.do=="mark" and .marker==$m)] | length')
check 1 'метка сохранена в профиле' "$saved"

# Метка без строки -- полуфраза: контроллер обязан отказать.
bad=$(printf '%s' "$before" | jq -c '.outcomes += [{on:"score", at:50, do:"mark", apply:"request"}]')
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$api/rule-sets/$set_id" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --argjson p "$bad" '{policy: $p}')")
check 400 'mark без метки не сохраняется' "$code"

curl -s -o /dev/null -X POST "$api/rules/send"
sleep 3

echo '=== трафик: метка на записи ==='

curl -s -o /dev/null -H "$HOST" -H "$IP" \
    "$BASE/rest/products/search?q=%27%20OR%201%3D1--%20"

# Логгер пишет пачками: ждём запись до 20 с.
rec=''
i=0
while [ $i -lt 20 ]; do
    rec=$(curl -s "$CTRL/api/search/audit?marker=$MARK&limit=5")
    [ "$(printf '%s' "$rec" | jq -r '.items | length')" != "0" ] && break
    sleep 1
    i=$((i + 1))
done

check 1 'поиск по метке нашёл запись' \
    "$(printf '%s' "$rec" | jq -r 'if (.items | length) > 0 then 1 else 0 end')"
check "$MARK" 'метка в секции markers' \
    "$(printf '%s' "$rec" | jq -r --arg m "$MARK" '.items[0].markers // [] | map(select(. == $m)) | first // "нет"')"

node=$(printf '%s' "$rec" | jq -r '.items[0].node')
ray=$(printf '%s' "$rec" | jq -r '.items[0].ray')
card=$(curl -s "$CTRL/api/search/audit/$node/$ray/inspectors")

check "$MARK" 'просьба в actions несёт метку' \
    "$(printf '%s' "$card" | jq -r --arg m "$MARK" '[.actions[] | select(.do=="mark" and .marker==$m)][0].marker // "нет"')"
check null 'у mark нет адресата: исполняет модуль' \
    "$(printf '%s' "$card" | jq -r --arg m "$MARK" '[.actions[] | select(.do=="mark" and .marker==$m)][0].to')"
# Соседям маркер не доставляют -- отчитываться о нём некому.
check 0 'исходов у маркера нет' \
    "$(printf '%s' "$card" | jq -r --arg m "$MARK" '[.actions[] | select(.do=="mark" and .marker==$m)][0].outcomes // [] | length')"

echo '=== группировка ==='

groups=$(curl -s "$CTRL/api/search/audit/groups?by=marker&limit=20")
check 1 'группа метки есть' \
    "$(printf '%s' "$groups" | jq -r --arg m "$MARK" '[.items[] | select(.keys.marker == $m)] | length')"
check 1 'в группе столько же запросов, сколько помечено' \
    "$(printf '%s' "$groups" | jq -r --arg m "$MARK" '[.items[] | select(.keys.marker == $m)][0].hits')"

echo
if [ "$fail" -eq 0 ]; then
    echo 'PASS'
else
    echo "FAIL: $fail"
    exit 1
fi
BOXED
