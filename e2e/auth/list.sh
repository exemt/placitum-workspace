#!/bin/sh
# Активный список калитки: список — истина, удаление записи завершает сессию.
#
#     docker compose up -d --wait
#     sh tests/auth/list.sh
#
# Механизм один — кука и список. Подпись куки доказывает, что сессию выписали
# мы; запись в наборе живых сессий — что её не завершили. Инспектора спрашивают
# на каждом запросе (никаких if-условий на маршруте), и на запросе старше
# грейса он сверяет sid со своим зеркалом набора:
#
#     запись есть   → allow
#     записи нет    → deny AUTH_SESSION_REVOKED, навигации — форма
#     свежая сессия → по одной подписи, запись ещё едет через секвенсор
#
# Прогон ходит по живому маршруту зоны объявлений (^/<регион>/ads/ за
# juice.waf.test) и живому источнику lalafo-users: заводит учётку, входит,
# дожидается конца грейса, удаляет запись из списка руками оператора и
# проверяет, что этого достаточно — ни Redis, ни отдельного отзыва больше нет.

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
IP='X-Forwarded-For: 10.0.0.9'
HTML='Accept: text/html,application/xhtml+xml'
PW=list-truth-1
# Грейс источника (list.grace, умолчание 2с; здесь с запасом на старые сборки).
GRACE=${GRACE:-18}

check() {
    want=$1; name=$2; got=$3
    if [ "$got" = "$want" ]; then
        printf 'ok   %-56s %s\n' "$name" "$got"
    else
        printf 'FAIL %-56s %s, ожидался %s\n' "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

scope=$(curl -s "$CTRL/api/spaces" | jq -r '.spaces[] | select(.name=="default") | .uuid')
api="$CTRL/api/$scope"
users=$(curl -s "$api/datasets" | jq -r '.datasets[] | select(.name=="lalafo_users") | .uuid')
sessions=$(curl -s "$api/datasets" | jq -r '.datasets[] | select(.name=="lalafo_sessions") | .uuid')

if [ -z "$scope" ] || [ -z "$users" ] || [ -z "$sessions" ]; then
    echo "FAIL: нет пространства default либо наборов lalafo_users/lalafo_sessions"
    exit 1
fi

drop_user() {
    id=$(curl -s "$api/datasets/$users/addresses" \
        | jq -r '.addresses[] | select(.address | startswith("tmpsmoke:")) | .uuid')
    [ -n "$id" ] && curl -s -o /dev/null -X DELETE "$api/addresses/$id"
}

cleanup() {
    drop_user
    # Списки едут источникам поколением: без рассылки на ноде осталась бы
    # тестовая учётка.
    curl -s -o /dev/null -X POST "$api/auth/send"
}
trap cleanup EXIT INT TERM

cleanup >/dev/null 2>&1 || true

# bcrypt считает контроллер — ровно тот вызов, что делает панель.
line=$(curl -s -X POST -H 'content-type: application/json' \
    -d "$(jq -n --arg p "$PW" '{login:"tmpsmoke", password:$p, groups:[]}')" \
    "$api/auth/user-line" | jq -r '.line')
curl -s -o /dev/null -X POST -H 'content-type: application/json' \
    -d "$(jq -n --arg a "$line" '{address:$a}')" \
    "$api/datasets/$users/addresses"
curl -s -o /dev/null -X POST "$api/auth/send"

# Поколение доезжает до ноды и перечитывается процессом.
sleep 4

csrf() { sed -n 's/.*name="csrf" value="\([a-f0-9]*\)".*/\1/p' | head -1; }
status() { curl -s -o /dev/null -w '%{http_code}' -H "$HOST" -H "$IP" "$@"; }

# Вердикт калитки из диагностического заголовка: auth-any=verdict/code.
gate() {
    field=$1; shift
    curl -s -o /dev/null -D - -H "$HOST" -H "$IP" "$@" \
        | tr ' ' '\n' | sed -n "s/^${field}=//p" | head -1 | cut -d/ -f1,2 | tr -d '\r'
}

J=/tmp/list-truth.jar
rm -f $J

ZONE=$BASE/kyrgyzstan/ads/list-truth-check

echo '--- без сессии: инспектора спрашивают каждый раз, форма на месте ---'
check 401 'GET зоны объявлений без куки' "$(status -H "$HTML" "$ZONE")"
check deny/AUTH_NO_SESSION 'вердикт без куки' "$(gate auth-any -H "$HTML" "$ZONE")"

echo '--- вход: запись рождается в списке и несёт логин ---'
token=$(curl -s -c $J -H "$HOST" -H "$IP" "$BASE/waf/login-lalafo" | csrf)
curl -s -o /dev/null -b $J -c $J -H "$HOST" -H "$IP" \
    --data-urlencode "csrf=$token" \
    --data-urlencode "login=tmpsmoke" \
    --data-urlencode "password=$PW" \
    "$BASE/waf/login-lalafo"

check allow/AUTH_OK 'вердикт с сессией (окно грейса)' "$(gate auth-any -b $J -H "$HTML" "$ZONE")"

entry=$(curl -s "$api/datasets/$sessions/addresses" \
    | jq -r '.addresses[] | select(.reason == "AUTH_LOGIN tmpsmoke")')
check tmpsmoke 'запись списка несёт логин' \
    "$(printf '%s' "$entry" | jq -r '.reason' | cut -d' ' -f2)"

uuid=$(printf '%s' "$entry" | jq -r '.uuid')

echo "--- конец грейса (${GRACE}с): дальше сессию держит только список ---"
sleep "$GRACE"
check allow/AUTH_OK 'вердикт после грейса (запись в списке)' "$(gate auth-any -b $J -H "$HTML" "$ZONE")"

echo '--- удаление записи из списка = завершение сессии ---'
curl -s -o /dev/null -X DELETE "$api/addresses/$uuid"
sleep 3
check deny/AUTH_SESSION_REVOKED 'вердикт после удаления записи' "$(gate auth-any -b $J -H "$HTML" "$ZONE")"
check 401 'клиенту — форма входа' "$(status -b $J -H "$HTML" "$ZONE")"

echo '--- продление не воскрешает: renew без записи — обычный вход ---'
check 303 'renew уводит на форму' \
    "$(curl -s -o /dev/null -w '%{http_code}' -b $J -H "$HOST" -H "$IP" -H "$HTML" \
        "$BASE/waf/login-lalafo/renew")"

if [ "$fail" -eq 0 ]; then echo 'ИТОГ: все проверки зелёные'; else echo "ИТОГ: провалов $fail"; exit 1; fi
exit "$fail"
BOXED
