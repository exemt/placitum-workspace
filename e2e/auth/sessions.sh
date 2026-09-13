#!/bin/sh
# Сессии в аудите: три режима калитки на живом контуре.
#
#     docker compose up -d --wait
#     node tests/auth/sessions-fixtures.mjs     # источники, профили, маршруты
#     sh tests/auth/sessions.sh
#
#   own  -- своя сессия (lalafo-users): вход формой, запись sessions в аудите
#           с видом own и логином.
#   jwt  -- токен Juice Shop (RS256, публичный ключ приложения): без токена
#           401, с токеном allow, порченый токен -- AUTH_SESSION_BAD; в аудите
#           kind=jwt, verified=true, логин из data.email.
#   app  -- кука echo-приложения: без записи в списке 401, вход подсмотрен на
#           фазе ответа (/set-cookie), хеш куки ложится в echo_sessions с
#           логином, дальше запросы с кукой -- allow; в аудите kind=app.
#
# Дальше -- обе калитки на одном пути (/echo/): в записи две сессии, и она
# находится по любой из личностей.
#
# Последняя часть -- журнал: личность записи это пара «источник:логин», ею же
# журнал группирует (by=user) и её же принимает фильтр user=.
#
# Гоняется с хоста, ходовая часть -- в nats-box: с хоста трафик до haproxy
# не доходит. Фикстуры ставит sessions-fixtures.mjs (идемпотентно), издание
# каналов nginx/auth -- тоже там.

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
IP='X-Forwarded-For: 10.0.0.19'
HTML='Accept: text/html,application/xhtml+xml'
PW=list-truth-1

check() {
    want=$1; name=$2; got=$3
    if [ "$got" = "$want" ]; then
        printf 'ok   %-58s %s\n' "$name" "$got"
    else
        printf 'FAIL %-58s %s, ожидался %s\n' "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

status() { curl -s -o /dev/null -w '%{http_code}' -H "$HOST" -H "$IP" "$@"; }

# Вердикт калитки из диагностического заголовка: <имя>=verdict/code.
gate() {
    field=$1; shift
    curl -s -o /dev/null -D - -H "$HOST" -H "$IP" "$@" \
        | tr ' ' '\n' | sed -n "s/^${field}=//p" | head -1 | cut -d/ -f1,2 | tr -d '\r'
}

# Запись аудита по логину: логгер пишет пачками, ждём до 15 с.
audit() {
    q=$1
    i=0
    while [ $i -lt 15 ]; do
        out=$(curl -s "$CTRL/api/search/audit?$q&limit=5")
        if [ "$(printf '%s' "$out" | jq -r '.items | length')" != "0" ]; then
            printf '%s' "$out"
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    printf '%s' "$out"
}

scope=$(curl -s "$CTRL/api/spaces" | jq -r '.spaces[] | select(.name=="default") | .uuid')
api="$CTRL/api/$scope"
sessions=$(curl -s "$api/datasets" | jq -r '.datasets[] | select(.name=="echo_sessions") | .uuid')

echo '=== own: своя сессия калитки ==='
J=/tmp/sessions-own.jar
rm -f $J
csrf() { sed -n 's/.*name="csrf" value="\([a-f0-9]*\)".*/\1/p' | head -1; }
token=$(curl -s -c $J -H "$HOST" -H "$IP" "$BASE/waf/login-lalafo" | csrf)
curl -s -o /dev/null -b $J -c $J -H "$HOST" -H "$IP" \
    --data-urlencode "csrf=$token" \
    --data-urlencode "login=tmpsmoke" \
    --data-urlencode "password=$PW" \
    "$BASE/waf/login-lalafo"
ZONE=$BASE/kyrgyzstan/ads/sessions-own-$$
check allow/AUTH_OK 'вердикт с сессией' "$(gate auth-any -b $J -H "$HTML" "$ZONE")"

rec=$(audit "user=tmpsmoke&uri=sessions-own-$$")
check own      'аудит: sessions[0].kind'   "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].kind')"
check tmpsmoke 'аудит: sessions[0].user'   "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].user')"
check auth-any 'аудит: sessions[0].by'     "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].by')"
check true     'аудит: sessions[0].verified' "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].verified')"

echo '=== jwt: токен Juice Shop ==='
WHOAMI=$BASE/rest/user/whoami
check 401 'без токена' "$(status "$WHOAMI")"
check deny/AUTH_NO_SESSION 'вердикт без токена' "$(gate auth-jwt "$WHOAMI")"

# Токен выдаёт само приложение: корень juice.waf.test на стенде ведёт не в
# Juice Shop, а за калиткой стоит только /rest/user/whoami.
jwt=$(curl -s -X POST http://juice-shop:3000/rest/user/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"admin@juice-sh.op","password":"admin123"}' \
    | jq -r '.authentication.token')
check 200 'с токеном' "$(status -H "Authorization: Bearer $jwt" "$WHOAMI")"
check allow/AUTH_OK 'вердикт с токеном' "$(gate auth-jwt -H "Authorization: Bearer $jwt" "$WHOAMI")"

# Порченая подпись: последний символ токена другой.
bad=$(printf '%s' "$jwt" | sed 's/.$/A/')
if [ "$bad" = "$jwt" ]; then bad=$(printf '%s' "$jwt" | sed 's/.$/B/'); fi
check 401 'порченая подпись' "$(status -H "Authorization: Bearer $bad" "$WHOAMI")"
check deny/AUTH_SESSION_BAD 'вердикт порченой подписи' "$(gate auth-jwt -H "Authorization: Bearer $bad" "$WHOAMI")"

rec=$(audit "user=admin@juice-sh.op&uri=/rest/user/whoami")
check jwt              'аудит: kind'     "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].kind')"
check juice-jwt        'аудит: source'   "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].source')"
check true             'аудит: verified' "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].verified')"
check admin            'аудит: groups (data.role)' "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].groups')"
check sha256           'аудит: id -- отпечаток токена, не сам токен' \
    "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].id' | cut -d: -f1)"

echo '=== app: кука приложения через подглядывание ==='
APP=$BASE/status/200
check 401 'без куки' "$(status "$APP")"
check deny/AUTH_NO_SESSION 'вердикт без куки' "$(gate auth-app "$APP")"

sid=e2e-$(date +%s)-$$
check 401 'с чужой кукой (не в списке)' "$(status -H "Cookie: sid=$sid" "$APP")"

# Вход приложения: POST на адрес входа, ответ с кукой -- калитка подсматривает.
hdrs=$(curl -s -o /dev/null -D - -X POST -H "$HOST" -H "$IP" \
    "$BASE/set-cookie?name=sid&value=$sid&user=alice" -d 'password=hunter2')
check 200 'вход приложения' "$(printf '%s' "$hdrs" | head -1 | cut -d' ' -f2)"
check "sid=$sid" 'ответ выдал куку' \
    "$(printf '%s' "$hdrs" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' | head -1)"

sleep 3
check allow/AUTH_OK 'вердикт с доверенной кукой' "$(gate auth-app -H "Cookie: sid=$sid" "$APP")"
check 200 'запрос с доверенной кукой' "$(status -H "Cookie: sid=$sid" "$APP")"

entry=$(curl -s "$api/datasets/$sessions/addresses" | jq -r '.addresses[] | select(.reason == "AUTH_LOGIN alice") | .address' | head -1)
check sha256 'запись списка -- хеш куки' "$(printf '%s' "$entry" | cut -d: -f1)"

rec=$(audit "user=alice&uri=/status/200")
check app     'аудит запроса: kind'    "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].kind')"
check alice   'аудит запроса: user'    "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].user')"
check auth-app 'аудит запроса: by'     "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].by')"

rec=$(audit "user=alice&uri=/set-cookie&phase=response")
check app   'аудит входа (фаза ответа): kind' "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].kind')"
check alice 'аудит входа (фаза ответа): user' "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0].user')"

# Выход: запись снимается, кука снова чужая. Ответ выхода обязан нести тело:
# на 204 и HEAD модуль фазу ответа не запускает, и подсматривать нечего.
curl -s -o /dev/null -X POST -H "$HOST" -H "$IP" -H "Cookie: sid=$sid" "$BASE/status/202"
sleep 3
check 401 'после выхода кука не доверенная' "$(status -H "Cookie: sid=$sid" "$APP")"

echo '=== две калитки на одном запросе ==='
# Массив sessions существует ради этого случая: на пути /echo/ стоят обе
# калитки -- кука приложения на волне 0, чужой токен на волне 1, -- и в записи
# обе сессии. Кука нужна свежая: прежнюю сняли выходом.
both=both-$$
curl -s -o /dev/null -X POST -H "$HOST" -H "$IP"     "$BASE/set-cookie?name=sid&value=$both&user=bob" -d 'password=hunter2'
sleep 3

BOTH=/echo/two-$$
check allow/AUTH_OK 'вердикт куки приложения'     "$(gate auth-app -H "Cookie: sid=$both" -H "Authorization: Bearer $jwt" "$BASE$BOTH")"
check allow/AUTH_OK 'вердикт токена на том же запросе'     "$(gate auth-jwt -H "Cookie: sid=$both" -H "Authorization: Bearer $jwt" "$BASE$BOTH")"

rec=$(audit "uri=$BOTH")
check 2 'аудит: две сессии в одной записи'     "$(printf '%s' "$rec" | jq -r '.items[0].sessions | length')"
# Порядок -- порядок волн: сначала калитка приложения, потом токен.
check echo-app:bob 'аудит: личность первой волны'     "$(printf '%s' "$rec" | jq -r '.items[0].sessions[0] | .source + ":" + .user')"
check juice-jwt:admin@juice-sh.op 'аудит: личность второй волны'     "$(printf '%s' "$rec" | jq -r '.items[0].sessions[1] | .source + ":" + .user')"
check app/jwt 'аудит: виды сессий'     "$(printf '%s' "$rec" | jq -r '[.items[0].sessions[].kind] | join("/")')"

# Запись с двумя сессиями ищется по любой из них -- и это одна и та же запись.
ray=$(printf '%s' "$rec" | jq -r '.items[0].ray')
check "$ray" 'ищется по личности приложения'     "$(curl -s "$CTRL/api/search/audit?uri=$BOTH&user=echo-app:bob&limit=1" | jq -r '.items[0].ray')"
check "$ray" 'ищется по личности токена'     "$(curl -s "$CTRL/api/search/audit?uri=$BOTH&user=juice-jwt:admin@juice-sh.op&limit=1" | jq -r '.items[0].ray')"

echo '=== журнал: личность и группировка ==='
# Личность записи -- пара «источник:логин»: журнал так её и показывает, так же
# группирует и такую же принимает в фильтре. Проверяем три свойства: ключ
# группы, разворот группы в те же строки и то, что однофамилец из другого
# источника в них не попадает.
groups() { curl -s "$CTRL/api/search/audit/groups?by=user&limit=50"; }
total() { curl -s "$CTRL/api/search/audit?$1&limit=1" | jq -r '.total'; }

check echo-app:alice 'ось группировки -- источник:логин'     "$(groups | jq -r '.items[] | select(.keys.user == "echo-app:alice") | .keys.user' | head -1)"

# Счёт группы и счёт её фильтра сходятся, когда логгер дописал пачку: пока
# запись едет, расходятся оба, а не один из них.
same=false
i=0
while [ $i -lt 5 ]; do
    hits=$(groups | jq -r '.items[] | select(.keys.user == "echo-app:alice") | .hits' | head -1)
    rows=$(total 'user=echo-app:alice')
    if [ "$hits" = "$rows" ] && [ "${hits:-0}" != "0" ]; then
        same=true
        break
    fi
    sleep 2
    i=$((i + 1))
done
check true 'разворот группы даёт ровно её строки' "$same"

check 0 'однофамилец другого источника не ловится' "$(total 'user=juice-jwt:alice')"
check "$rows" 'голый логин ловит ту же alice' "$(total 'user=alice')"
check "$rows" 'пустой источник -- логин целиком' "$(total 'user=:alice')"

echo
if [ "$fail" -eq 0 ]; then
    echo 'PASS'
else
    echo "FAIL: $fail"
    exit 1
fi
BOXED
