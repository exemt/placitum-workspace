#!/bin/sh
# Калитка второго фактора на живом контуре: лестница вердикта, вход, заголовки
# приложению, одноразовость билета и кода, выход с отзывом, профиль общего
# кода, режим наблюдения и блокировка подбора.
#
#     docker compose up -d --wait
#     sh tests/auth/auth.sh
#
# Гоняется с хоста. Состояние входа (банка cookie) живёт внутри nats-box: она
# обязана пережить весь сценарий, а каждый docker compose exec -- это новый
# контейнерный процесс, поэтому вся ходовая часть исполняется одним sh там.
#
# Счётчики попыток и билеты чистятся в начале и в конце: сценарий намеренно
# доводит учётную запись до блокировки, и оставлять её запертой следующему
# прогону нельзя.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

SECRET=JBSWY3DPEHPK3PXP
PASSWORD=waf-demo-2fa
ACCESS_CODE=let-me-in-2fa

clean() {
    docker compose exec -T redis sh -c "
        redis-cli --scan --pattern 'auth:lock:*'  | xargs -r redis-cli del
        redis-cli --scan --pattern 'auth:fail:*'  | xargs -r redis-cli del
        redis-cli --scan --pattern 'auth:nonce:*' | xargs -r redis-cli del
    " > /dev/null 2>&1 || true
}

trap clean EXIT INT TERM

clean

# Код TOTP одноразовый: тот же код в том же шаге форма второй раз не примет.
# Ждём начала шага, чтобы у сценария была полная минута на вход и чтобы два
# прогона подряд не спорили за один код.
rem=$(( $(date +%s) % 30 ))
if [ "$rem" -gt 0 ]; then
    sleep $(( 30 - rem ))
fi

CODE=$(docker compose exec -T inspector-auth auth-probe --totp "$SECRET" | tr -d '\r\n')

docker compose exec -T nats-box sh -s "$CODE" "$PASSWORD" "$ACCESS_CODE" <<'BOXED'
code=$1
password=$2
access=$3
fail=0
BASE=http://nginx-1:8080

check() {
    want=$1; name=$2; got=$3
    if [ "$got" = "$want" ]; then
        printf 'ok   %-42s %s\n' "$name" "$got"
    else
        printf 'FAIL %-42s %s, ожидался %s\n' "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

yes_no() {
    name=$1; ok=$2
    if [ "$ok" = yes ]; then
        printf 'ok   %-42s\n' "$name"
    else
        printf 'FAIL %-42s\n' "$name"
        fail=$((fail + 1))
    fi
}

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# Решение калитки видно в диагностическом заголовке модуля:
# X-WAF-Debug: ... auth=<вердикт>/<код причины>/<время>/profile=<имя>
gate() {
    curl -s -o /dev/null -D - "$@" \
        | tr ' ' '\n' | sed -n 's/^auth[a-z-]*=//p' | head -1 | cut -d/ -f1,2 | tr -d '\r'
}

# Форма отдаёт nonce скрытым полем; он же лежит в билете waf_lgn. Двойная
# отправка -- то, что форма проверяет до провайдеров.
csrf() { sed -n 's/.*name="csrf" value="\([a-f0-9]*\)".*/\1/p' | head -1; }

echo "--- лестница вердикта ---"

check 303 'навигационный GET без сессии' \
    "$(status -H 'Accept: text/html' $BASE/auth/echo)"
check 401 'POST без сессии' \
    "$(status -X POST -d x=1 -H 'Accept: text/html' $BASE/auth/echo)"
check 401 'XHR без text/html в Accept' \
    "$(status -H 'Accept: application/json' $BASE/auth/echo)"

# Пути API -- отдельный маршрут с профилем-спутником (default-api: кука
# последней калитки, пустые redirect_methods), а не список в профиле:
# без полного входа 401 всегда, даже на навигационном GET.
check 401 'путь API даже на навигационном GET' \
    "$(status -H 'Accept: text/html' $BASE/auth/api/orders)"

# Публичный путь под калиткой -- отдельный маршрут без инспектора, а не список
# исключений в профиле: калитку на нём не спрашивают вовсе, поэтому в
# диагностическом заголовке нет ни вердикта, ни кода.
check 200 'публичный путь отдаёт приложение' "$(status $BASE/auth/healthz)"
check '' 'на публичном маршруте калитки нет' "$(gate $BASE/auth/healthz)"

# Цель редиректа собирает инспектор, и возврат в неё кладёт он же: в сообщении
# едет только путь, а строка запроса лежит отдельным объектом обменника.
loc=$(curl -s -o /dev/null -D - -H 'Accept: text/html' "$BASE/auth/echo?page=2" \
      | sed -n 's/^[Ll]ocation: //p' | tr -d '\r')
case "$loc" in
    */waf/login\?rd=%2Fauth%2Fecho%3Fpage%3D2) ok=yes ;;
    *) ok=no ;;
esac
yes_no 'редирект несёт возврат вместе с query' "$ok"

echo
echo "--- вход ---"

J=/tmp/auth-jar
rm -f $J
token=$(curl -s -c $J "$BASE/waf/login?rd=%2Fauth%2Fecho" | csrf)

# Две калитки -- два шага. Первая (default) спрашивает логин и пароль;
# вторая (default-totp) стоит на маршруте второй волной, личность берёт из
# сессии первой и спрашивает только код.
check 303 'первая калитка: логин и пароль' \
    "$(status -b $J -c $J -X POST \
        --data-urlencode "csrf=$token" \
        --data-urlencode 'login=operator' \
        --data-urlencode "password=$password" \
        $BASE/waf/login)"
check 303 'после пароля маршрут уводит на вторую калитку' \
    "$(status -b $J -c $J -H 'Accept: text/html' $BASE/auth/echo)"
loc=$(curl -s -o /dev/null -D - -b $J -H 'Accept: text/html' $BASE/auth/echo \
      | sed -n 's/^[Ll]ocation: //p' | tr -d '\r')
case "$loc" in
    */waf/login-totp\?rd=*) ok=yes ;;
    *) ok=no ;;
esac
yes_no 'цель -- форма кода' "$ok"

form=$(curl -s -b $J -c $J "$BASE/waf/login-totp?rd=%2Fauth%2Fecho")
case "$form" in
    *'name="password"'*) ok=no ;;
    *'name="code"'*) ok=yes ;;
    *) ok=no ;;
esac
yes_no 'форма кода спрашивает только код' "$ok"

t_totp=$(echo "$form" | csrf)
check 303 'вторая калитка: код' \
    "$(status -b $J -c $J -X POST \
        --data-urlencode "csrf=$t_totp" \
        --data-urlencode "code=$code" \
        $BASE/waf/login-totp)"

check 200 'GET с сессией' "$(status -b $J -H 'Accept: text/html' $BASE/auth/echo)"
check 200 'POST с сессией' "$(status -b $J -X POST -d x=1 $BASE/auth/echo)"

# Токены запечатаны: ни логина, ни групп наружу. Подписанный отдавал их
# любому, кто взглянет на cookie, -- ради этого схема и менялась.
case "$(cat $J)" in
    *operator*|*ops*) ok=no ;;
    *) ok=yes ;;
esac
yes_no 'личности в куках не видно' "$ok"

case "$(cat $J)" in
    *waf_id*) ok=yes ;;
    *) ok=no ;;
esac
yes_no 'удостоверение приложению выдано' "$ok"

# Заголовки личности ставятся на каждом allow целиком: unset на фазе запроса
# модуль не поддерживает, и подделка снимается только перезаписью.
seen=$(curl -s -b $J -H 'X-WAF-User: admin' -H 'X-WAF-Groups: root' $BASE/auth/echo \
       | tr -d ' \n')

for pair in '"x-waf-user","operator"' '"x-waf-groups","ops"' '"x-waf-auth","pwd+totp"'; do
    case "$seen" in
        *"$pair"*) ok=yes ;;
        *) ok=no ;;
    esac
    yes_no "заголовок приложению $pair" "$ok"
done

case "$seen" in
    *'"admin"'*|*'"root"'*) ok=no ;;
    *) ok=yes ;;
esac
yes_no 'подделанный заголовок перезаписан' "$ok"

echo
echo "--- другой способ входа тем же процессом ---"
#
# Профиль list -- тот же провайдер local, что у default, но на его маршруте
# нет второй калитки: способ входа задаёт набор инспекторов маршрута, а не
# профиль.

form=$(curl -s -c /tmp/auth-list-jar "$BASE/waf/login-list")

case "$form" in
    *'name="code"'*) ok=no ;;
    *'name="password"'*) ok=yes ;;
    *) ok=no ;;
esac
yes_no 'форма списка не спрашивает код' "$ok"

tl=$(echo "$form" | csrf)

check 303 'вход по списку без второго фактора' \
    "$(status -b /tmp/auth-list-jar -c /tmp/auth-list-jar -X POST \
        --data-urlencode "csrf=$tl" \
        --data-urlencode 'login=operator' \
        --data-urlencode "password=$password" \
        $BASE/waf/login-list)"
check 200 'маршрут списка открылся' \
    "$(status -b /tmp/auth-list-jar $BASE/auth-list/echo)"

# Тот же пользователь и тот же пароль, но профиль default требует ещё и код --
# и без него не пускает. Это и есть переключение способа входа.
seen=$(curl -s -b /tmp/auth-list-jar $BASE/auth-list/echo | tr -d ' \n')
case "$seen" in
    *'"x-waf-auth","pwd"'*) ok=yes ;;
    *) ok=no ;;
esac
yes_no 'приложению видно, каким фактором вошли' "$ok"

echo
echo "--- одноразовость билета и кода ---"

# Тот же код TOTP вторым билетом: перехваченный код не должен работать
# оставшуюся часть шага.
# Сессия первой калитки уже есть в банке; новый билет формы кода -- и тот же
# код. Сожжён после первого принятия.
K=/tmp/auth-jar2
cp $J $K
t2=$(curl -s -b $K -c $K "$BASE/waf/login-totp" | csrf)
check 401 'повторный код TOTP отвергнут' \
    "$(status -b $K -X POST \
        --data-urlencode "csrf=$t2" \
        --data-urlencode "code=$code" \
        $BASE/waf/login-totp)"

# Код без сессии первой калитки: второй фактор не знает, чей секрет
# проверять, и отказывает до проверки кода.
N=/tmp/auth-nofirst
rm -f $N
t4=$(curl -s -c $N "$BASE/waf/login-totp" | csrf)
check 401 'код без первой калитки отвергнут' \
    "$(status -b $N -X POST \
        --data-urlencode "csrf=$t4" \
        --data-urlencode "code=$code" \
        $BASE/waf/login-totp)"

# Уже сожжённый билет: nonce гасится до провайдеров, поэтому один билет не даёт
# неограниченного числа попыток подбора.
check 401 'повторный билет формы отвергнут' \
    "$(status -b $J -X POST \
        --data-urlencode "csrf=$token" \
        --data-urlencode 'login=operator' \
        --data-urlencode "password=$password" \
        $BASE/waf/login)"

echo
echo "--- выход и отзыв ---"

cp $J /tmp/auth-stolen
check 200 'выход' "$(status -b $J -c $J $BASE/waf/login/logout)"

# Отзыв инспектор читает из памяти и освежает раз в roster.revoke_refresh:
# окно между выходом и тем, как его увидят все реплики, -- свойство схемы.
sleep 4
check deny/AUTH_SESSION_REVOKED 'угнанная cookie после отзыва' \
    "$(gate -b /tmp/auth-stolen -X POST -d x=1 $BASE/auth/echo)"

echo
echo "--- профиль общего кода и наблюдение ---"

C=/tmp/auth-code
rm -f $C
form=$(curl -s -c $C "$BASE/waf/code?rd=%2Fauth-code%2Fecho")
t3=$(echo "$form" | csrf)

case "$form" in
    *'name="login"'*) ok=no ;;
    *) ok=yes ;;
esac
yes_no 'форма кода спрашивает только код' "$ok"

check 303 'вход по общему коду' \
    "$(status -b $C -c $C -X POST \
        --data-urlencode "csrf=$t3" \
        --data-urlencode "code=$access" \
        $BASE/waf/code)"
check 200 'маршрут кода после входа' "$(status -b $C $BASE/auth-code/echo)"
check deny/AUTH_SESSION_SCOPE 'токен профиля кода на чужом маршруте' \
    "$(gate -b $C -X POST -d x=1 $BASE/auth/echo)"
check allow/AUTH_OBSERVE 'наблюдение пропускает без сессии' \
    "$(gate -X POST -d x=1 $BASE/auth-observe/echo)"

echo
echo "--- подбор пароля ---"
#
# В самом конце нарочно: блокировка считается по адресу клиента и общая на весь
# процесс, поэтому после неё не пройдёт ни один вход с этой машины -- ни в один
# профиль. Числом попытка не проверяется: неудачи предыдущих разделов уже в
# счётчике, и точный номер зависит от того, какие из них дошли до провайдеров.

i=1
locked=нет
while [ $i -le 8 ]; do
    L=/tmp/auth-brute
    rm -f $L
    t=$(curl -s -c $L "$BASE/waf/login" | csrf)
    out=$(curl -s -b $L -X POST \
        --data-urlencode "csrf=$t" \
        --data-urlencode 'login=operator' \
        --data-urlencode "password=wrong-$i" \
        $BASE/waf/login)
    case "$out" in
        *'Слишком много попыток'*) locked=$i; break ;;
    esac
    i=$((i + 1))
done

if [ "$locked" = нет ]; then
    yes_no 'подбор упирается в блокировку' no
else
    printf 'ok   %-42s попытка %s\n' 'подбор упирается в блокировку' "$locked"
fi

echo
if [ "$fail" -eq 0 ]; then
    echo 'все проверки прошли'
else
    echo "провалено проверок: $fail"
fi

exit "$fail"
BOXED

# Удостоверение открывает приложение, а не калитка, поэтому проверка здесь, а
# не внутри бокса: ключ приложения смонтирован в auth-http.
echo
echo "--- удостоверение приложению ---"

ID=$(docker compose exec -T nats-box sh -c         "grep waf_id /tmp/auth-stolen | awk '{print \$7}'" | tr -d '
')

if [ -z "$ID" ]; then
    echo 'FAIL удостоверения нет в банке cookie'
    exit 1
fi

OPENED=$(docker compose exec -T auth-http auth-probe --open-identity "$ID" | tr -d '
')

case "$OPENED" in
    *'"sub":"operator"'*) printf 'ok   %-42s
' 'приложение открывает удостоверение' ;;
    *) printf 'FAIL %-42s %s
' 'удостоверение не открылось' "$OPENED"; exit 1 ;;
esac

case "$OPENED" in
    *'"grp":["ops"]'*) printf 'ok   %-42s
' 'группы доехали' ;;
    *) printf 'FAIL %-42s %s
' 'групп в удостоверении нет' "$OPENED"; exit 1 ;;
esac

# Ключом сессии удостоверение не открыть: у приложения свой, и это граница, а
# не деталь -- с ключом сессии оно выписало бы себе вход.
if docker compose exec -T auth-http auth-probe --open-identity "$ID"         --key-file /run/secrets/waf_auth_hmac > /dev/null 2>&1; then
    echo 'FAIL удостоверение открылось ключом сессии'
    exit 1
fi

printf 'ok   %-42s
' 'ключом сессии не открывается'
