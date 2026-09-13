#!/bin/sh
# Провайдер ldap калитки на живом каталоге.
#
#     docker compose up -d --wait
#     sh tests/auth/ldap.sh
#
# Каталог -- контейнер ldap (osixia/openldap), дерево из deploy/ldap/bootstrap.
# Пароль здесь не хранит никто в контуре: форма отдаёт его серверу операцией
# bind и знает только, сошлось или нет.
#
# Учётные записи стенда:
#   ivanov  / ldap-demo-2fa -- в группе cn=waf-users, пускаем
#   sidorov / ldap-demo-2fa -- тот же пароль, группы нет, не пускаем

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

PASSWORD=ldap-demo-2fa

echo "--- каталог отвечает ---"
docker compose exec -T ldap ldapwhoami -x \
    -H ldap://127.0.0.1:389 \
    -D "uid=ivanov,ou=people,dc=corp,dc=example,dc=com" \
    -w "$PASSWORD" | tr -d '\r'

docker compose exec -T nats-box sh -s "$PASSWORD" <<'BOXED'
password=$1
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

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
csrf()   { sed -n 's/.*name="csrf" value="\([a-f0-9]*\)".*/\1/p' | head -1; }
error()  { grep -o 'class="error">[^<]*' | sed 's/.*>//'; }

# Вход одной попыткой: билет одноразовый, поэтому на каждую -- своя банка.
try() {
    login=$1
    pass=$2
    jar=$(mktemp)
    t=$(curl -s -c "$jar" "$BASE/waf/login-ldap" | csrf)
    curl -s -b "$jar" -X POST \
        --data-urlencode "csrf=$t" \
        --data-urlencode "login=$login" \
        --data-urlencode "password=$pass" \
        "$BASE/waf/login-ldap"
    rm -f "$jar"
}

echo
echo "--- калитка на месте ---"
check 303 'навигационный GET уводит на форму' \
    "$(status -H 'Accept: text/html' $BASE/auth-ldap/echo)"
check 401 'POST без сессии' \
    "$(status -X POST -d x=1 $BASE/auth-ldap/echo)"

echo
echo "--- вход ---"
J=/tmp/auth-ldap
rm -f $J
t=$(curl -s -c $J "$BASE/waf/login-ldap?rd=%2Fauth-ldap%2Fecho" | csrf)
check 303 'ivanov: пароль сошёлся в каталоге' \
    "$(status -b $J -c $J -X POST \
        --data-urlencode "csrf=$t" \
        --data-urlencode 'login=ivanov' \
        --data-urlencode "password=$password" \
        $BASE/waf/login-ldap)"
check 200 'маршрут открылся' "$(status -b $J $BASE/auth-ldap/echo)"

# Группы приезжают обратным поиском по member=<dn>: memberOf есть у Active
# Directory и у OpenLDAP с overlay memberof, а без него членство приходится
# спрашивать с другой стороны.
seen=$(curl -s -b $J $BASE/auth-ldap/echo | tr -d ' \n')
for pair in '"x-waf-user","ivanov"' '"x-waf-groups","waf-users"' '"x-waf-auth","ldap"'; do
    case "$seen" in
        *"$pair"*) printf 'ok   %-42s %s\n' 'заголовок приложению' "$pair" ;;
        *) printf 'FAIL %-42s %s\n' 'заголовок приложению' "$pair"; fail=$((fail + 1)) ;;
    esac
done

echo
echo "--- отказы ---"

# Пароль тот же, группы нет. Для клиента это отказ, для аудита -- другой код.
out=$(try sidorov "$password")
case "$out" in
    *'Доступ запрещён'*) printf 'ok   %-42s\n' 'sidorov: пароль верен, группы нет' ;;
    *) printf 'FAIL %-42s %s\n' 'sidorov: ожидался отказ по группе' "$(printf '%s' "$out" | error)"
       fail=$((fail + 1)) ;;
esac

out=$(try ivanov nope)
case "$out" in
    *'Неверные данные'*) printf 'ok   %-42s\n' 'неверный пароль' ;;
    *) printf 'FAIL %-42s\n' 'неверный пароль принят'; fail=$((fail + 1)) ;;
esac

# Пустой пароль -- анонимный bind, каталог отвечает успехом. Отсекается до
# похода в каталог, иначе это дыра, а не особенность LDAP.
out=$(try ivanov '')
case "$out" in
    *'Неверные данные'*) printf 'ok   %-42s\n' 'пустой пароль (анонимный bind)' ;;
    *) printf 'FAIL %-42s\n' 'пустой пароль принят'; fail=$((fail + 1)) ;;
esac

out=$(try nobody "$password")
case "$out" in
    *'Неверные данные'*) printf 'ok   %-42s\n' 'нет такой записи' ;;
    *) printf 'FAIL %-42s\n' 'неизвестный логин принят'; fail=$((fail + 1)) ;;
esac

echo
if [ "$fail" -eq 0 ]; then
    echo 'все проверки прошли'
else
    echo "провалено проверок: $fail"
fi

exit "$fail"
BOXED
