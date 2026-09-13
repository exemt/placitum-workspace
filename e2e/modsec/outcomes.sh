#!/bin/sh
# Инициаторы по исходу у инспектора правил: просьба соседу и запись субъекта
# в живой набор.
#
#     docker compose up -d --wait
#     sh tests/modsec/outcomes.sh
#
# Гоняется с хоста, а не внутри nginx: проверять надо две вещи, которых с края
# не видно. Просьба видна прямо в ответе инспектора -- её показывает проба;
# запись субъекта видна в базе контроллера -- он секвенсор набора.
#
# Адрес пробе задаётся публичный нарочно: анонсированную подсеть и номер
# системы инспектор берёт у сервиса гео, а у адресов контура анонса нет.
# Резолв асинхронный -- первый запрос субъекта его греет, записывает второй:
# за справочником на горячем пути не ждут, и это цена такого решения.

set -eu

export MSYS_NO_PATHCONV=1

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

SCOPE=${SCOPE:-31291282-a50c-4107-9164-e2ae46cd8b36}
CTRL=${CTRL:-http://127.0.0.1:8080}
PROFILE=${PROFILE:-strict}
LIST=${LIST:-cap_ipban}

# Классическая инъекция: libinjection даёт баллы на любом уровне паранойи.
SQLI="id=1%27+or+1%3D1--"
CLIENT=${CLIENT:-8.8.8.8}
PREFIX=${PREFIX:-8.8.8.0/24}

fail=0

ok()  { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=$((fail + 1)); }

probe() {
    docker compose exec -T inspector-modsec modsec-probe \
        --profile "$PROFILE" --client-ip "$CLIENT" --uri "/x?$SQLI" \
        --expect score 2>/dev/null | tr -d '\r'
}

rows() {
    docker compose exec -T postgres psql -U waf -d waf -t -A -F'|' -c \
        "select a.address, a.origin, a.reason from dataset_addresses a
           join datasets d on d.id = a.dataset_id
          where d.name = '$LIST' and a.origin = 'modsec' limit 1" \
        2>/dev/null | head -1 | tr -d "\r"
}

drop() {
    ids=$(docker compose exec -T postgres psql -U waf -d waf -t -A -c \
        "select a.id from dataset_addresses a
           join datasets d on d.id = a.dataset_id
          where d.name = '$LIST' and a.origin = 'modsec'" \
        2>/dev/null | tr -d "\r")

    for id in $ids; do
        curl -s -o /dev/null -X DELETE "$CTRL/api/$SCOPE/addresses/$id" || true
    done
}

trap drop EXIT INT TERM

drop

echo "--- просьба соседу ---"

ask=$(probe)

case "$ask" in
    *'"to":"captcha","do":"challenge"'*)
        ok "просьба капче едет в ответе рядом с вердиктом" ;;
    *)
        bad "в ответе нет просьбы: $(echo "$ask" | head -c 160)" ;;
esac

case "$ask" in
    *'"verdict":"score"'*) ok "вердикт остался своим: score" ;;
    *) bad "вердикт не score: $(echo "$ask" | head -c 120)" ;;
esac

echo
echo "--- запись субъекта в набор ---"

# Второй запрос: справочник уже прогрет первым.
row=""
i=0

while [ $i -lt 20 ]; do
    probe > /dev/null 2>&1 || true
    row=$(rows)
    [ -n "$row" ] && break
    i=$((i + 1))
    sleep 1
done

if [ "$row" = "$PREFIX|modsec|MODSEC_NET_HOT" ]; then
    ok "в набор уехала анонсированная подсеть: $row"
else
    bad "в наборе не подсеть: ${row:-пусто}"
fi

# Адрес клиента в набор не уезжал: строка просила именно подсеть.
case "$row" in
    "$CLIENT"*) bad "записан адрес вместо подсети" ;;
    *) ok "адрес клиента остался вне набора" ;;
esac

echo

if [ "$fail" -ne 0 ]; then
    echo "провалено: $fail"
    exit 1
fi

echo "все проверки прошли"
