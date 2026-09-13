#!/bin/sh
# Большой список на инспекторе адреса: выгрузка страны из Postgres в
# policy/lists/us.txt, reload, вердикты и замер 100 запросов через модуль.
#
#     docker compose up -d --wait
#     sh tests/ip/ip-large.sh
#     COUNTRY=ru sh tests/ip/ip-large.sh
#     LOAD=1 sh tests/ip/ip-large.sh   # + k6 STEPS=100:15
#
# Файл us.txt возвращается к заглушке в конце (и по сигналу).

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

COUNTRY=${COUNTRY:-us}
US=ip/policy/lists/us.txt
STUB='# Заглушка, чтобы профиль грузился. Полный us кладёт tests/ip/ip-large.sh.
9.9.9.0/24
'
fail=0

restore() {
    printf '%s' "$STUB" > "$US"
}

trap restore EXIT INT TERM

probe() {
    want=$1
    ip=$2
    docker compose exec -T inspector-ip \
        ip-probe --quiet --timeout 5s --profile heavy --client-ip "$ip" --expect "$want"
}

# Слоя HTTP здесь больше нет. Профиль heavy на стенде ни на одном маршруте не
# стоит: синтетика /ip-heavy/ снята вместе с остальной при перекройке под
# juice.waf.test. Мерить круг через nginx незачем и нечем -- предмет замера
# здесь сам инспектор с большим списком, а модуль меряют нагрузочные
# (loadgen/ip.js) и tests/nginx.
say() { # ожидание имя адрес
    if probe "$1" "$3"; then
        printf 'ok   %-36s %s  %s\n' "$2" "$3" "$1"
    else
        printf 'FAIL %-36s %s  ожидался %s\n' "$2" "$3" "$1"
        fail=$((fail + 1))
    fi
}

echo "--- dump $COUNTRY ---"
t0=$(date +%s)
docker compose exec -T postgres psql -U waf -d waf -At -c "
select a.address
  from http_spaces s
  join ip_countries c on c.http_space_id = s.id
  join ip_country_addresses a on a.country_id = c.id
 where s.name = 'default'
   and c.code = '$COUNTRY'
" > "$US"
t1=$(date +%s)

lines=$(grep -c . "$US" || true)
bytes=$(wc -c < "$US" | tr -d ' ')
first=$(head -n 1 "$US")
hit=${first%%/*}

if [ -z "$hit" ] || [ "$lines" -lt 100 ]; then
    echo "FAIL dump: $lines строк, мало для большого списка"
    exit 1
fi

printf 'ok   dump %-28s %s строк  %s байт  %ss\n' "$COUNTRY" "$lines" "$bytes" $((t1 - t0))
printf '     hit из первой сети: %s  (%s)\n' "$hit" "$first"

# Поколение с контроллера перекрывает дерево политики целиком: инспектор
# читает /app/state/policy, где списки названы uuid, а не именами. Файл,
# положенный в дерево образа, он в таком состоянии не увидит вовсе -- и
# «не стал deny» ниже сказало бы не то, что случилось на самом деле.
if docker compose exec -T inspector-ip \
    sh -c 'ls /app/state/policy/lists/ 2>/dev/null | head -1' | grep -q .
then
    cat >&2 <<'WHY'
Прогон устарел: стенд получает политику поколением с контроллера, а этот
прогон кладёт большой список файлом в дерево стенда (deploy/ip/policy).
Инспектор такой файл не читает.

Чинится переносом состава в набор e2e_ip_us через API контроллера
(/datasets/<id>/addresses) и рассылкой -- это другая механика, чем здесь.
WHY
    exit 1
fi

echo '--- reload ---'
t2=$(date +%s)
ready=0
i=0
while [ "$i" -lt 40 ]; do
    if probe deny "$hit" >/dev/null 2>&1; then
        ready=1
        break
    fi
    i=$((i + 1))
    sleep 1
done
t3=$(date +%s)

if [ "$ready" -ne 1 ]; then
    echo "FAIL reload: $hit не стал deny за 40s"
    exit 1
fi

printf 'ok   reload heavy                     %ss\n' $((t3 - t2))

echo '--- probe / http ---'
if probe deny "$hit"; then
    printf 'ok   probe hit                       %s  deny\n' "$hit"
else
    printf 'FAIL probe hit                       %s\n' "$hit"
    fail=$((fail + 1))
fi

if probe allow 10.1.2.3; then
    printf 'ok   probe allowlist                 10.1.2.3  allow\n'
else
    printf 'FAIL probe allowlist                 10.1.2.3\n'
    fail=$((fail + 1))
fi

if probe allow 203.0.113.10; then
    printf 'ok   probe miss TEST-NET             203.0.113.10  allow\n'
else
    printf 'FAIL probe miss TEST-NET             203.0.113.10\n'
    fail=$((fail + 1))
fi

echo '--- 100 решений на большом списке ---'
t4=$(date +%s)
bad=0
n=0
while [ "$n" -lt 100 ]; do
    if ! probe deny "$hit"; then
        bad=$((bad + 1))
    fi
    n=$((n + 1))
done
t5=$(date +%s)
printf 'ok   100× hit                        %s deny, ошибок %s, %ss\n' \
    "$hit" "$bad" $((t5 - t4))
if [ "$bad" != "0" ]; then
    fail=$((fail + 1))
fi

if [ "${LOAD:-0}" = "1" ]; then
    echo '--- k6 ---'
    docker compose exec -T -e STEPS="${STEPS:-100:15,500:15}" \
        -e KINDS=allow,block,geo,exclude,inverse \
        -e PROFILES=default,admin,ext,heavy \
        loadgen k6 run /app/ip.js
fi

if [ "$fail" -ne 0 ]; then
    echo "провалено: $fail"
    exit 1
fi

echo 'ok'
