#!/bin/sh
# Keeper и модуль v3 сквозняком (docs/keeper.md).
#
#     docker compose up -d --wait
#     sh tests/keeper/keeper.sh
#
# Истина активных наборов -- keeper; край держит зеркало в shm и сверяет
# (epoch, seq, hash) на каждом кадре. Прогон пишет адрес хоста в
# banned_by_counter событием с ответом и смотрит на edge-01 напрямую (:8086,
# мимо haproxy): waf_local_check banned_by_counter стоит на сервере, и запись
# обязана закрыть запрос без reload и без участия контроллера. Затем -- снятие,
# срок, рестарт keeper (новая эпоха -> края перечитывают) и отсутствие
# «diverged» в логах краёв: единственный WARN, который всегда ошибка.

set -eu

export MSYS_NO_PATHCONV=1

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

fail=0
SET=banned_by_counter
HOST='Host: juice.waf.test'

# Адрес, с которого край видит запросы с хоста: шлюз сети compose.
NET=$(docker inspect waf-edge-01-1 --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' | head -1)
if [ -z "$NET" ]; then
    echo "FAIL не нашёл шлюз сети edge-01"
    exit 1
fi

event() {
    docker compose exec -T nats-box nats --server nats://nats:4222 req \
        "waf.sets.$SET.event" "$1" --raw 2>/dev/null
}

code() {
    env -u MSYS_NO_PATHCONV curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "$HOST" "http://127.0.0.1:8086/$1"
}

# Отказ локального слоя: запись каталога маршрута -- blocked (403) или
# too_many (429); важно, что это не ответ приложения.
blocked() {
    case "$(code "$1")" in
        403|429) echo blocked ;;
        *) echo open ;;
    esac
}

check() {
    # check <имя> <ожидание> <получено>
    if [ "$2" = "$3" ]; then
        printf 'ok   %-44s %s\n' "$1" "$3"
    else
        printf 'FAIL %-44s %s, ожидался %s\n' "$1" "$3" "$2"
        fail=$((fail + 1))
    fi
}

edge_log() {
    # edge_log <секунд> <шаблон>
    for e in 1 2 3; do
        docker logs "waf-edge-0$e-1" --since "$1s" 2>&1 | grep -E "$2" || true
    done
}

echo "--- до записи: хост проходит (адрес $NET) ---"
before=$(code 'rest/products/search?q=keeper')
if [ "$before" = "429" ]; then
    echo "FAIL хост уже забанен -- сними запись руками"; exit 1
fi
printf 'ok   %-44s %s\n' 'запрос с хоста до бана' "$before"

echo "--- add через keeper: край закрывает без reload ---"
reply=$(event "{\"v\":3,\"op\":\"add\",\"value\":\"$NET\",\"ttl\":60,\"origin\":\"e2e\",\"reason\":\"KEEPER_E2E\"}")
case "$reply" in
    *'"ok":true'*) printf 'ok   %-44s\n' 'keeper принял add' ;;
    *) echo "FAIL keeper отверг add: $reply"; fail=$((fail + 1)) ;;
esac
sleep 1
check 'край закрыл хост (waf_local_check)' blocked "$(blocked 'rest/products/search?q=keeper')"

applied=$(edge_log 15 "dataset \"$SET\" applied add" | wc -l | tr -d ' ')
check 'дельта add применена на всех краях (>=3)' 1 "$([ "$applied" -ge 3 ] && echo 1 || echo "$applied")"

echo "--- remove: край открывает ---"
event "{\"v\":3,\"op\":\"remove\",\"value\":\"$NET\",\"origin\":\"e2e\"}" >/dev/null
sleep 1
check 'край открыл хост' "$before" "$(code 'rest/products/search?q=keeper')"

echo "--- запись со сроком истекает дельтой keeper ---"
event "{\"v\":3,\"op\":\"add\",\"value\":\"$NET\",\"ttl\":4,\"origin\":\"e2e\",\"reason\":\"KEEPER_E2E_TTL\"}" >/dev/null
sleep 1
check 'бан со сроком действует' blocked "$(blocked 'rest/products/search?q=keeper')"
sleep 6
check 'срок вышел -- открыто' "$before" "$(code 'rest/products/search?q=keeper')"
expired=$(edge_log 20 "dataset \"$SET\" applied remove" | wc -l | tr -d ' ')
check 'истечение пришло дельтой remove (>=3)' 1 "$([ "$expired" -ge 3 ] && echo 1 || echo "$expired")"

echo "--- рестарт keeper: новая эпоха, края перечитывают ---"
docker compose --profile keeper restart keeper >/dev/null 2>&1
sleep 12
snap=$(edge_log 30 "dataset \"$SET\" applied snapshot epoch" | wc -l | tr -d ' ')
check 'снапшот новой эпохи на всех краях (>=3)' 1 "$([ "$snap" -ge 3 ] && echo 1 || echo "$snap")"
check 'после рестарта запрос проходит' "$before" "$(code 'rest/products/search?q=keeper')"

echo "--- сверка хешей: ни одного diverged за прогон ---"
div=$(edge_log 120 "diverged" | wc -l | tr -d ' ')
check 'diverged в логах краёв' 0 "$div"

if [ "$fail" -eq 0 ]; then
    echo "ИТОГ: все проверки зелёные"
else
    echo "ИТОГ: FAIL $fail"
    exit 1
fi
