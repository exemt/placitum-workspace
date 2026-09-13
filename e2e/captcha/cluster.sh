#!/bin/sh
# Капча на трёх краях: общий счёт корзин, изоляция профилей и петля отказов,
# доведённая правилами до бана локальным слоем.
#
#     docker compose up -d --wait
#     sh tests/captcha/cluster.sh
#
# Чем этот прогон отличается от captcha.sh: тот проверяет один край и одного
# клиента, этот -- групповую работу. Запросы идут на nginx-1..3 (три
# waf_node_id, общий nginx.conf) и растекаются по двум репликам инспектора,
# а счёт корзин у них один на всех -- контурный Redis. Cookie передаются
# заголовком, а не банкой: у трёх нод три разных хоста, и банка бы не
# поделилась между ними, тогда как билет привязан к подсети и UA, не к краю.
#
# Маршрут прогона -- /captcha-cluster/ (профиль cluster): виджет каждому,
# провал -> +30% корзины ip, порог бана -> адрес в cap_ipban, и первая строка
# маршрута режет забаненного локальным слоем, до шины. Набор свой, а не
# blocklist: тем владеет прогон наборов (tests/dataset), который публикует
# снапшоты в шину сам, минуя контроллер, -- наши записи он бы затёр.
#
# Профиль и набор прогон заводит сам, если их в базе нет (первый запуск на
# свежем стенде), и оставляет: маршрут /captcha-cluster/ в nginx.conf на них
# ссылается. Корзина течёт медленно нарочно -- 0.1%/с: субъект обязан
# остаться горячим на всё время проверки, пока запись едет через секвенсор и
# доезжает до краёв, иначе к моменту сверки банить будет нечего.

set -eu

# Рига nginx-1..3 с маршрутами капчи на стенде не поднимается: маршрутов капчи
# у стенда нет. Без неё прогон не о чем -- пропуск, а не ложный FAIL.
if ! docker compose ps --services 2>/dev/null | grep -qx nginx-1; then
    echo "skip: рига nginx-1 не поднята, маршрутов капчи на стенде нет"
    exit 0
fi

# docker compose exec с хоста под MSYS: иначе пути уезжают в Windows.
export MSYS_NO_PATHCONV=1

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

SCOPE=${SCOPE:-31291282-a50c-4107-9164-e2ae46cd8b36}
CTRL=${CTRL:-http://127.0.0.1:8080}
PROFILE=cluster
BANLIST=cap_ipban

fail=0
started=$(date -u +%s)

ok()  { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=$((fail + 1)); }

api() { # метод путь [тело]
    if [ $# -ge 3 ]; then
        curl -s -X "$1" "$CTRL/api/$SCOPE$2" -H 'content-type: application/json' -d "$3"
    else
        curl -s -X "$1" "$CTRL/api/$SCOPE$2"
    fi
}

# Набор и профиль прогона. Умолчания дописывает контроллер (normalizeDoc),
# поэтому документ здесь -- только то, чем этот профиль отличается.
ensure_stand() {
    if ! api GET /datasets | grep -q "\"$BANLIST\""; then
        api POST /datasets "{\"name\":\"$BANLIST\",
            \"description\":\"Адреса, забаненные правилами капчи\",
            \"mode\":\"active\",\"kind\":\"list\",\"type\":\"ipv4\",
            \"limit\":8192,\"ttl\":\"1h\"}" > /dev/null
        echo "     создан набор $BANLIST"
    fi

    if api GET /captcha/profiles | grep -q "\"name\":\"$PROFILE\""; then
        return
    fi

    # Сервер берётся у соседнего профиля, а не первый попавшийся: путь
    # страницы обязан быть локейшеном именно этого сервера, иначе контроллер
    # отвергнет запись (unknown_location).
    server=$(api GET /captcha/profiles \
        | tr ',' '\n' | sed -n 's/.*"server_id":"\([0-9a-f-]*\)".*/\1/p' | head -1)

    if [ -z "$server" ]; then
        echo "FAIL: не у кого взять server_id -- заведите профиль капчи в панели"
        exit 1
    fi

    created=$(api POST /captcha/profiles "{\"name\":\"$PROFILE\",
        \"description\":\"Групповой прогон: три края, общий счёт, бан правилами\",
        \"server_id\":\"$server\",
        \"doc\":{\"mode\":\"enforce\",\"path\":\"/waf/captcha\",
          \"trigger\":{\"when\":\"always\"},
          \"buckets\":{\"ip\":{\"max\":100,\"loss\":0.1,\"captchaAt\":60,\"banAt\":80}},
          \"rules\":[
            {\"on\":\"fail\",\"charge\":\"ip\",\"percent\":30},
            {\"on\":\"pass\",\"charge\":\"ip\",\"percent\":-100},
            {\"on\":\"bucket_ban\",\"bucket\":\"ip\",\"list\":\"$BANLIST\",
             \"write\":\"addr\",\"ttlS\":600,\"code\":\"CAPTCHA_LOOP\"}],
          \"clearance\":{\"scope\":\"profile\",\"ttlS\":600}}}")

    case "$created" in
        *"\"name\":\"$PROFILE\""*) ;;
        *)
            echo "FAIL: профиль $PROFILE не заведён: $(echo "$created" | head -c 200)"
            exit 1
            ;;
    esac

    api POST /captcha/send '{}' > /dev/null
    echo "     заведён профиль $PROFILE и разослан флоту"
}

check() {
    want=$1; name=$2; got=$3

    if [ "$got" = "$want" ]; then
        printf 'ok   %-52s %s\n' "$name" "$got"
    else
        printf 'FAIL %-52s %s, ожидался %s\n' "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

box() { docker compose exec -T nats-box sh -c "$1"; }

# Код ответа маршрута на конкретном крае.
code() { box "curl -s -o /dev/null -w '%{http_code}' $2 http://nginx-$1:8080$3"; }

# Решение инспектора из диагностического заголовка модуля:
# X-WAF-Debug: ... captcha-cluster=<вердикт>/<код>/...
gate() {
    box "curl -s -o /dev/null -D - $2 http://nginx-$1:8080$3 \
         | tr ' ' '\n' | sed -n 's/^captcha[a-z-]*=//p' | head -1 | cut -d/ -f1,2 | tr -d '\r'"
}

# Кто отказал: by=local -- локальный слой края (набор), by=inspector -- вердикт
# с шины. Это и есть разница между «модуль забанил по списку» и «капча увела».
by() {
    box "curl -s -o /dev/null -D - $2 http://nginx-$1:8080$3 \
         | tr ' ' '\n' | sed -n 's/^by=//p' | head -1 | tr -d '\r'"
}

# Набор едет каждому краю своим консьюмером, и приходит он к ним не в один
# такт: ждём нужного состояния на каждом крае отдельно, а не на первом.
wait_code() { # край код опции путь
    i=0

    while [ $i -lt 60 ]; do
        [ "$(code "$1" "$3" "$4")" = "$2" ] && return 0
        i=$((i + 1))
        sleep 1
    done

    return 1
}

# Корзина в контурном Redis. Хранение сдвинутое (docs/inspectors/captcha/
# buckets.md): stored = effective + rate*(now - 2024-01-01), rate = loss/100*max.
# У корзины ip профилей стенда max=100, значит rate = loss ед/с.
epoch() { echo $(( $(date -u +%s) - 1704067200 )); }

bucket_set() { # профиль корзина субъект уровень потери
    printf '%s' "$(docker compose exec -T redis redis-cli set \
        "cap:bkt:$1:$2:$3" "$(echo "$4 $5 $(epoch)" | awk '{print $1 + $2 * $3}')" \
        EX 120)" > /dev/null
}

bucket_level() { # профиль корзина субъект потери
    raw=$(docker compose exec -T redis redis-cli --raw get "cap:bkt:$1:$2:$3" | tr -d '\r\n')

    if [ -z "$raw" ]; then
        echo "-"
        return
    fi

    echo "$raw $4 $(epoch)" | awk '{printf "%.0f", $1 - $2 * $3}'
}

# Записи, положенные капчей: их пишет правило профиля -- через шину в
# контроллер, а тот переиздаёт набор всем краям.
banlist_rows() {
    docker compose exec -T postgres psql -U waf -d waf -t -A -F'|' -c \
        "select a.address, a.origin, a.reason from dataset_addresses a
           join datasets d on d.id = a.dataset_id
          where d.name = '$BANLIST'" 2>/dev/null | tr -d '\r'
}

# Снятие бана руками оператора: удаление записи через API. Контроллер --
# владелец набора, поэтому он же разошлёт снапшот без неё.
banlist_drop() {
    ids=$(docker compose exec -T postgres psql -U waf -d waf -t -A -c \
        "select a.id from dataset_addresses a
           join datasets d on d.id = a.dataset_id
          where d.name = '$BANLIST'" 2>/dev/null | tr -d '\r')

    for id in $ids; do
        curl -s -o /dev/null -X DELETE "$CTRL/api/$SCOPE/addresses/$id" || true
    done
}

clean() {
    docker compose exec -T redis sh -c "
        redis-cli --scan --pattern 'cap:bkt:*'   | xargs -r redis-cli del
        redis-cli --scan --pattern 'cap:img:*'   | xargs -r redis-cli del
        redis-cli --scan --pattern 'cap:nonce:*' | xargs -r redis-cli del
    " > /dev/null 2>&1 || true

    banlist_drop > /dev/null 2>&1 || true
}

trap clean EXIT INT TERM

clean
ensure_stand

self=$(box "hostname -i" | awk '{print $1}' | tr -d '\r')
echo "клиент прогона: $self, края: nginx-1..3, профиль: $PROFILE"

# Прогон начинается с чистого края: снятие бана предыдущего прогона едет
# через контроллер и приходит не мгновенно, а первая же проверка ждёт
# ровно обратного. Ждём готовности, а не спим наугад.
for n in 1 2 3; do
    wait_code $n 303 "-H 'Accept: text/html'" /captcha-cluster/echo || true
done

echo

echo "--- виджет требует каждый край ---"

for n in 1 2 3; do
    check 303 "nginx-$n: /captcha-cluster/ без клиренса" \
        "$(code $n "-H 'Accept: text/html'" /captcha-cluster/echo)"
done

for n in 1 2 3; do
    check 'allow/CAPTCHA_NOT_REQUIRED' "nginx-$n: холодные корзины пропускают" \
        "$(gate $n "-H 'Accept: text/html'" /captcha-score/echo)"
done

echo
echo "--- один счёт на три края ---"

# Корзину наполняют соседи просьбами note; отправителя на этих маршрутах нет,
# поэтому заполнение кладётся прямо в общий Redis -- ровно то, что увидел бы
# инспектор от соседа. Профиль default: ip max=100, loss=1, captcha_at=60.
bucket_set default ip "$self/32" 70 1
echo "     корзина default:ip $self/32 = 70% (порог 60)"

for n in 1 2 3; do
    check 'redirect/CAPTCHA_REQUIRED' "nginx-$n: горячая корзина видна краю" \
        "$(gate $n "-H 'Accept: text/html'" /captcha-score/echo)"
done

# Изоляция профилей: ключ несёт имя профиля, у observe корзина своя и пустая.
check 'allow/CAPTCHA_NOT_REQUIRED' 'профиль observe: своя корзина, своя пустота' \
    "$(gate 2 "-H 'Accept: text/html'" /captcha-observe/echo)"

docker compose exec -T redis redis-cli del "cap:bkt:default:ip:$self/32" > /dev/null

for n in 1 2 3; do
    check 'allow/CAPTCHA_NOT_REQUIRED' "nginx-$n: корзина убрана -- край отпустил" \
        "$(gate $n "-H 'Accept: text/html'" /captcha-score/echo)"
done

echo
echo "--- провалы виджета через разные края ---"

# Билет выдаёт инспектор вердиктом redirect; он привязан к подсети и UA, а не
# к краю, поэтому одним билетом можно ходить на все три ноды.
ticket=$(box "curl -s -o /dev/null -D - -H 'Accept: text/html' \
              http://nginx-1:8080/captcha-cluster/echo \
              | sed -n 's/^[Ss]et-[Cc]ookie: waf_cap=\([^;]*\).*/\1/p' | head -1 | tr -d '\r'")

if [ -n "$ticket" ]; then
    ok "билет waf_cap выдан краем nginx-1"
else
    bad "билета нет: дальше проверять нечего"
    exit 1
fi

COOK="-H 'Cookie: waf_cap=$ticket'"

# Каждый промах -- заряд общей корзины: 25% ёмкости. Четыре подряд, каждый со
# своего края, доводят её до потолка, и порог бана (90) оказывается взят.
n=1
attempt=1

while [ "$attempt" -le 4 ]; do
    nonce=$(box "curl -s $COOK -H 'Accept: text/html' \
                 'http://nginx-$n:8080/waf/captcha?rd=%2Fcaptcha-cluster%2Fecho' \
                 | sed -n 's/.*name=\"csrf\" value=\"\([a-f0-9]*\)\".*/\1/p' | head -1")

    got=$(box "curl -s -o /dev/null -w '%{http_code}' $COOK -X POST \
               --data-urlencode 'csrf=$nonce' -d answer_image=NOPE \
               http://nginx-$n:8080/waf/captcha")

    level=$(bucket_level $PROFILE ip "$self/32" 0.1)
    check 400 "провал $attempt через nginx-$n (корзина $level%)" "$got"

    attempt=$((attempt + 1))
    n=$(( (n % 3) + 1 ))
done

level=$(bucket_level $PROFILE ip "$self/32" 0.1)

if [ "$level" != "-" ] && [ "$level" -ge 80 ]; then
    ok "корзина ip дошла до порога бана: $level% (ban_at 80)"
else
    bad "корзина ip = $level%, порог бана 80 не взят"
fi

echo
echo "--- бан правилом: список, край, соседний маршрут ---"

# Пороговое событие живёт на волне: правило сработает на следующем запросе,
# который дойдёт до инспектора. Сам этот запрос ещё обслуживается капчей.
check 303 'запрос, на котором сработал порог, ещё ведёт на виджет' \
    "$(code 3 "-H 'Accept: text/html'" /captcha-cluster/echo)"

row=""
i=0

# Правило порога срабатывает на каждом запросе, пока корзина выше порога,
# поэтому запись появляется с первого же обращения; ждать здесь приходится
# не инспектора, а секвенсор и края. Маршрут при этом продолжают дёргать:
# правилу нужен запрос, на котором сработать.
while [ $i -lt 90 ]; do
    # В базе адрес лежит так, как его прислало правило -- без маски; на края
    # он уезжает уже как /32.
    row=$(banlist_rows | grep -E "^$self(/32)?\|" || true)
    [ -n "$row" ] && break

    code 2 "-H 'Accept: text/html'" /captcha-cluster/echo > /dev/null
    i=$((i + 1))
    sleep 1
done

if [ -n "$row" ]; then
    ok "адрес уехал в $BANLIST правилом: $row"
else
    bad "записи в $BANLIST нет: правило bucket_ban не сработало"
fi

# Набор рассылается контроллером всем краям; ждём, пока доедет до каждого.
for n in 1 2 3; do
    wait_code $n 403 "-H 'Accept: text/html'" /captcha-cluster/echo || true

    check 403 "nginx-$n: забаненный адрес режется" \
        "$(code $n "-H 'Accept: text/html'" /captcha-cluster/echo)"
    check local "nginx-$n: режет локальный слой, не инспектор" \
        "$(by $n "-H 'Accept: text/html'" /captcha-cluster/echo)"
done

# Набор -- свойство края, а не маршрута: тот же адрес закрыт и на соседнем
# маршруте капчи, где стоит другой профиль.
check 403 'соседний маршрут /captcha-fast/ закрыт тем же набором' \
    "$(code 2 "" /captcha-fast/echo)"

echo
echo "--- снятие бана ---"

# Снять одну запись мало: корзина всё ещё за порогом, и первый же запрос,
# дошедший до инспектора, забанит адрес заново -- правило порога срабатывает
# на каждом запросе, памяти «уже банил» у реплики нет. Поэтому бан снимают
# вместе с причиной: сначала остывает корзина -- как после прохождения
# виджета (правило on: pass -> -100%) или просто по времени, 100/loss
# секунд, -- и только потом уходит запись.
banlist_drop
docker compose exec -T redis redis-cli del "cap:bkt:$PROFILE:ip:$self/32" > /dev/null
banlist_drop

for n in 1 2 3; do
    wait_code $n 303 "-H 'Accept: text/html'" /captcha-cluster/echo || true

    check 303 "nginx-$n: корзина остыла, запись снята -- снова виджет" \
        "$(code $n "-H 'Accept: text/html'" /captcha-cluster/echo)"
done

# Снятое снятым и остаётся: холодный субъект не банится заново ни одной
# репликой, на какую бы его ни занесло.
again=0
i=1

while [ $i -le 9 ]; do
    got=$(code $(( (i % 3) + 1 )) "-H 'Accept: text/html'" /captcha-cluster/echo)
    [ "$got" = "303" ] || again=$((again + 1))
    i=$((i + 1))
done

check 0 'девять запросов вразнобой: бан не вернулся' "$again"

wait_code 3 303 "-H 'Accept: text/html'" /captcha-fast/echo || true

check 303 'соседний маршрут /captcha-fast/ снова спрашивает капчу' \
    "$(code 3 "-H 'Accept: text/html'" /captcha-fast/echo)"

echo
echo "--- аудит: работали все три края ---"

nodes=$(docker compose exec -T clickhouse clickhouse-client -q \
    "select node from waf.audit
      where uri like '/captcha-cluster%' and ts > toDateTime($started)
      group by node order by node" 2>/dev/null | tr -d '\r' | tr '\n' ' ')

for n in edge-01 edge-02 edge-03; do
    case " $nodes " in
        *" $n "*) ok "в аудите есть записи с $n" ;;
        *) bad "в аудите нет записей с $n (есть: $nodes)" ;;
    esac
done

echo

if [ "$fail" -ne 0 ]; then
    echo "провалено: $fail"
    exit 1
fi

echo "все проверки прошли"
