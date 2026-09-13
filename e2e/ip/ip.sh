#!/bin/sh
# Прогон инспектора адреса (inspectors/ip).
#
#     docker compose up -d --wait
#     sh tests/ip/ip.sh
#     sh tests/ip/ip-large.sh          # GeoLite2 us (~300k) + 100 запросов
#     docker compose exec -T loadgen k6 run /app/ip.js
#
# Два слоя. Probe кладёт client_ip прямо в сообщение на шину -- без nginx, и
# потому проверяет решение целиком: все профили, все виды совпадения, словарь
# исходов и просьбы соседям.
#
# HTTP идёт через модуль на juice.waf.test, где инспектор вызван на уровне
# сервера с профилем default. Профиль там один, и это не потеря: выбор профиля
# покрыт probe, а http отвечает на другой вопрос -- доезжает ли вердикт до
# клиента страницей отказа.
#
# Ожидания -- демо-дерево политики стенда (deploy/ip/policy), но живёт оно
# только до рассылки: первая же рассылка ip-профилей перекрывает
# дерево целиком. Поэтому прогон заводит недостающее сам через API контроллера
# (ensure_stand ниже) и рассылает поколение: наборы e2e_ip_*, составные наборы
# e2e-* и профили default, admin, ext, heavy, на которые ссылается nginx.conf.
#
# Заведённое остаётся: маршруты /ip-admin/, /ip-ext/, /ip-heavy/ без этих
# профилей отвечают отказом на всё -- инспектор не знает такого профиля.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

fail=0

SCOPE=${SCOPE:-31291282-a50c-4107-9164-e2ae46cd8b36}
CTRL=${CTRL:-http://127.0.0.1:8080}

# Край и виртуальный хост стенда. Синтетических маршрутов /ip* здесь больше
# нет: стенд перекроен на один juice.waf.test, а инспектор адреса вызван на
# уровне сервера (waf_inspect request ip wave=0) с профилем default. Значит,
# http-слой проверяет ровно то, чего не может probe, -- что вердикт доезжает
# до клиента через модуль, -- и делает это на одном профиле.
EDGE=${EDGE:-http://edge-01:8080}
HOST=${HOST:-juice.waf.test}

# Ответ каталога отказов blocked отдаёт 405 (params ray/addr/scope/retry).
DENY=${DENY:-405}

api() { # метод путь [тело]
    if [ $# -ge 3 ]; then
        curl -s -X "$1" "$CTRL/api/$SCOPE$2" -H 'content-type: application/json' -d "$3"
    else
        curl -s -X "$1" "$CTRL/api/$SCOPE$2"
    fi
}

# uuid сущности по имени: в ответах контроллера имя идёт рядом с uuid.
uuid_of() { # ответ имя
    printf '%s' "$1" | tr '{' '\n' | grep "\"name\":\"$2\"" \
        | sed -n 's/.*"uuid":"\([0-9a-f-]*\)".*/\1/p' | head -1
}

need() { # что uuid
    if [ -z "$2" ]; then
        echo "FAIL: не удалось завести $1"
        exit 1
    fi
}

# Сырьё: набор адресов. Недостающие адреса дописываются -- прогон не зависит
# от того, чем набор был раньше.
ensure_list() { # имя тип режим (internal|active) адреса...
    name=$1; type=$2; mode=$3; shift 3

    id=$(uuid_of "$(api GET /datasets)" "$name")

    if [ -z "$id" ]; then
        created=$(api POST /datasets "{\"name\":\"$name\",
            \"description\":\"Фикстура tests/ip\",\"kind\":\"list\",
            \"type\":\"$type\",\"mode\":\"$mode\",\"limit\":65536}")
        id=$(uuid_of "$created" "$name")
        need "набор $name" "$id"
    fi

    if [ $# -gt 0 ]; then
        have=$(api GET "/datasets/$id/addresses")

        for addr in "$@"; do
            case "$have" in
                *"\"$addr\""*) ;;
                *) api POST "/datasets/$id/addresses" \
                       "{\"address\":\"$addr\"}" > /dev/null ;;
            esac
        done
    fi

    echo "$id"
}

# Составной набор: выражение над сырьём. Тело -- всё, кроме имени.
ensure_set() { # имя тело
    id=$(uuid_of "$(api GET /ip-sets)" "$1")

    if [ -n "$id" ]; then
        api PUT "/ip-sets/$id" "{\"name\":\"$1\",$2}" > /dev/null
    else
        created=$(api POST /ip-sets "{\"name\":\"$1\",$2}")
        id=$(uuid_of "$created" "$1")
        need "составной набор $1" "$id"
    fi

    echo "$id"
}

# Ответ контроллера проверяется: PUT с битым телом отвечает 400 и телом
# {"error":...}, а прогон, который этого не замечает, зеленеет на том, что в
# базе лежало раньше. Так и было -- фикстура писала строку канала по набору
# после того, как условие у неё стало списком.
ensure_profile() { # имя тело
    id=$(uuid_of "$(api GET /ip-profiles)" "$1")

    if [ -n "$id" ]; then
        got=$(api PUT "/ip-profiles/$id" "{\"name\":\"$1\",$2}")
    else
        got=$(api POST /ip-profiles "{\"name\":\"$1\",$2}")
        id=$(uuid_of "$got" "$1")
    fi

    case "$got" in
        *'"error"'*)
            echo "фикстура: профиль $1 не записан: $got" >&2
            exit 1
            ;;
    esac

    need "профиль $1" "$id"

    echo "$id"
}

# Наборы, составные наборы и профили прогона. Идемпотентно: заведённое
# переписывается тем же содержимым, чужое не трогается.
ensure_stand() {
    private=$(ensure_list e2e_ip_private ip internal \
        10.0.0.0/8 127.0.0.0/8 192.168.0.0/16 172.16.0.0/12 ::1/128)
    blocked=$(ensure_list e2e_ip_blocked ipv4 internal 203.0.113.0/24 198.51.100.7)
    # Офис -- он же исключение из страновых наборов, поэтому в нём есть адрес
    # внутри RU: 5.8.8.1 обязан пройти там, где вся 5.8.8.0/24 закрыта.
    office=$(ensure_list e2e_ip_office ip internal \
        10.0.0.0/8 127.0.0.0/8 192.168.0.0/16 172.16.0.0/12 ::1/128 5.8.8.1/32)
    tor=$(ensure_list e2e_ip_tor ipv4 internal 185.220.101.0/24)
    us=$(ensure_list e2e_ip_us ipv4 internal 9.9.9.0/24)
    allow=$(ensure_list e2e_ip_allow ipv4 internal 10.0.0.0/8 127.0.0.0/8)
    # Живой набор: состав приезжает с keeper (waf.sets.<имя>), а не поколением.
    banned=$(ensure_list e2e_ip_banned ipv4 active)

    s_private=$(ensure_set e2e-private "\"lists\":[\"$private\"]")
    s_blocked=$(ensure_set e2e-blocked "\"lists\":[\"$blocked\"]")
    s_not_office=$(ensure_set e2e-not-office "\"lists\":[\"$office\"],\"inverse\":true")
    s_ru=$(ensure_set e2e-ru "\"countries\":[\"ru\"]")
    s_ru_ext=$(ensure_set e2e-ru-ext \
        "\"countries\":[\"ru\"],\"exclude\":{\"lists\":[\"$office\"]}")
    s_banned=$(ensure_set e2e-banned "\"lists\":[\"$banned\"]")
    s_tor=$(ensure_set e2e-tor "\"lists\":[\"$tor\"]")
    s_us=$(ensure_set e2e-us "\"lists\":[\"$us\"]")
    s_allow=$(ensure_set e2e-heavy-allow "\"lists\":[\"$allow\"]")
    # Набор, которого не называет ни один профиль: он и проверяет отсев пака.
    ensure_set e2e-unused "\"lists\":[\"$tor\"]" > /dev/null

    # Порядок правил -- порядок решения: белый раньше чёрного, живой набор
    # раньше статики, просьба соседу вердикта не выносит вовсе.
    # Условие терминальной строки -- составной набор, накопительной -- сырой
    # список, и только объявленный профилем: неназванный на ноду не поедет.
    ensure_profile default "\"description\":\"Фикстура tests/ip\",
        \"default\":\"allow\",
        \"datasets\":[\"$tor\"],
        \"rules\":[
          {\"set\":\"$s_private\",\"action\":\"allow\"},
          {\"set\":\"$s_banned\",\"action\":\"deny\",\"response\":\"blocked\"},
          {\"dataset\":\"$tor\",\"action\":\"request\",\"to\":\"captcha\",
           \"do\":\"challenge\",\"apply\":\"request\",\"code\":\"IP_GREYLIST\"},
          {\"set\":\"$s_blocked\",\"action\":\"deny\",\"response\":\"blocked\"},
          {\"set\":\"$s_ru\",\"action\":\"deny\",\"response\":\"blocked\"}],
        \"outcomes\":[
          {\"on\":\"white\",\"to\":\"captcha\",\"do\":\"note\",\"apply\":\"ip\",
           \"value\":10,\"code\":\"IP_VIEW\"}]" > /dev/null

    ensure_profile admin "\"description\":\"Фикстура tests/ip: только офис\",
        \"default\":\"allow\",
        \"rules\":[{\"set\":\"$s_not_office\",\"action\":\"deny\",
                    \"response\":\"blocked\"}]" > /dev/null

    ensure_profile ext "\"description\":\"Фикстура tests/ip: RU без офиса\",
        \"default\":\"allow\",
        \"rules\":[{\"set\":\"$s_ru_ext\",\"action\":\"deny\",
                    \"response\":\"blocked\"}]" > /dev/null

    # Словарь «где оказался адрес» целиком: список, не-список и три исхода.
    # Отдельный профиль, чтобы не мешать выводы default с проверкой словаря.
    ensure_profile e2e-words "\"description\":\"Фикстура tests/ip: словарь триггеров\",
        \"default\":\"allow\",
        \"datasets\":[\"$office\"],
        \"rules\":[
          {\"set\":\"$s_private\",\"action\":\"allow\"},
          {\"set\":\"$s_blocked\",\"action\":\"deny\",\"response\":\"blocked\"},
          {\"dataset\":\"$office\",\"not\":true,\"action\":\"request\",
           \"to\":\"captcha\",\"do\":\"challenge\",\"apply\":\"request\",
           \"code\":\"IP_NOT_OFFICE\"}],
        \"outcomes\":[
          {\"on\":\"white\",\"to\":\"modsec\",\"do\":\"skip\",\"apply\":\"request\",
           \"code\":\"IP_W\"},
          {\"on\":\"black\",\"to\":\"\",\"do\":\"mark\",\"apply\":\"request\",
           \"marker\":\"e2e-black\",\"code\":\"IP_B\"},
          {\"on\":\"none\",\"to\":\"captcha\",\"do\":\"note\",\"apply\":\"ip\",
           \"value\":5,\"code\":\"IP_N\"}]" > /dev/null

    ensure_profile heavy "\"description\":\"Фикстура tests/ip: большой список\",
        \"default\":\"allow\",
        \"rules\":[
          {\"set\":\"$s_allow\",\"action\":\"allow\"},
          {\"set\":\"$s_us\",\"action\":\"deny\",\"response\":\"blocked\"}]" > /dev/null

    api POST /ip-profiles/send '{}' > /dev/null

    # Поколение доезжает шиной и применяется не мгновенно. Ждём применения
    # пробой, а не спим наугад: первая же проверка ниже ждёт нового дерева.
    n=0
    while [ "$n" -lt 40 ]; do
        if docker compose exec -T inspector-ip ip-probe --quiet --timeout 2s                --profile default --client-ip 198.51.100.7 --expect deny
        then
            break
        fi

        n=$((n + 1))
        sleep 0.5
    done

    # Живой набор прогон дёргает шиной сам: uuid нужен и в теме, и в теле.
    LIVE_UUID=$banned
}

ensure_stand

probe() {
    want=$1
    name=$2
    ip=$3
    profile=${4:-default}

    if docker compose exec -T inspector-ip \
        ip-probe --quiet --timeout 2s --profile "$profile" --client-ip "$ip" --expect "$want"
    then
        printf 'ok   %-42s %s  %s  %s\n' "$name" "$profile" "$ip" "$want"
    else
        printf 'FAIL %-42s %s  %s  ожидался %s\n' "$name" "$profile" "$ip" "$want"
        fail=$((fail + 1))
    fi
}

# ожидаемый_код имя путь адрес
# пустой адрес — без X-Forwarded-For (из edge это адрес самого nats-box).
#
# Ходим из nats-box, а не с хоста: край опубликован не для всех, а имя edge-01
# резолвится только внутри сети компоуза. Клиента curl в образе края нет,
# поэтому wget: он в busybox есть всегда.
http() {
    want=$1
    name=$2
    path=$3
    ip=${4-}

    hdr=""
    if [ -n "$ip" ]; then
        hdr="--header=X-Forwarded-For: $ip"
    fi

    # На маршруте стоит локальный лимит (waf_local_check banned_by_counter),
    # и просьбы инспектора капче заносят сеть клиента в набор на минуту. Тогда
    # край отвечает 429 чему угодно из этой сети -- к решению фильтра это
    # отношения не имеет, но ломает проверку у того, кто гоняет прогон часто.
    # Ждём снятия того же запроса, а не постороннего адреса.
    n=0
    while :; do
        got=$(docker compose exec -T nats-box sh -c "
            wget -qO- --server-response --timeout=5 \
                 --header='Host: $HOST' ${hdr:+\"$hdr\"} \
                 '$EDGE$path' 2>&1 | awk '/^  HTTP/ { print \$2; exit }'
        " 2>/dev/null | tr -d '\r')

        if [ "$got" != 429 ] || [ "$want" = 429 ] || [ "$n" -ge 35 ]; then
            break
        fi

        n=$((n + 1))
        sleep 2
    done

    if [ "$n" -gt 0 ] && [ "$got" = "$want" ]; then
        echo "   (ждали снятия локального бана: ${n}x2s)"
    fi

    shown=$ip
    if [ -z "$shown" ]; then
        shown=-
    fi

    if [ "$got" = "$want" ]; then
        printf 'ok   %-42s %s  %s  %s\n' "$name" "$path" "$shown" "$got"
    else
        printf 'FAIL %-42s %s  %s  %s, ожидался %s\n' \
            "$name" "$path" "$shown" "$got" "$want"
        fail=$((fail + 1))
    fi
}

echo '--- probe: default ---'
probe deny  'blocklist 203.0.113.0/24'     203.0.113.10
probe deny  'blocklist точный адрес'       198.51.100.7
probe allow 'allowlist 10/8'               10.1.2.3
probe allow 'allowlist loopback'           127.0.0.1
probe deny  'ru deny'                      5.8.8.10
probe deny  'ru v6'                        2a02:6b8::10
probe allow 'en без действия'              8.8.8.8
probe allow 'неизвестный адрес'            1.2.3.4
probe allow 'частная сеть, не гео'         192.168.1.10

echo '--- probe: правило-действие (серый список) ---'
probe allow 'tor не блокируют'             185.220.101.7

# Просьба соседу едет рядом с вердиктом и от него не зависит: allow с
# действием и allow без действия -- разные ответы, и видно это только здесь.
if docker compose exec -T inspector-ip \
    ip-probe --timeout 2s --client-ip 185.220.101.7 --expect allow \
    | grep -q '"do":"challenge"'
then
    printf 'ok   %-42s %s\n' 'tor просит капчу' 'actions'
else
    printf 'FAIL %-42s %s\n' 'tor просит капчу' 'в ответе нет действия'
    fail=$((fail + 1))
fi

# Ответ инспектора целиком: вердикт плюс просьбы. Их видно только здесь --
# probe печатает ответ, а модуль до клиента их не доносит.
reply() { # имя адрес профиль образец
    if docker compose exec -T inspector-ip \
        ip-probe --timeout 2s --profile "$3" --client-ip "$2" \
        | grep -q "$4"
    then
        printf 'ok   %-42s %s  %s\n' "$1" "$3" "$2"
    else
        printf 'FAIL %-42s %s  %s  нет %s\n' "$1" "$3" "$2" "$4"
        fail=$((fail + 1))
    fi
}

# ожидаемое_отсутствие: тот же ответ, но образца в нём быть не должно.
no_reply() { # имя адрес профиль образец
    if docker compose exec -T inspector-ip \
        ip-probe --timeout 2s --profile "$3" --client-ip "$2" \
        | grep -q "$4"
    then
        printf 'FAIL %-42s %s  %s  лишнее %s\n' "$1" "$3" "$2" "$4"
        fail=$((fail + 1))
    else
        printf 'ok   %-42s %s  %s\n' "$1" "$3" "$2"
    fi
}

echo '--- probe: словарь «где оказался адрес» ---'
# Условие накопительной строки -- сырой список, и отрицание работает по нему.
probe allow 'не в списке: просьба есть'    8.8.8.8      e2e-words
reply 'не в офисе -> капча'                8.8.8.8      e2e-words '"code":"IP_NOT_OFFICE"'
no_reply 'в офисе -> просьбы нет'          10.1.2.3     e2e-words 'IP_NOT_OFFICE'

# Три исхода: белый, чёрный и «ни в одних». Слова разные -- и дёргаются разные.
reply 'белый список -> skip modsec'        10.1.2.3     e2e-words '"code":"IP_W"'
reply 'чёрный список -> метка'             203.0.113.10 e2e-words '"marker":"e2e-black"'
reply 'ни в одних -> note капче'           8.8.8.8      e2e-words '"code":"IP_N"'

# «Иначе» дёргает только on: none. Белый на прохожем молчит -- это и есть
# разница между «пропустили правилом» и «не совпало ничего».
no_reply 'прохожий -- не белый список'     8.8.8.8      e2e-words 'IP_W'
no_reply 'белый -- не «ни в одних»'        10.1.2.3     e2e-words 'IP_N'

echo '--- probe: admin (inverse) ---'
probe allow 'офис проходит'                10.1.2.3     admin
probe deny  'снаружи офиса'                8.8.8.8      admin

echo '--- probe: ext (ru minus office) ---'
probe deny  'ru без исключения'            5.8.8.10     ext
probe allow 'офис вычтен из ru'            5.8.8.1      ext
probe allow 'не ru'                        8.8.8.8      ext

# Живой набор: состав приезжает с keeper, а не поколением (docs/keeper.md).
# До снапшота правило не совпадает -- непрогретый список не имеет права
# закрыть маршрут. Пишем через событие с ответом: keeper кладёт запись на
# обменник, издаёт дельту, и зеркало инспектора применяет её за миллисекунды.
echo '--- probe: живой набор ---'
LIVE_SET=e2e_ip_banned
LIVE_IP=192.0.2.55

event() {
    docker compose exec -T nats-box nats --server nats://nats:4222 req         "waf.sets.$LIVE_SET.event" "$1" --raw 2>/dev/null
}

# command -- встроенная команда оболочки, а не файл: без sh -c docker её не
# найдёт и живой набор пропускался всегда.
if docker compose exec -T nats-box sh -c 'command -v nats' >/dev/null 2>&1; then
    probe allow 'до записи — промах'        "$LIVE_IP"

    reply=$(event "{\"v\":3,\"op\":\"add\",\"value\":\"$LIVE_IP\",\"ttl\":60,\"origin\":\"e2e\",\"reason\":\"E2E\"}")
    case "$reply" in
        *'"ok":true'*) echo "ok   keeper принял add" ;;
        *) echo "FAIL keeper отверг add: $reply"; fail=1 ;;
    esac
    sleep 1
    probe deny  'дельта add закрыла'        "$LIVE_IP"

    event "{\"v\":3,\"op\":\"remove\",\"value\":\"$LIVE_IP\",\"origin\":\"e2e\"}" >/dev/null
    sleep 1
    probe allow 'дельта remove сняла'       "$LIVE_IP"

    # Запись со сроком: истечение приходит дельтой от keeper, а до неё
    # истёкшее и так промах у зеркала.
    # Срок с запасом на docker exec: probe сам стоит около секунды.
    event "{\"v\":3,\"op\":\"add\",\"value\":\"$LIVE_IP\",\"ttl\":6,\"origin\":\"e2e\",\"reason\":\"E2E_TTL\"}" >/dev/null
    sleep 1
    probe deny  'запись с ttl действует'    "$LIVE_IP"
    sleep 7
    probe allow 'ttl истёк сам'             "$LIVE_IP"
else
    echo 'skip живой набор: в nats-box нет клиента nats'
fi

echo '--- probe: нет профиля ---'
probe deny  'неизвестный тег'              1.2.3.4      no-such


# Профиль на маршруте один -- default: выбор профиля целиком покрыт probe
# выше, а здесь проверяется другое -- что вердикт доезжает до клиента.
echo '--- http: вердикт через модуль ---'
http "$DENY" 'blocklist /24'               /  203.0.113.10
http "$DENY" 'blocklist точный адрес'      /  198.51.100.7
http "$DENY" 'ru geo'                      /  5.8.8.10
http "$DENY" 'ru v6'                       /  2a02:6b8::10
http 200     'allowlist 10/8'              /  10.1.2.3
http 200     'en без действия'             /  8.8.8.8
http 200     'неизвестный адрес'           /  1.2.3.4

# Серый список вердикта не выносит: строка канала только просит капчу, а
# решает капча по своему профилю. Клиент этого не замечает.
#
# Адрес берётся свежий на каждый прогон: просьба поднимает счётчик капчи по
# оси ip, и повторные запуски подряд загоняли один и тот же адрес за порог --
# приходил 429 от локального слоя, к инспектору адреса отношения не имеющий.
http 200     'tor не блокируют'            /  "185.220.101.$(( ($$ % 200) + 20 ))"

echo '--- контроллер: счёта у фильтра нет ---'
# Вердикт у инспектора один из двух. Профиль, который просит счёт, не должен
# сохраняться вовсе -- иначе панель предлагала бы то, чего он не выносит.
refuses() { # имя тело
    got=$(api POST /ip-profiles "{\"name\":\"e2e-refuse\",$2}")

    case "$got" in
        *'"error"'*) printf 'ok   %-42s %s\n' "$1" 'отказ' ;;
        *)
            printf 'FAIL %-42s %s\n' "$1" 'принято'
            fail=$((fail + 1))
            # Прибираем за собой: принятое осталось бы в базе стенда.
            id=$(uuid_of "$got" e2e-refuse)
            [ -n "$id" ] && api DELETE "/ip-profiles/$id" > /dev/null
            ;;
    esac
}

refuses 'строка со счётом' \
    "\"default\":\"allow\",\"rules\":[{\"set\":\"$s_ru\",\"action\":\"score\",\"score\":40}]"
refuses 'иначе = счёт' '"default":"score","rules":[]'
refuses 'условие не объявлено' \
    "\"default\":\"allow\",\"datasets\":[],\"rules\":[{\"dataset\":\"$tor\",
      \"action\":\"request\",\"to\":\"captcha\",\"do\":\"challenge\",\"apply\":\"request\"}]"

echo '--- пак: едет только названное ---'
# Набор, которого не называет ни одна строка, на ноду ехать не должен: тела
# списков -- самое тяжёлое в паке, и платить за них незачем.
sets_on_node=$(docker compose exec -T inspector-ip \
    sh -c 'cat /app/state/policy/sets.yaml' 2>/dev/null | tr -d '\r')

case "$sets_on_node" in
    *e2e-unused:*)
        printf 'FAIL %-42s %s\n' 'неназванный набор не едет' 'e2e-unused на ноде'
        fail=$((fail + 1))
        ;;
    *)
        printf 'ok   %-42s %s\n' 'неназванный набор не едет' 'e2e-unused'
        ;;
esac

case "$sets_on_node" in
    *e2e-tor:*)
        printf 'FAIL %-42s %s\n' 'набор без строк не едет' 'e2e-tor на ноде'
        fail=$((fail + 1))
        ;;
    *)
        # Набор e2e-tor остался в пространстве, но условие строки канала теперь
        # сырой список, и набором его никто не называет.
        printf 'ok   %-42s %s\n' 'набор без строк не едет' 'e2e-tor'
        ;;
esac

case "$sets_on_node" in
    *e2e-private:*) printf 'ok   %-42s %s\n' 'названный набор едет' 'e2e-private' ;;
    *)
        printf 'FAIL %-42s %s\n' 'названный набор едет' 'e2e-private потерян'
        fail=$((fail + 1))
        ;;
esac

if [ "$fail" -ne 0 ]; then
    echo "провалено: $fail"
    exit 1
fi

echo 'ok'
