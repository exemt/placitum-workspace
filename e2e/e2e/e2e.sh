#!/bin/sh
# Прогон окружения deploy/: nginx с модулем, шина NATS, инспекторы ip и
# modsec и защищаемое приложение за прокси.
#
#     docker compose up -d --wait
#     docker compose exec -T nginx-1 sh /t/e2e/e2e.sh
#
# Проверяется то, что видит клиент: код ответа и диагностический заголовок.
# Внутреннее состояние модуля читается из docker compose logs nginx-1 --
# в конце скрипт печатает подсказку.
#
# Ожидаемые коды -- из профилей deploy/ip и inspectors/modsec и
# настроек deploy/nginx/nginx.conf. Дефолтный набор -- ip: частная сеть
# проходит, 203.0.113.0/24 в blocklist. CRS на /modsec* с порогом 50.

BASE=http://127.0.0.1:8080
SHADOW=http://127.0.0.1:8082
APP=$BASE/app
SQLI="$BASE/modsec/?id=1%27+or+1%3D1--"
BADIP='X-Forwarded-For: 203.0.113.10'
OKIP='X-Forwarded-For: 8.8.8.8'

fail=0

# ожидаемый_код имя url [аргументы curl...]
check() {
    want=$1; name=$2; url=$3; shift 3

    got=$(curl -s -o /dev/null -w '%{http_code}' "$@" "$url")

    if [ "$got" = "$want" ]; then
        printf 'ok   %-46s %s\n' "$name" "$got"
    else
        printf 'FAIL %-46s %s, ожидался %s\n' "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

# заголовок url [аргументы curl...]
header() {
    hdr=$1; url=$2; shift 2

    value=$(curl -s -o /dev/null -D - "$@" "$url" \
            | tr -d '\r' | grep -i "^${hdr}:" | cut -d' ' -f2-)

    echo "${value:-<нет>}"
}

# имя url заголовок [аргументы curl...]
show() {
    name=$1; url=$2; hdr=$3; shift 3

    printf '     %-46s %s\n' "$name" "$(header "$hdr" "$url" "$@")"
}

# полученное ожидаемое имя
same() {
    if [ "$1" = "$2" ]; then
        printf 'ok   %-46s %s\n' "$3" "$1"
    else
        printf 'FAIL %-46s %s, ожидался %s\n' "$3" "$1" "$2"
        fail=$((fail + 1))
    fi
}

# Коды подряд идущих запросов одной строкой: счётчик частоты проверяется
# последовательностью ответов, а не одним из них.
#
#     количество url [аргументы curl...]
codes() {
    n=$1; url=$2; shift 2
    i=0

    while [ "$i" -lt "$n" ]; do
        printf '%s ' "$(curl -s -o /dev/null -w '%{http_code}' "$@" "$url")"
        i=$((i + 1))
    done
}

# код строка_кодов
howmany() {
    printf '%s' "$2" | tr ' ' '\n' | grep -c "^$1$"
}

# ожидаемый_шаблон имя url заголовок [аргументы curl...]
match() {
    want=$1; name=$2; url=$3; hdr=$4; shift 4

    value=$(header "$hdr" "$url" "$@")

    case $value in
    $want) printf 'ok   %-46s %s\n' "$name" "$value" ;;
    *)     printf 'FAIL %-46s %s\n     ожидался %s\n' "$name" "$value" "$want"
           fail=$((fail + 1)) ;;
    esac
}

echo '--- вердикты ---'
check 200 'allow: частная сеть в allowlist'     "$BASE/"
check 403 'deny по адресу'                      "$BASE/" -H "$BADIP"
check 200 'allow публичный адрес'               "$BASE/" -H "$OKIP"
check 403 'deny профилем modsec'                "$BASE/modsec-deny/"
check 200 'allow профилем modsec'               "$BASE/modsec-allow/"
check 403 'deny по CRS'                         "$SQLI"

echo '--- счёт ---'
# 942100 даёт 5 баллов CRS -- score 50, порог маршрута 50.
check 403 'score 50 на пороге 50'               "$SQLI"
check 200 'чистый запрос ниже порога'           "$BASE/modsec/"

echo '--- режимы ---'
check 200 'passive: deny не блокирует'          "$BASE/passive/" -H "$BADIP"
check 200 'passive: CRS не блокирует'           "$BASE/modsec-passive/?id=1%27+or+1%3D1--"
check 403 'shadow: активный ip всё ещё решает'  "$BASE/shadow/" -H "$BADIP"
check 200 'ignore: на шину ничего не уходит'    "$BASE/ignored/" -H "$BADIP"
check 200 'сервер целиком в passive'            "$SHADOW/" -H "$BADIP"
check 200 'waf off'                             "$BASE/healthz" -H "$BADIP"

echo '--- локальный слой: счётчики частоты ---'
# Решение принимается на месте, до единого сообщения на шину, поэтому проверяется
# оно последовательностью кодов: /local/ объявлен rate=5r/s burst=5, то есть
# первые шесть запросов проходят (пятый всплеск плюс сам запрос), а дальше 429 из
# waf_deny_response too_many.
#
# Пауза перед прогоном обязательна: корзина стекает 5 запросов в секунду, и остаток
# от предыдущей проверки сдвинул бы границу.
sleep 2
row=$(codes 12 "$BASE/local/")
echo "     коды: $row"
same "$(howmany 200 "$(printf '%s' "$row" | cut -d' ' -f1-6)")" 6 \
     'первые шесть запросов проходят'
same "$(printf '%s' "$row" | awk '{ print $NF }')" 429 'двенадцатый отклонён'

# Наблюдающий лимит: превышение только в логе, клиент этого не видит.
sleep 2
row=$(codes 12 "$BASE/local-pass/")
echo "     коды: $row"
same "$(howmany 429 "$row")" 0 'action=pass не отклоняет'

# Счёт по волнам: маршрут стоит контуру двух сообщений на запрос (ip, crs),
# и лимит 10r/s burst=10 исчерпывается вдвое быстрее, чем при счёте запросов.
sleep 3
row=$(codes 8 "$BASE/local-waves/")
echo "     коды: $row"
same "$(printf '%s' "$row" | cut -d' ' -f1)" 200 'первый запрос проходит'
same "$(printf '%s' "$row" | awk '{ print $NF }')" 429 'волны исчерпали лимит'

echo '--- проксирование на апстрим ---'
# /app/ ведёт на backend, а не на статику: здесь проверяется, что вердикт allow
# не мешает ответу приложения дойти до клиента, а deny -- не даёт запросу
# добраться до апстрима вовсе. Коды берутся из backend/README.md.
check 200 'allow: ответ апстрима дошёл'         "$APP/echo"
check 403 'deny: до апстрима не дошло'          "$APP/echo" -H "$BADIP"
check 418 'код апстрима не подменяется'         "$APP/status/418"
check 500 'сбой апстрима не выглядит отказом'   "$APP/error"
check 302 'редирект апстрима не путается с waf' "$APP/redirect"
check 200 'cookie апстрима проходит'            "$APP/set-cookie"
check 200 'апстрим медленнее waf_deadline'      "$APP/delay/100"
check 200 'крупное тело ответа'                 "$APP/large?bytes=2000"
check 200 'потоковая отдача чанками'            "$APP/stream?chunks=3&interval_ms=10"

# Зависший апстрим -- это не зависшая инспекция: вердикт уже получен, ждёт
# proxy_read_timeout, поэтому клиент отваливается по своему -m, а не по 503.
printf '     %-46s ' 'зависший апстрим не отвечает'
curl -s -m 1 -o /dev/null "$APP/hang" && echo 'FAIL: ответил' || echo 'таймаут клиента, как и задумано'

echo '--- заголовки ответа ---'
match '*v=deny*' \
      'отказ ip в диагностике' \
      "$BASE/" X-WAF-Debug -H "$BADIP"
match '*ip=deny*' \
      'решает инспектор адреса' \
      "$BASE/" X-WAF-Debug -H "$BADIP"
match '*by=score*' \
      'отказ CRS называет порог' \
      "$SQLI" X-WAF-Debug
show 'диагностика allow'   "$BASE/"                  X-WAF-Debug
show 'диагностика passive' "$BASE/passive/"           X-WAF-Debug -H "$BADIP"
show 'диагностика ignore'  "$BASE/ignored/"           X-WAF-Debug
show 'диагностика score'   "$SQLI"                    X-WAF-Debug

echo '--- keepalive: два запроса в одном соединении ---'
curl -s -o /dev/null -w '     статусы: %{http_code} ' "$BASE/" \
     -o /dev/null -w '%{http_code}\n' "$BASE/" -H "$BADIP"

echo '--- нагрузочный прогон, 500 запросов ---'
# RSS читается из procfs: в образе nginx нет ps
rss() { awk '/^VmRSS:/ { print $2 }' "/proc/$(cat /var/run/nginx.pid)/status"; }
before=$(rss)
i=0
while [ $i -lt 500 ]; do
    curl -s -o /dev/null "$BASE/" || true
    i=$((i + 1))
done
after=$(rss)
echo "     RSS мастера до=${before}K после=${after}K"

echo ''
if [ $fail -eq 0 ]; then
    echo 'все проверки пройдены'
else
    echo "провалено проверок: $fail"
fi

echo 'построчная раскладка ответов: docker compose logs nginx-1 | grep "waf:"'

exit $fail
