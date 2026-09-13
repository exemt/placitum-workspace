#!/bin/sh
# Прогон хранилища: заголовки и тело в Redis (два ключа), не в сообщении.
#
#     docker compose up -d --wait
#     docker compose exec -T nginx-1 sh /t/body/body.sh
#
# Проверяется то, что видит клиент: код ответа и поля body= / headers=
# диагностического заголовка. Одно и то же тело с признаком "union select"
# даёт 403 и на /body/inline/, и на /body/store/: инлайн в горячем пути больше
# нет, modsec читает Redis. Доказательство размещения -- не разница
# кодов, а body=hot:redis/N и headers=hot:redis/N, и что после вердикта ключей
# не осталось.
#
#     store     -- 403, локаторы в debug
#     префикс   -- размещается ровно waf_body_limit
#     oversize  -- тела нет вовсе, исход решает второе слово waf_body_limit
#
# Инспектор правил по-прежнему читает тело из Redis на /modsec/.
#
# Ожидаемые коды выведены из CRS (942100) и настроек маршрутов /body/*
# в deploy/nginx/nginx.conf.

BASE=http://127.0.0.1:8080

# waf_node_id этого контейнера: им начинается всякий ключ, который положил
# модуль, и по нему же его ключи отделяются от чужих в общей базе стенда.
NODE=edge-01

# Признак, на который смотрит CRS 942100 (libinjection). Пробел здесь
# существенный: правило ищет SQLi в самом теле, поэтому тело едет как JSON --
# urlencode превратил бы пробел в плюс, и признак не нашёлся бы ни инлайном,
# ни из хранилища.
MARK='1 union select 1'

# Инъекция для инспектора правил: 942100 (libinjection) даёт 5 баллов на любом
# уровне паранойи, то есть score 50 -- ровно порог маршрутов /modsec*.
# Экранировано для формы urlencoded, в ARGS_POST уходит id=1' or 1=1--
SQLI="id=1%27+or+1%3D1--"

SMALL=200
MID=2000
BIG=40000

pass=0
fail=0

ok() {
    pass=$((pass + 1))
    printf 'ok   %-46s %s\n' "$1" "$2"
}

bad() {
    fail=$((fail + 1))
    printf 'FAIL %-46s %s\n' "$1" "$2"
}

# body ФАЙЛ РАЗМЕР head|tail|none
#
# Тело заданного размера, в котором признак стоит в начале, в конце или
# отсутствует. Позиция нужна для waf_body_limit ... trim: префикс тела --
# это префикс, и признак за его пределом не находится.
body() {
    file=$1
    size=$2

    head=''
    tail=''

    case $3 in
        head) head=$MARK ;;
        tail) tail=$MARK ;;
    esac

    open="{\"q\":\"$head\",\"pad\":\""
    close="\",\"z\":\"$tail\"}"

    n=$((size - ${#open} - ${#close}))
    [ "$n" -lt 1 ] && n=1

    {
        printf '%s' "$open"
        head -c "$n" /dev/zero | tr '\0' a
        printf '%s' "$close"
    } > "$file"
}

size_of() {
    wc -c < "$1" | tr -d ' '
}

# ожидаемый_код имя url файл [аргументы curl...]
check() {
    want=$1; name=$2; url=$3; file=$4; shift 4

    got=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
               -H 'content-type: application/json' \
               --data-binary "@$file" "$@" "$url")

    if [ "$got" = "$want" ]; then
        ok "$name" "$got"
    else
        bad "$name" "$got, ожидался $want"
    fi
}

# Значение X-WAF-Debug того же запроса. Отдельным запросом, а не тем же: код и
# заголовок читаются разными вызовами curl, и это осознанно -- маршруты
# идемпотентны, а разбирать заголовки при -o /dev/null иначе неудобно.
debug() {
    url=$1; file=$2; shift 2

    curl -s -o /dev/null -D - -X POST -H 'content-type: application/json' \
         --data-binary "@$file" "$@" "$url" \
        | tr -d '\r' | grep -i '^x-waf-debug:' | cut -d' ' -f2-
}

# шаблон имя url файл [аргументы curl...]
locator() {
    want=$1; name=$2; url=$3; file=$4; shift 4

    value=$(debug "$url" "$file" "$@")

    case $value in
    $want) ok "$name" "$(printf '%s' "$value" | tr ' ' '\n' | grep '^body=')" ;;
    *)     bad "$name" "нет '$want' в: $value" ;;
    esac
}

# Число ключей в Redis. Клиента в образе nginx нет, но Redis принимает
# инлайновые команды, а curl умеет telnet://. Если сборка curl без него --
# проверка пропускается, а не проваливается: это диагностика хранилища, а не
# поведение модуля.
dbsize() {
    printf 'DBSIZE\r\nQUIT\r\n' \
        | curl -s --max-time 2 telnet://redis:6379 2>/dev/null \
        | tr -d '\r' | sed -n 's/^://p' | head -1
}

# Имена ключей: тем же способом, ответ -- массив RESP. Служебные строки кадра
# начинаются с *, $, + или -, имена ключей -- с имени ноды, поэтому фильтр по
# первому символу разбирает ответ целиком.
keys() {
    printf 'KEYS *\r\nQUIT\r\n' \
        | curl -s --max-time 2 telnet://redis:6379 2>/dev/null \
        | tr -d '\r' | grep -v '^[*$+-]' | grep -v '^$' | sort
}

# Только ключи этого узла. База на стенде общая: пульс инспектора правил кладёт
# в неё свои probe:*, и считать их значило бы проверять чужую уборку. Прогон
# отвечает за то, что оставил после себя модуль.
mine() {
    keys | grep "^$NODE:"
}

ttl_of() {
    printf 'TTL %s\r\nQUIT\r\n' "$1" \
        | curl -s --max-time 2 telnet://redis:6379 2>/dev/null \
        | tr -d '\r' | sed -n 's/^://p' | head -1
}

body /tmp/small.json     "$SMALL" head
body /tmp/small-ok.json  "$SMALL" none
body /tmp/big.json       "$BIG"   head
body /tmp/mid-head.json  "$MID"   head
body /tmp/mid-tail.json  "$MID"   tail

small=$(size_of /tmp/small.json)
big=$(size_of /tmp/big.json)

store_up=$(dbsize)
keys_before=$(mine | wc -l)

echo '--- Redis: и мелкое, и крупное тело в store ---'
check 403 'признак в теле на /body/inline/'    "$BASE/body/inline/" /tmp/small.json
check 200 'тело без признака'                  "$BASE/body/inline/" /tmp/small-ok.json
locator "* body=hot:redis/$small*" 'локатор тела: store, driver, размер' \
        "$BASE/body/inline/" /tmp/small-ok.json
locator "* headers=hot:redis/*" 'локатор заголовков' \
        "$BASE/body/inline/" /tmp/small-ok.json
check 403 'признак в теле 40k'                 "$BASE/body/inline/" /tmp/big.json
locator "* body=hot:redis/$big*" 'локатор 40k' \
        "$BASE/body/inline/" /tmp/big.json

# То же тело на маршруте, который раньше отличался порогом инлайна.
check 403 'то же тело на /body/store/'         "$BASE/body/store/" /tmp/small.json
locator "* body=hot:redis/$small*" 'локатор на /body/store/' \
        "$BASE/body/store/" /tmp/small.json
locator "* headers=hot:redis/*" 'заголовки на /body/store/' \
        "$BASE/body/store/" /tmp/small.json
check 403 'тело 40k на /body/store/'           "$BASE/body/store/" /tmp/big.json

# Запрос без тела: body= нет, headers= есть -- заголовки кладутся отдельно.
value=$(curl -s -o /dev/null -D - "$BASE/body/store/" \
        | tr -d '\r' | grep -i '^x-waf-debug:' | cut -d' ' -f2-)
case $value in
*body=*) bad 'запрос без тела: body= нет' "$value" ;;
*)       ok  'запрос без тела: body= нет' 'body= отсутствует' ;;
esac
case $value in
*headers=hot:redis/*) ok  'запрос без тела: headers= есть' "$value" ;;
*)                    bad 'запрос без тела: headers= есть' "$value" ;;
esac

echo '--- предел размера тела ---'
# waf_body_limit 1k при теле 40k. Тело есть, но в контур не попадает, и по
# умолчанию это отказ: 503, как всякое "вердикта нет", -- каталог
# waf_deny_response тут не при чём, отказал контур, а не правило.
check 503 'oversize: block по умолчанию'       "$BASE/body/oversize/" /tmp/big.json
locator "* body=unavailable:oversize/$big*" 'локатор: причина и размер' \
        "$BASE/body/oversize/" /tmp/big.json

# Та же недоступность с обратной политикой: запрос идёт дальше, инспектор
# получает причину и решает по остальным признакам.
check 200 'oversize: pass пропускает'          "$BASE/body/oversize-pass/" /tmp/big.json
locator "* body=unavailable:oversize/$big*" 'причина доехала и при pass' \
        "$BASE/body/oversize-pass/" /tmp/big.json

echo '--- усечение до предела ---'
# Размещается ровно waf_body_limit, и это единственное, что здесь проверяется
# кодом ответа: положение признака в теле на исход не влияет.
#
# Тело тут -- JSON, а префикс JSON обрывается посреди строки и разбираться
# перестаёт. Движок сообщает об ошибке разбора (crs-200002), ARGS остаются
# пустыми, и 942100, которое ищет SQLi именно в ARGS, не срабатывает -- ни на
# признаке в начале тела, ни на признаке за пределом префикса. Так что усечение
# структурированного тела -- это не "проверка по префиксу", а отказ от проверки
# содержимого; сама находка об ошибке разбора проверяется на шине, в
# tests/audit/truncate.sh.
check 200 'префикс: признак внутри предела'    "$BASE/body/truncate/" /tmp/mid-head.json
check 200 'префикс: признак за пределом'       "$BASE/body/truncate/" /tmp/mid-tail.json
locator '* body=hot:redis/1024*' 'размещён ровно waf_body_limit' \
        "$BASE/body/truncate/" /tmp/mid-tail.json
locator '* body=hot:redis/1024*' 'префикс не зависит от признака' \
        "$BASE/body/truncate/" /tmp/mid-head.json

echo '--- отсечение до волн: тела не читаем вовсе ---'
# Лимит маршрута -- 1r/s без запаса: первый запрос секунды проходит и тело
# размещает, второй отвергается на месте, до единого сообщения на шину. Значит,
# до волны, которой тело нужно, дело не доходит -- и локатора в диагностике нет.
# Проверяется именно так, а не счётчиками: наружу их пока не отдаёт ничто
# (waf_status -- этап 13).
#
# Первый запрос идёт впустую нарочно: обращение, создающее счётчик, корзину не
# наполняет, и без него пара ниже зависела бы от того, остался ли счётчик от
# прошлого прогона. Секунда после него корзину опустошает.
curl -s -o /dev/null -X POST -H 'content-type: application/json' \
     --data-binary @/tmp/small.json "$BASE/body/rate/"
sleep 1

locator '* body=hot:redis/*' 'прошедший запрос: тело размещено' \
        "$BASE/body/rate/" /tmp/small.json

value=$(debug "$BASE/body/rate/" /tmp/small.json)
case $value in
*body=*) bad 'отсечённый запрос тела не читает' "$value" ;;
*)       ok  'отсечённый запрос тела не читает' 'body= отсутствует' ;;
esac

# Два запроса в одном соединении, и первый из них -- ранний ответ на запрос с
# телом. Непрочитанное тело обязано быть отброшено
# (ngx_http_discard_request_body), иначе следующий запрос того же соединения
# разбирается начиная с остатка предыдущего тела: ломается чужой запрос, а не
# этот. Ожидание -- 200 и 429: второй попадает в тот же лимит.
sleep 1
row=$(curl -s -X POST -H 'content-type: application/json' \
           --data-binary @/tmp/big.json -o /dev/null "$BASE/body/rate/" \
           -X POST -H 'content-type: application/json' \
           --data-binary @/tmp/big.json -o /dev/null "$BASE/body/rate/" \
           -w '%{http_code} ')

case $row in
'200 429 ') ok 'keepalive исправен после раннего ответа' "$row" ;;
*)          bad 'keepalive исправен после раннего ответа' "$row" ;;
esac

echo '--- инспектор правил читает тело из Redis ---'
# Здесь тело проверяется по-настоящему: инъекция уходит в ARGS_POST, а сам
# инспектор живёт в другом контейнере и читает тело по локатору.
#
# Оба тела в Redis: мелкое раньше уезжало инлайном. Один и тот же отказ
# означает, что путь через хранилище работает целиком.
printf '%s&pad=%s\n' "$SQLI" "$(head -c 100 /dev/zero | tr '\0' a)" \
    > /tmp/sqli-small.txt
printf '%s&pad=%s\n' "$SQLI" "$(head -c "$BIG" /dev/zero | tr '\0' a)" \
    > /tmp/sqli-big.txt

form() {
    want=$1; name=$2; file=$3

    got=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
               -H 'content-type: application/x-www-form-urlencoded' \
               --data-binary "@$file" "$BASE/modsec/")

    if [ "$got" = "$want" ]; then
        ok "$name" "$got"
    else
        bad "$name" "$got, ожидался $want"
    fi
}

form 403 'инъекция в инлайновом теле'          /tmp/sqli-small.txt
form 403 'инъекция в теле из Redis'            /tmp/sqli-big.txt

echo '--- хранилище после прогона ---'
keys_after=$(mine | wc -l)

if [ -z "$store_up" ]; then
    echo '     Redis недоступен (curl без telnet://), проверка пропущена'
elif [ "$keys_before" = "$keys_after" ]; then
    ok 'ключей не осталось' "ключей узла $keys_after"
else
    bad 'ключей не осталось' "было $keys_before, стало $keys_after"
fi

echo '--- архивация: удержание, перенос, retain_ttl ---'
# На /body/archive/ модуль ключи не удаляет: владение перешло агенту. Дальше
# судьба двух объектов расходится, и обе ветви здесь и проверяются.
#
# Тело и заголовки: бакеты waf-bodies / waf-headers у агента настроены,
# объекты уезжают в MinIO, ключи агент снимает сам -- к концу проверки их нет.
#
# Проверка идёт после подсчёта ключей выше нарочно: архивация -- отдельное
# утверждение. Подмена локаторов в самой записи -- в tests/audit.
if [ -z "$store_up" ]; then
    echo '     Redis недоступен (curl без telnet://), проверка пропущена'
else
    before=$(mine)

    check 403 'признак в теле на /body/archive/' "$BASE/body/archive/" \
          /tmp/small.json

    # Датаграмма уходит агенту вдогонку ответу: секунда на GET, PUT, PUB и DEL.
    sleep 1

    kept=$(printf '%s\n%s\n' "$before" "$(mine)" | sort | uniq -u)

    if printf '%s\n' "$kept" | grep -q ':req:hdr'; then
        bad 'заголовки уехали в архив: ключ снят агентом' 'ключ :hdr на месте'
    else
        ok 'заголовки уехали в архив: ключ снят агентом' 'ключа :hdr нет'
    fi

    if printf '%s\n' "$kept" | grep -q ':req$'; then
        bad 'тело уехало в архив: ключ снят агентом' 'ключ тела на месте'
    else
        ok 'тело уехало в архив: ключ снят агентом' 'ключа тела нет'
    fi
fi

echo ''
echo "итог: $pass ok, $fail fail"
echo 'размещение и удаление по строкам: docker compose logs nginx-1 | grep "waf:"'
echo 'чтение тела инспектором:          docker compose logs inspector-modsec'

exit $fail
