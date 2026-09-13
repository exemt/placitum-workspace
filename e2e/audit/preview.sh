#!/bin/sh
#
# Превью запроса в записи аудита: заголовки, параметры, тело.
# Гоняется из nats-box -- из контейнера nginx шину не видно, клиента там нет:
#
#     docker compose exec -T nats-box sh /t/audit/preview.sh
#
# Маршрут /preview/ (deploy/nginx/nginx.conf) намеренно урезан до крошечных
# бюджетов: 512 байт на заголовки при потолке 96 на пару, 128 на параметры без
# потолка, 64 на тело. Две оси разведены по объектам нарочно. У заголовков видно
# потолок на пару: длинное значение приезжает помеченным огрызком, а пара с
# именем длиннее половины потолка выбрасывается целиком и попадает в счётчик. У
# параметров потолка нет, и там видно бюджет секции: пара, не влезающая в его
# остаток, не пишется вовсе. Запрещённого заголовка нет ни при каком бюджете.
#
# Там же waf_body_limit 1k: тело ради превью читается мимо обменника, и его пределы
# к превью отношения не имеют.
#
# Проверяется вся дорога: модуль собрал -> датаграмма пролезла -> агент не
# тронул -> логгер свернул пары в карту -> ClickHouse отдаёт по имени. Первое
# и последнее звенья здесь важнее середины: превью существует ради поиска, а
# поиск идёт по колонке, а не по сообщению на шине.

set -u

NATS=${NATS_URL:-nats://nats:4222}
EDGE=${EDGE:-http://nginx-1:8080}
NODE=${NODE:-edge-01}

CH=${CH_URL:-http://clickhouse:8123}
CH_USER=${CH_USER:-waf}
CH_PASS=${CH_PASS:-waf}

# Датаграмма уходит вдогонку ответу клиенту, дальше шина, батч логгера и
# вставка. До ClickHouse дольше, чем до NATS, отсюда два ожидания.
SETTLE=${SETTLE:-2}
CH_SETTLE=${CH_SETTLE:-6}

SUBJECT="waf.audit.request.$NODE"

# Маркер уникален на прогон: в теле его ищут подстрокой, и попасть на след
# прошлого запуска здесь проще всего.
MARK="prv-$(date +%s)-$$"
BODY="{\"note\":\"$MARK\"}"

# Значение в 64 байта: пара из него укладывается в потолок 96, резать её нечему.
LONGUA="0123456789012345678901234567890123456789012345678901234567890123"

# А это в потолок на пару не влезет: значение обязано приехать помеченным
# огрызком, а не пропасть и не вытеснить остальные заголовки.
HUGE=$(awk 'BEGIN { while (i++ < 600) printf "z" }')

# Имя длиннее половины потолка: обрезать его нельзя -- по огрызку имени не
# найдётся ни один запрос, -- поэтому пара выбрасывается целиком и остаётся
# только числом в счётчике.
LONGNAME=x-preview-name-that-is-long-enough-to-be-dropped-outright

# Параметр, который не влезет в остаток бюджета секции: у параметров потолка на
# пару нет, и такая пара не пишется вовсе.
LONGARG=$(awk 'BEGIN { while (i++ < 200) printf "y" }')

pass=0
fail=0

say() { printf '%s\n' "$*"; }

ok() {
    pass=$((pass + 1))
    say "ok   $1"
}

bad() {
    fail=$((fail + 1))
    say "FAIL $1: $2"
}

eq() {
    if [ "$2" = "$3" ]; then
        ok "$1"
    else
        bad "$1" "$3, ожидалось $2"
    fi
}

field() {
    printf '%s' "$record" | jq -r "$1"
}

# Запрос к ClickHouse. Значения подставляются кавычками -- строки здесь свои,
# из этого же скрипта, а не с провода.
ch() {
    curl -s --get "$CH/" \
         --data-urlencode "query=$1" \
         -H "X-ClickHouse-User: $CH_USER" \
         -H "X-ClickHouse-Key: $CH_PASS"
}

say "--- запрос на маршрут с превью ---"

code=$(printf '%s' "$BODY" \
       | curl -s -o /dev/null -w '%{http_code}' -X POST \
              -H 'content-type: application/json' \
              -H "user-agent: $LONGUA" \
               -H "x-preview-huge: $HUGE" \
               -H "$LONGNAME: dropped-with-its-name" \
               -H 'x-preview-mark: kept' \
               -H 'x-preview-secret: must-not-appear' \
               -H 'cookie: sid=must-not-appear' \
               -H 'authorization: Bearer must-not-appear' \
               --data-binary @- \
              "$EDGE/preview/?q=$MARK&empty=&dup=one&dup=two&long=$LONGARG")

eq 'вердикт клиенту' 200 "$code"

sleep "$SETTLE"

say "--- превью в записи на шине ---"

raw=$(nats --server "$NATS" stream get WAF_AUDIT --last-for="$SUBJECT" -j \
      2>/dev/null)

if [ -z "$raw" ]; then
    bad 'запись в WAF_AUDIT' "нет сообщений на $SUBJECT"
    say ''
    say "итог: $pass ok, $fail fail"
    exit 1
fi

record=$(printf '%s' "$raw" | jq -r '.data' | base64 -d)

if ! printf '%s' "$record" | jq -e . >/dev/null 2>&1; then
    bad 'запись разбирается как JSON' "$(printf '%s' "$record" | head -c 200)"
    say ''
    say "итог: $pass ok, $fail fail"
    exit 1
fi

ray=$(field '.ray')

# Пары, а не объект: свёртку повторяющихся имён делает логгер.
eq 'headers_preview -- массив пар' 'true' \
   "$(field 'if (.headers_preview | type) == "array" then "true" else "false" end')"

eq 'заголовок маршрута на месте' 'kept' \
   "$(field '.headers_preview[] | select(.[0] | ascii_downcase == "x-preview-mark") | .[1]')"

say '--- запрет сильнее того, что прислал клиент ---'

# x-preview-secret запрещён маршрутом, cookie и authorization -- встроенным
# списком. Проверяются оба источника: список маршрута к встроенному
# добавляется, а не заменяет его, и именно это свойство легко потерять.
for h in x-preview-secret cookie authorization; do
    eq "заголовка $h нет в превью" '0' \
       "$(field "[.headers_preview[] | select(.[0] | ascii_downcase == \"$h\")] | length")"
done

say '--- потолок на пару ---'

# Пара из имени и значения в 64 байта укладывается в потолок 96, поэтому
# значение едет целиком и пометки на паре нет.
eq 'значение в 64 байта доехало целиком' '64' \
   "$(field '.headers_preview[] | select(.[0] | ascii_downcase == "user-agent") | .[1] | length')"

eq 'целая пара едет двумя элементами' '2' \
   "$(field '.headers_preview[] | select(.[0] | ascii_downcase == "user-agent") | length')"

# Значение длиннее потолка -- это префикс, а не пропавшая пара: имя уложилось,
# и по нему запрос обязан находиться.
huge=$(field '.headers_preview[] | select(.[0] | ascii_downcase == "x-preview-huge") | .[1]')

eq 'значение длиннее потолка урезано' 'true' \
   "$(printf '%s' "$huge" | awk '{ print (length > 0 && length < 600) ? "true" : "false" }')"

# Третий элемент пары и есть пометка: без него читатель принял бы префикс за
# оригинал, а сравнение с ним ничего не находило бы.
eq 'урезанная пара помечена третьим элементом' '1' \
   "$(field '.headers_preview[] | select(.[0] | ascii_downcase == "x-preview-huge") | .[2]')"

# Имя длиннее половины потолка -- пара выброшена целиком, а не обрезана по
# имени: по огрызку имени не находится ни один запрос.
eq 'пара с длинным именем выброшена' '0' \
   "$(field "[.headers_preview[] | select(.[0] | ascii_downcase == \"$LONGNAME\")] | length")"

# Единственное, что остаётся от выброшенной пары: число. Перечислять такие
# имена значило бы записать ровно то, из-за чего пара и не поместилась.
eq 'выброшенная пара посчитана' '1' "$(field '.headers_preview_dropped')"

say '--- бюджеты соблюдены ---'

# У параметров потолка на пару нет, поэтому здесь работает второе правило: пара
# длиннее остатка бюджета не пишется вовсе. Обрезанная посередине пара была бы
# сломанным JSON у получателя, а получатель разбирает датаграмму целиком.
eq 'параметр длиннее остатка бюджета выпал целиком' '0' \
   "$(field '[.args_preview[] | select(.[0] == "long")] | length')"

eq 'выброшенных по имени параметров нет' 'null' \
   "$(field '.args_preview_dropped')"

# Бюджет считается по записанным байтам, поэтому сравнение -- с длиной готовой
# секции, а не с суммой длин значений.
eq 'секция заголовков в пределах 512 байт' 'true' \
   "$(field 'if (.headers_preview | tojson | length) <= 512 then "true" else "false" end')"

eq 'секция параметров в пределах 128 байт' 'true' \
   "$(field 'if (.args_preview | tojson | length) <= 128 then "true" else "false" end')"

eq 'превью тела в пределах 64 байт' 'true' \
   "$(field 'if (.body_preview | length) <= 64 then "true" else "false" end')"

say '--- параметры и тело ---'

qval=$(field '.args_preview[] | select(.[0] == "q") | .[1]')

eq 'параметр q доехал маркером целиком' "$MARK" "$qval"

# Параметр без значения -- это имя, а не отсутствие параметра.
eq 'параметр без значения -- пустая строка' '""' \
   "$(field '.args_preview[] | select(.[0] == "empty") | .[1] | tojson')"

# Тело на этом маршруте не просит ни один инспектор: превью тела здесь и есть
# единственная причина его прочитать. Проверяется именно это.
eq 'превью тела собрано без инспектора' 'true' \
   "$(field 'if ((.body_preview // "") | contains("'"$MARK"'")) then "true" else "false" end')"

say '--- тело крупнее waf_body_limit ---'

# waf_body_limit на маршруте -- 1k, тело вчетверо больше. Тело при этом никуда
# не размещается: его никто не просил, а превью читает его ради записи. Значит,
# ни локатора, ни политики waf_body_limit здесь быть не должно -- превью не
# имеет права решать судьбу запроса.
dd if=/dev/zero bs=1024 count=4 2>/dev/null | tr '\0' 'b' > /tmp/waf-preview-big

debug=$(curl -s -o /dev/null -D - -X POST -H 'content-type: text/plain' \
             --data-binary @/tmp/waf-preview-big "$EDGE/preview/" \
        | grep -i '^x-waf-debug:')

eq 'крупное тело не меняет вердикт' 'allow' \
   "$(printf '%s' "$debug" | tr ' ' '\n' | sed -n 's/^v=//p')"

eq 'локатора тела не появилось' '0' \
   "$(printf '%s' "$debug" | grep -c 'body=')"

sleep "$SETTLE"

big=$(nats --server "$NATS" stream get WAF_AUDIT --last-for="$SUBJECT" -j \
      2>/dev/null | jq -r '.data' | base64 -d)

eq 'превью крупного тела собрано' 'true' \
   "$(printf '%s' "$big" \
      | jq -r 'if ((.body_preview // "") | startswith("bbb")) then "true" else "false" end')"

eq 'и уложено в бюджет' 'true' \
   "$(printf '%s' "$big" \
      | jq -r 'if ((.body_preview // "") | length) <= 64 then "true" else "false" end')"

say '--- превью доехало до ClickHouse ---'

sleep "$CH_SETTLE"

row=$(ch "SELECT
              headers_preview['x-preview-mark']  AS mark,
              headers_preview['user-agent']      AS ua,
              args_preview['q']                  AS q,
              args_preview['dup']                AS dup,
              has(mapKeys(headers_preview), 'cookie') AS has_cookie,
              has(headers_preview_truncated, 'x-preview-huge') AS has_cut,
              headers_preview_dropped            AS dropped,
              body_preview                       AS body
          FROM waf.audit
          WHERE node = '$NODE' AND ray = '$ray' AND phase = 'request'
          LIMIT 1
          FORMAT JSONEachRow")

if [ -z "$row" ]; then
    bad 'строка в waf.audit' "ray $ray не найден"
    say ''
    say "итог: $pass ok, $fail fail"
    exit 1
fi

chf() { printf '%s' "$row" | jq -r "$1"; }

eq 'карта заголовков: имя -> значение' 'kept'  "$(chf '.mark')"
eq 'карта параметров: q'               "$qval" "$(chf '.q')"
eq 'длинное значение доехало и в базу' '64'    "$(printf '%s' "$(chf '.ua')" \
   | awk '{ print length }')"
eq 'запрещённого заголовка нет и в базе' '0'   "$(chf '.has_cookie')"

# Списком имён, а не пометкой внутри значения: пометка попала бы в поиск по
# содержимому, а ищут именно по нему.
eq 'урезанное имя названо в базе'        '1'   "$(chf '.has_cut')"
eq 'выброшенная пара посчитана и в базе' '1'   "$(chf '.dropped')"

# Повторяющееся имя логгер склеивает через ", " -- по правилу составных
# заголовков, а не выбором одного из двух.
eq 'дубль параметра склеен' 'one, two' "$(chf '.dup')"

eq 'тело в базе содержит маркер' 'true' \
   "$(printf '%s' "$row" | jq -r 'if (.body | contains("'"$MARK"'")) then "true" else "false" end')"

say '--- поиск по превью ---'

# То, ради чего колонки и заведены: найти запрос, не зная его ray.
found=$(ch "SELECT count()
            FROM waf.audit
            WHERE ray = '$ray' AND lower(body_preview) LIKE '%$(printf '%s' "$MARK" | tr 'A-Z' 'a-z')%'
            FORMAT TabSeparated")

eq 'запись находится подстрокой в теле' '1' "$(printf '%s' "$found" | tr -d '[:space:]')"

found=$(ch "SELECT count()
            FROM waf.audit
            WHERE ray = '$ray' AND headers_preview['x-preview-mark'] = 'kept'
            FORMAT TabSeparated")

eq 'запись находится по заголовку' '1' "$(printf '%s' "$found" | tr -d '[:space:]')"

say ''
say "итог: $pass ok, $fail fail"
say "запись целиком: nats --server $NATS stream get WAF_AUDIT --last-for=$SUBJECT"

exit $fail
