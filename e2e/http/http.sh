#!/bin/sh
# Директивы docs/directives/http.md: то, что видно клиенту и в Redis.
#
#     docker compose exec -T nginx-1 sh /t/http/http.sh
#
# Превью и store.archive в записи -- tests/http/audit.sh (nats-box).
# nginx -t -- tests/http/conf.sh и nginx/tests/unit.

set -u

BASE=http://127.0.0.1:8080
NODE=edge-01
SEARCH=${SEARCH:-http://search:8091}
SQLI="id=1%27+or+1%3D1--"
SECRET=s3cret

pass=0
fail=0
skip=0

ok() {
    pass=$((pass + 1))
    printf 'ok   %-52s %s\n' "$1" "$2"
}

bad() {
    fail=$((fail + 1))
    printf 'FAIL %-52s %s\n' "$1" "$2"
}

skip() {
    skip=$((skip + 1))
    printf 'skip %-52s %s\n' "$1" "$2"
}

say() { printf '%s\n' "$*"; }

bytes() {
    head -c "$1" /dev/zero | tr '\0' "${2:-a}"
}

# url файл [curl...]  -- один запрос: код и X-WAF-Debug
hit() {
    _url=$1
    _file=$2
    shift 2
    _hdr=/tmp/waf-http-hdr

    if [ "$_file" = "-" ]; then
        _code=$(curl -s -o /dev/null -D "$_hdr" -w '%{http_code}' \
                     -X POST -H 'content-type: application/json' \
                     --data-binary @- "$@" "$_url")
    elif [ -n "$_file" ]; then
        _code=$(curl -s -o /dev/null -D "$_hdr" -w '%{http_code}' \
                     -X POST -H 'content-type: application/json' \
                     --data-binary "@$_file" "$@" "$_url")
    else
        _code=$(curl -s -o /dev/null -D "$_hdr" -w '%{http_code}' \
                     "$@" "$_url")
    fi

    _debug=$(tr -d '\r' < "$_hdr" | grep -i '^x-waf-debug:' | cut -d' ' -f2-)
}

eq_code() {
    if [ "$_code" = "$1" ]; then
        ok "$2" "$_code"
    else
        bad "$2" "$_code, ожидался $1"
    fi
}

# объект (body|headers|args) ожидаемый_локатор имя
has_loc() {
    case $_debug in
    *$1=$2*) ok "$3" "$(printf '%s' "$_debug" | tr ' ' '\n' | grep "^$1=")" ;;
    *)       bad "$3" "нет $1=$2 в: $_debug" ;;
    esac
}

no_loc() {
    case $_debug in
    *$1=*) bad "$2" "$_debug" ;;
    *)     ok  "$2" "$1= нет" ;;
    esac
}

loc_n() {
    printf '%s' "$_debug" | tr ' ' '\n' | sed -n "s/^$1=hot:redis\\///p" | head -1
}

rid_of() {
    printf '%s' "$_debug" | tr ' ' '\n' | sed -n 's/^rid=//p' | head -1
}

# Ключ обменника этого запроса. Не KEYS *: агент успевает снять ключ,
# пока обходим всю базу.
store_key() {
    _rid=$(rid_of)
    case $1 in
        hdr)  printf '%s:%s:req:hdr' "$NODE" "$_rid" ;;
        arg)  printf '%s:%s:req:arg' "$NODE" "$_rid" ;;
        body) printf '%s:%s:req'     "$NODE" "$_rid" ;;
    esac
}

le() {
    n=$1; max=$2; name=$3
    if [ -z "$n" ]; then
        bad "$name" "локатор пуст: $_debug"
    elif [ "$n" -le "$max" ]; then
        ok "$name" "$n <= $max"
    else
        bad "$name" "$n > $max"
    fi
}

eq_n() {
    if [ "$1" = "$2" ]; then
        ok "$3" "$1"
    else
        bad "$3" "$1, ожидалось $2"
    fi
}

dbsize() {
    printf 'DBSIZE\r\nQUIT\r\n' \
        | curl -s --max-time 2 telnet://redis:6379 2>/dev/null \
        | tr -d '\r' | sed -n 's/^://p' | head -1
}

redis_get() {
    printf 'GET %s\r\nQUIT\r\n' "$1" \
        | curl -s --max-time 2 telnet://redis:6379 2>/dev/null \
        | tr -d '\r' | awk 'BEGIN { p=0 } /^\$-1/ { exit } /^\$/ { p=1; next } p==1 { print; exit }'
}

ttl_of() {
    printf 'TTL %s\r\nQUIT\r\n' "$1" \
        | curl -s --max-time 2 telnet://redis:6379 2>/dev/null \
        | tr -d '\r' | sed -n 's/^://p' | head -1
}

# Сквозной идентификатор запроса. По нему запись ищут и оператор, и карточка:
# rid -- номер слота ожидания, он живёт один запрос и за пределами error_log
# ничего не адресует.
ray_of() {
    printf '%s' "$_debug" | tr ' ' '\n' | sed -n 's/^ray=//p' | head -1
}

# Объект после переезда. Агент уносит его в S3 и снимает ключ обменника -- это
# его работа, а не потеря: содержимое читается там же, откуда его берёт
# карточка инцидента. Запись доезжает до ClickHouse не мгновенно, отсюда
# попытки.
archive_get() {
    _ray=$(ray_of)

    if [ -z "$_ray" ]; then
        return
    fi

    _try=0

    while [ "$_try" -lt 20 ]; do
        _out=$(curl -s --max-time 3 "$SEARCH/api/audit/$NODE/$_ray/$1" 2>/dev/null)

        case $_out in
        *'"available":true'*) printf '%s' "$_out"; return ;;
        esac

        _try=$((_try + 1))
        sleep 0.5
    done

    printf '%s' "$_out"
}

# Содержимое объекта там, где оно сейчас: горячий обменник до агента, архив после.
# Проверять только обменник значит проверять, кто из них успел раньше.
object_get() {
    _val=$(redis_get "$(store_key "$1")")

    if [ -n "$_val" ]; then
        printf 'hot %s' "$_val"
        return
    fi

    _val=$(archive_get "$2")

    if [ -n "$_val" ]; then
        printf 'archive %s' "$_val"
    fi
}

redis_up=$(dbsize)

bytes 400  a > /tmp/http-400
bytes 512  a > /tmp/http-512
bytes 1024 a > /tmp/http-1k
bytes 1025 a > /tmp/http-1k1
bytes 2048 a > /tmp/http-2k
bytes 200  a > /tmp/http-200

HASH=$(printf '%s' "$SECRET" | sha256sum | awk '{ print $1 }')

# =============================================================================
say '--- client_max_body_size ---'

hit "$BASE/http/client-max/" /tmp/http-512
eq_code 200 'меньше 1k проходит'

hit "$BASE/http/client-max/" /tmp/http-1k
eq_code 200 'ровно 1k проходит'

hit "$BASE/http/client-max/" /tmp/http-1k1
eq_code 413 '1k+1 — 413'

hit "$BASE/http/client-max/" /tmp/http-2k
eq_code 413 '2k JSON — 413'

got=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
           -H 'content-type: application/x-www-form-urlencoded' \
           --data-binary @/tmp/http-2k "$BASE/http/client-max/")
if [ "$got" = 413 ]; then
    ok '2k form — 413' "$got"
else
    bad '2k form — 413' "$got"
fi

hit "$BASE/http/client-max/" ""
eq_code 200 'GET без тела'

hit "$BASE/http/client-max/" /tmp/http-2k
if [ "$_code" = 413 ]; then
    case $_debug in
    *v=*) bad '413 до вердикта WAF' "$_debug" ;;
    *)    ok  '413 до вердикта WAF' 'debug нет' ;;
    esac
else
    bad '413 до вердикта WAF' "код $_code"
fi

hit "$BASE/http/limit-block/" /tmp/http-2k
eq_code 503 'при client_max 8k режет body_limit, не 413'

row=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
           -H 'content-type: application/json' \
           --data-binary @/tmp/http-2k "$BASE/http/client-max/" \
           --next -s -o /dev/null -w ' %{http_code}' "$BASE/http/client-max/")
case $row in
'413 200') ok 'keepalive после 413' "$row" ;;
*)         bad 'keepalive после 413' "$row" ;;
esac

# =============================================================================
say '--- waf_body_limit ---'

hit "$BASE/http/limit-block/" /tmp/http-400
eq_code 200 'block: тело внутри предела'
has_loc body 'hot:redis/*' 'block: тело размещено'

hit "$BASE/http/limit-block/" /tmp/http-2k
eq_code 503 'block: сверх предела — 503'
has_loc body 'unavailable:oversize/2048' 'block: причина oversize'

hit "$BASE/http/limit-trim/" /tmp/http-400
eq_code 200 'trim: тело внутри предела'
eq_n "$(loc_n body)" 400 'trim: внутри — весь объект'

hit "$BASE/http/limit-trim/" /tmp/http-2k
eq_code 200 'trim: сверх предела пропускает'
eq_n "$(loc_n body)" 512 'trim: в Redis ровно 512'

hit "$BASE/http/limit-pass/" /tmp/http-400
eq_code 200 'pass: тело внутри предела'
has_loc body 'hot:redis/*' 'pass: тело размещено'

hit "$BASE/http/limit-pass/" /tmp/http-2k
eq_code 200 'pass: сверх предела пропускает'
has_loc body 'unavailable:oversize/2048' 'pass: причина oversize'

hit "$BASE/http/limit-block/" ""
eq_code 200 'block: GET без тела'
no_loc body 'block: без тела нет body='

# =============================================================================
say '--- waf_store ---'

if [ -z "$redis_up" ]; then
    skip 'Redis недоступен' 'curl без telnet://'
else
    hit "$BASE/http/store-keys/" /tmp/http-200
    eq_code 200 'store: запрос прошёл'
    has_loc headers 'hot:redis/*' 'store: headers=hot:redis'
    has_loc body    'hot:redis/*' 'store: body=hot:redis'
    eq_n "$(loc_n body)" 200 'store: размер тела = запрос'

    hdr=$(store_key hdr)
    bod=$(store_key body)

    # Объект живёт в обменнике до агента и в архиве после него. Проверяется, что
    # он есть где-то из двух, а не что успел именно обменник: гонка с агентом --
    # это гонка теста, а не дефект контура.
    hval=$(object_get hdr headers)
    case $hval in
    hot\ *)
        ok 'store: заголовки в обменнике' "$hdr"
        ttl=$(ttl_of "$hdr")
        if [ -n "$ttl" ] && [ "$ttl" -gt 20 ]; then
            ok 'store: retain_ttl, не ttl волны' "TTL=$ttl"
        else
            bad 'store: retain_ttl, не ttl волны' "TTL=$ttl"
        fi
        case ${hval#hot } in
        '['*) ok 'store: заголовки — JSON массив' "$(printf '%s' "${hval#hot }" | head -c 40)" ;;
        *)    bad 'store: заголовки — JSON массив' "${hval#hot }" ;;
        esac
        ;;
    archive\ *)
        ok 'store: заголовки в архиве' "ray=$(ray_of)"
        ok 'store: retain_ttl, не ttl волны' 'объект уже перенесён агентом'
        case ${hval#archive } in
        *'"headers":['*) ok 'store: заголовки — JSON массив' 'headers[] в архиве' ;;
        *)               bad 'store: заголовки — JSON массив' "${hval#archive }" ;;
        esac
        ;;
    *)
        bad 'store: заголовки доступны' "ни в обменнике ($hdr), ни в архиве"
        ;;
    esac

    bval=$(object_get body body)
    case $bval in
    hot\ *)     ok 'store: тело в обменнике' "$bod" ;;
    archive\ *) ok 'store: тело в архиве' "ray=$(ray_of)" ;;
    *)          bad 'store: тело доступно' "ни в обменнике ($bod), ни в архиве" ;;
    esac

    if [ -n "$hval" ] || [ -n "$bval" ]; then
        ok 'store: объекты запроса адресуемы' "$(rid_of)"
    else
        bad 'store: объекты запроса адресуемы' "$(rid_of)"
    fi

    sleep 3
    left=$(redis_get "$hdr")
    ttl=$(ttl_of "$hdr")
    if [ -z "$left" ]; then
        ok 'store: агент снял ключи' 'нет'
    elif [ -n "$ttl" ] && [ "$ttl" -gt 20 ]; then
        ok 'store: агент ещё забирает (retain_ttl)' "TTL=$ttl"
    else
        bad 'store: агент снял или удерживает ключи' "TTL=$ttl"
    fi

    hit "$BASE/http/limit-block/" /tmp/http-400
    hdr=$(store_key hdr)
    if [ -z "$(redis_get "$hdr")" ]; then
        ok 'store: без archive ключ снят после вердикта' 'нет'
    else
        bad 'store: без archive ключ снят после вердикта' "$hdr"
    fi
fi

# =============================================================================
say '--- waf_archive (клиент / обменник) ---'

hit "$BASE/http/archive-sized/?q=hello" /tmp/http-2k
eq_code 200 'archive sized: запрос прошёл'
eq_n "$(loc_n body)" 256 'archive sized: put = 256, не весь 2k'
has_loc headers 'hot:redis/*' 'archive sized: заголовки есть'
has_loc args    'hot:redis/*' 'archive sized: args есть'

hit "$BASE/http/archive-whole/" /tmp/http-200
eq_code 200 'archive whole: POST'
eq_n "$(loc_n body)" 200 'archive whole: тело целиком'

hit "$BASE/http/archive-whole/?q=hello-world" ""
eq_code 200 'archive whole: GET с query'
has_loc args 'hot:redis/*' 'archive whole: args с query'
n=$(loc_n args)
if [ -n "$n" ] && [ "$n" -ge 13 ]; then
    ok 'archive whole: args не обрезаны' "$n"
else
    bad 'archive whole: args не обрезаны' "$_debug"
fi

hit "$BASE/http/archive-whole/" ""
eq_code 200 'archive whole: GET без тела'
has_loc headers 'hot:redis/*' 'archive whole: заголовки на GET'
no_loc body 'archive whole: без тела нет body='

hit "$BASE/http/archive-no-hdr/" /tmp/http-200
eq_code 200 'archive headers=none'
no_loc headers 'archive headers=none: headers= нет'
has_loc body 'hot:redis/*' 'archive headers=none: тело есть'

# =============================================================================
say '--- waf_capture ---'

hit "$BASE/http/capture-limit/?$(bytes 80 y)" /tmp/http-2k \
    -H 'x-pad: '"$(bytes 80 z)"
eq_code 200 'capture limit: запрос прошёл'
le "$(loc_n body)"    256 'capture: тело ≤ 256'
le "$(loc_n args)"     64 'capture: args ≤ 64'
le "$(loc_n headers)" 128 'capture: headers ≤ 128'

hit "$BASE/http/capture-whole/" /tmp/http-200
eq_code 200 'capture whole: запрос прошёл'
eq_n "$(loc_n body)" 200 'capture whole: тело целиком'

hit "$BASE/http/capture-off/" /tmp/http-200
eq_code 200 'capture off: превью/архив сами снимают'
has_loc body 'hot:redis/*' 'capture off: архив всё равно кладёт тело'

if [ -z "$redis_up" ]; then
    skip 'capture mask/deny: Redis недоступен' ''
else
    hit "$BASE/http/capture-mask-hdr/" "" \
        -H "x-token: $SECRET" -H "x-key: $SECRET" -H 'x-plain: visible'
    eq_code 200 'capture mask headers: запрос'
    hdr=$(store_key hdr)
    val=$(object_get hdr headers)
    case $val in
    *"\"x-token\",\"$HASH\""*|*"\"X-Token\",\"$HASH\""*|*"\"x-token\", \"$HASH\""*)
        ok 'capture mask: x-token = sha256' "$HASH" ;;
    *)
        case $val in
        *"$HASH"*) ok 'capture mask: x-token = sha256' 'хеш в блобе' ;;
        *)         bad 'capture mask: x-token = sha256' "$val" ;;
        esac ;;
    esac
    case $val in
    *s3cret*) bad 'capture mask: секрет не в обменнике' "$val" ;;
    *)        ok  'capture mask: секрет не в обменнике' 'нет' ;;
    esac
    case $val in
    *x-plain*|*X-Plain*) ok 'capture mask: имя без mask как есть' 'x-plain' ;;
    *)                   bad 'capture mask: имя без mask как есть' "$val" ;;
    esac

    hit "$BASE/http/capture-mask-args/?id=1&token=$SECRET&q=ok" ""
    eq_code 200 'capture mask args: запрос'
    arg=$(store_key arg)
    val=$(object_get arg args)
    case $val in
    *"token=$HASH"*) ok 'capture mask: token=sha256' "$HASH" ;;
    *)               bad 'capture mask: token=sha256' "$val" ;;
    esac
    case $val in
    *s3cret*) bad 'capture mask args: секрет не в обменнике' "$val" ;;
    *)        ok  'capture mask args: секрет не в обменнике' 'нет' ;;
    esac

    hit "$BASE/http/capture-deny-hdr/" "" \
        -H 'x-internal: hidden' -H 'x-hidden: also' -H 'x-keep: yes'
    eq_code 200 'capture deny headers: запрос'
    hdr=$(store_key hdr)
    val=$(object_get hdr headers)
    case $val in
    *x-internal*|*X-Internal*|*x-hidden*|*X-Hidden*)
        bad 'capture deny: запрещённых нет в обменнике' "$val" ;;
    *)
        ok  'capture deny: запрещённых нет в обменнике' 'нет' ;;
    esac
    case $val in
    *x-keep*|*X-Keep*) ok 'capture deny: остальные на месте' 'x-keep' ;;
    *)                 bad 'capture deny: остальные на месте' "$val" ;;
    esac

    hit "$BASE/http/capture-deny-args/?id=1&session=abc&sid=def&q=ok" ""
    eq_code 200 'capture deny args: запрос'
    arg=$(store_key arg)
    val=$(object_get arg args)
    case $val in
    *session=*|*sid=*) bad 'capture deny args: session/sid нет' "$val" ;;
    *)                 ok  'capture deny args: session/sid нет' "$val" ;;
    esac
    case $val in
    *id=1*) ok 'capture deny args: id остался' "$val" ;;
    *)      bad 'capture deny args: id остался' "$val" ;;
    esac
fi

# =============================================================================
say '--- взаимодействия: max(preview, archive, capture) ---'

hit "$BASE/http/max-three/" /tmp/http-2k
eq_code 200 'max-three: запрос прошёл'
eq_n "$(loc_n body)" 256 'max-three: put = max(256,64,128)'

hit "$BASE/http/max-three-meta/" "" \
    -H "x-pad: $(bytes 180 p)"
eq_code 200 'max-three headers: запрос прошёл'
n=$(loc_n headers)
if [ -n "$n" ] && [ "$n" -gt 64 ] && [ "$n" -le 256 ]; then
    ok 'max-three headers: put > capture и ≤ archive' "$n"
else
    bad 'max-three headers: put > capture и ≤ archive' "$_debug"
fi

# =============================================================================
say ''
say "итог: $pass ok, $fail fail, $skip skip"
say 'превью и archive в записи: docker compose exec -T nats-box sh /t/http/audit.sh'

exit $fail
