#!/bin/sh
# Превью, archive в записи и связки осей. Из nats-box: шины в nginx нет.
#
#     docker compose exec -T nats-box sh /t/http/audit.sh
#
# ClickHouse не нужен: превью есть в самой датаграмме. Коды и Redis --
# tests/http/http.sh.

set -u

NATS=${NATS_URL:-nats://nats:4222}
EDGE=${EDGE:-http://nginx-1:8080}
NODE=${NODE:-edge-01}
SETTLE=${SETTLE:-2}
SUBJECT="waf.audit.request.$NODE"
SQLI="id=1%27+or+1%3D1--"
SECRET=s3cret
RUN="http-$(date +%s)-$$"

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

bytes() {
    awk -v n="$1" -v c="${2:-a}" 'BEGIN { while (i++ < n) printf "%s", c }'
}

# url [curl...] -- POST, ждём запись, проверяем маршрут
post() {
    _url=$1
    _loc=$2
    shift 2
    _code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
                 -H "x-http-run: $RUN" \
                 "$@" "$_url")
    sleep "$SETTLE"
    raw=$(nats --server "$NATS" stream get WAF_AUDIT --last-for="$SUBJECT" -j \
          2>/dev/null)
    record=$(printf '%s' "$raw" | jq -r '.data' | base64 -d 2>/dev/null)
    if ! printf '%s' "$record" | jq -e . >/dev/null 2>&1; then
        record=''
        return 1
    fi
    got=$(printf '%s' "$record" | jq -r '.route.location // empty')
    if [ -n "$_loc" ] && [ "$got" != "$_loc" ]; then
        return 1
    fi
    return 0
}

need() {
    if [ -z "$record" ]; then
        bad "$1" "нет записи WAF_AUDIT (last-for перекрыт или шина пуста)"
        return 1
    fi
    return 0
}

# =============================================================================
say "--- waf_preview: размеры и обрезка ---"

HUGE=$(bytes 80 z)
BODY=$(bytes 200 b)

if post "$EDGE/http/preview-size/?q=$RUN&page=1&long=$(bytes 160 y)" \
        /http/preview-size/ \
        -H 'content-type: text/plain' \
        -H "x-http-mark: $RUN" \
        -H "x-preview-huge: $HUGE" \
        --data-binary "$BODY"
then
    eq 'preview-size: клиенту 200' 200 "$_code"
    need 'запись preview-size' || true
    eq 'body_preview ≤ 64' true \
       "$(field 'if ((.body_preview // "") | length) <= 64 then "true" else "false" end')"
    eq 'body_preview — префикс тела' true \
       "$(field 'if ((.body_preview // "") | startswith("bbb")) then "true" else "false" end')"
    eq 'headers_preview ≤ 256' true \
       "$(field 'if ((.headers_preview | tojson | length) <= 256) then "true" else "false" end')"
    eq 'args_preview ≤ 128' true \
       "$(field 'if ((.args_preview | tojson | length) <= 128) then "true" else "false" end')"
    eq 'пара long выпала из бюджета args' 0 \
       "$(field '[.args_preview[]? | select(.[0] == "long")] | length')"
    eq 'q доехал' "$RUN" \
       "$(field '.args_preview[]? | select(.[0] == "q") | .[1]')"
    eq 'huge обрезан по item=64' true \
       "$(field '[.headers_preview[]? | select(.[0] | ascii_downcase == "x-preview-huge") | .[2]] | length > 0')"
    eq 'маркер заголовка на месте' "$RUN" \
       "$(field '.headers_preview[]? | select(.[0] | ascii_downcase == "x-http-mark") | .[1]')"
else
    bad 'запись preview-size' "location=$(printf '%s' "$record" | jq -r '.route.location // empty')"
fi

# =============================================================================
say '--- waf_preview: allow / deny ---'

if post "$EDGE/http/preview-allow-hdr/" /http/preview-allow-hdr/ \
        -H 'content-type: text/plain' \
        -H 'x-keep: yes' \
        -H 'x-other: no' \
        -H 'x-extra: no' \
        --data-binary ok
then
    eq 'allow headers: 200' 200 "$_code"
    eq 'allow: x-keep есть' 1 \
       "$(field '[.headers_preview[]? | select(.[0] | ascii_downcase == "x-keep")] | length')"
    eq 'allow: content-type есть' 1 \
       "$(field '[.headers_preview[]? | select(.[0] | ascii_downcase == "content-type")] | length')"
    eq 'allow: x-other нет' 0 \
       "$(field '[.headers_preview[]? | select(.[0] | ascii_downcase == "x-other")] | length')"
    eq 'allow: архив заголовков всё равно снят' true \
       "$(field 'if (.store.headers.size // 0) > 0 then "true" else "false" end')"
else
    bad 'запись preview-allow-hdr' 'нет'
fi

if post "$EDGE/http/preview-deny-hdr/" /http/preview-deny-hdr/ \
        -H 'content-type: text/plain' \
        -H 'x-secret: hide' \
        -H 'x-token: hide' \
        -H 'x-keep: yes' \
        --data-binary ok
then
    eq 'deny headers: 200' 200 "$_code"
    eq 'deny: x-secret нет в preview' 0 \
       "$(field '[.headers_preview[]? | select(.[0] | ascii_downcase == "x-secret")] | length')"
    eq 'deny: x-token нет в preview' 0 \
       "$(field '[.headers_preview[]? | select(.[0] | ascii_downcase == "x-token")] | length')"
    eq 'deny: x-keep есть' 1 \
       "$(field '[.headers_preview[]? | select(.[0] | ascii_downcase == "x-keep")] | length')"
    eq 'deny: архив заголовков снят' true \
       "$(field 'if (.store.headers.size // 0) > 0 then "true" else "false" end')"
else
    bad 'запись preview-deny-hdr' 'нет'
fi

if post "$EDGE/http/preview-allow-args/?id=1&page=2&token=no&other=no" \
        /http/preview-allow-args/
then
    eq 'allow args: 200' 200 "$_code"
    eq 'allow args: id есть' 1 \
       "$(field '[.args_preview[]? | select(.[0] == "id")] | length')"
    eq 'allow args: page есть' 1 \
       "$(field '[.args_preview[]? | select(.[0] == "page")] | length')"
    eq 'allow args: token нет' 0 \
       "$(field '[.args_preview[]? | select(.[0] == "token")] | length')"
    eq 'allow args: архив args снят' true \
       "$(field 'if (.store.args.size // 0) > 0 then "true" else "false" end')"
else
    bad 'запись preview-allow-args' 'нет'
fi

if post "$EDGE/http/preview-deny-args/?id=1&token=hide&secret=hide&q=ok" \
        /http/preview-deny-args/
then
    eq 'deny args: 200' 200 "$_code"
    eq 'deny args: token нет' 0 \
       "$(field '[.args_preview[]? | select(.[0] == "token")] | length')"
    eq 'deny args: secret нет' 0 \
       "$(field '[.args_preview[]? | select(.[0] == "secret")] | length')"
    eq 'deny args: id есть' 1 \
       "$(field '[.args_preview[]? | select(.[0] == "id")] | length')"
    eq 'deny args: архив args снят' true \
       "$(field 'if (.store.args.size // 0) > 0 then "true" else "false" end')"
else
    bad 'запись preview-deny-args' 'нет'
fi

if post "$EDGE/http/preview-allow-deny/" /http/preview-allow-deny/ \
        -H 'x-keep: yes' -H 'x-secret: hide' -H 'x-other: no' \
        --data-binary ok
then
    eq 'allow+deny: x-keep есть' 1 \
       "$(field '[.headers_preview[]? | select(.[0] | ascii_downcase == "x-keep")] | length')"
    eq 'allow+deny: deny сильнее allow' 0 \
       "$(field '[.headers_preview[]? | select(.[0] | ascii_downcase == "x-secret")] | length')"
    eq 'allow+deny: вне allow нет' 0 \
       "$(field '[.headers_preview[]? | select(.[0] | ascii_downcase == "x-other")] | length')"
else
    bad 'запись preview-allow-deny' 'нет'
fi

# =============================================================================
say '--- waf_archive: записи и when= ---'

if post "$EDGE/http/archive-sized/?q=hello" /http/archive-sized/ \
        -H 'content-type: text/plain' \
        --data-binary "$(bytes 800 a)"
then
    eq 'archive sized: 200' 200 "$_code"
    eq 'archive sized: ttl тела 1h' 3600 "$(field '.store.archive.body.ttl // empty')"
    eq 'archive sized: ttl headers 1h' 3600 "$(field '.store.archive.headers.ttl // empty')"
    eq 'archive sized: ttl args 1h' 3600 "$(field '.store.archive.args.ttl // empty')"
    eq 'archive sized: limit тела 256' 256 "$(field '.store.archive.body.limit // empty')"
    eq 'archive sized: size тела ≤ 256' true \
       "$(field 'if ((.store.body.size // 0) <= 256) then "true" else "false" end')"
else
    bad 'запись archive-sized' 'нет'
fi

if post "$EDGE/http/archive-whole/" /http/archive-whole/ \
        -H 'content-type: text/plain' \
        --data-binary "$(bytes 200 a)"
then
    eq 'archive whole: 200' 200 "$_code"
    eq 'archive whole: ttl тела' 3600 "$(field '.store.archive.body.ttl // empty')"
    eq 'archive whole: без limit — весь объект' null \
       "$(field '.store.archive.body.limit // "null"')"
    eq 'archive whole: тело 200' 200 "$(field '.store.body.size // 0 | tostring')"
else
    bad 'запись archive-whole' 'нет'
fi

if post "$EDGE/http/archive-no-hdr/" /http/archive-no-hdr/ \
        -H 'content-type: text/plain' \
        --data-binary "$(bytes 80 a)"
then
    eq 'archive none headers: ttl headers нет' null \
       "$(field '.store.archive.headers // "null"')"
    eq 'archive none headers: ttl тела есть' 3600 \
       "$(field '.store.archive.body.ttl // empty')"
else
    bad 'запись archive-no-hdr' 'нет'
fi

if post "$EDGE/http/archive-when-deny/" /http/archive-when-deny/ \
        -H 'content-type: application/json' \
        --data-binary '{"ok":true}'
then
    eq 'when=deny на allow: клиенту 200' 200 "$_code"
    eq 'when=deny на allow: archive.body нет' null \
       "$(field '.store.archive.body // "null"')"
else
    bad 'запись archive-when-deny allow' 'нет'
fi

if post "$EDGE/http/archive-when-deny/" /http/archive-when-deny/ \
        -H 'content-type: application/x-www-form-urlencoded' \
        --data-binary "$SQLI"
then
    eq 'when=deny на deny: клиенту 403' 403 "$_code"
    eq 'when=deny на deny: archive.body 1h' 3600 \
       "$(field '.store.archive.body.ttl // empty')"
else
    bad 'запись archive-when-deny deny' "code=$_code"
fi

if post "$EDGE/http/archive-when-allow/" /http/archive-when-allow/ \
        -H 'content-type: application/json' \
        --data-binary '{"ok":true}'
then
    eq 'when=allow на allow: archive.body 1h' 3600 \
       "$(field '.store.archive.body.ttl // empty')"
else
    bad 'запись archive-when-allow allow' 'нет'
fi

if post "$EDGE/http/archive-when-allow/" /http/archive-when-allow/ \
        -H 'content-type: application/x-www-form-urlencoded' \
        --data-binary "$SQLI"
then
    eq 'when=allow на deny: клиенту 403' 403 "$_code"
    eq 'when=allow на deny: archive.body нет' null \
       "$(field '.store.archive.body // "null"')"
else
    bad 'запись archive-when-allow deny' "code=$_code"
fi

# =============================================================================
say '--- waf_capture ↔ preview ---'

if post "$EDGE/http/capture-mask-hdr/" /http/capture-mask-hdr/ \
        -H "x-token: $SECRET" -H 'x-plain: visible' \
        --data-binary ok
then
    eq 'mask hdr: preview видит оригинал' "$SECRET" \
       "$(field '.headers_preview[]? | select(.[0] | ascii_downcase == "x-token") | .[1]')"
    eq 'mask hdr: x-plain в preview' visible \
       "$(field '.headers_preview[]? | select(.[0] | ascii_downcase == "x-plain") | .[1]')"
else
    bad 'запись capture-mask-hdr' 'нет'
fi

if post "$EDGE/http/capture-mask-args/?token=$SECRET&q=ok" \
        /http/capture-mask-args/
then
    eq 'mask args: preview видит оригинал' "$SECRET" \
       "$(field '.args_preview[]? | select(.[0] == "token") | .[1]')"
else
    bad 'запись capture-mask-args' 'нет'
fi

if post "$EDGE/http/capture-deny-hdr/" /http/capture-deny-hdr/ \
        -H 'x-internal: hidden' -H 'x-keep: yes' \
        --data-binary ok
then
    eq 'deny hdr: preview всё равно видит' hidden \
       "$(field '.headers_preview[]? | select(.[0] | ascii_downcase == "x-internal") | .[1]')"
    eq 'deny hdr: x-keep в preview' yes \
       "$(field '.headers_preview[]? | select(.[0] | ascii_downcase == "x-keep") | .[1]')"
else
    bad 'запись capture-deny-hdr' 'нет'
fi

if post "$EDGE/http/capture-deny-args/?session=abc&id=1" \
        /http/capture-deny-args/
then
    eq 'deny args: preview видит session' abc \
       "$(field '.args_preview[]? | select(.[0] == "session") | .[1]')"
    eq 'deny args: preview видит id' 1 \
       "$(field '.args_preview[]? | select(.[0] == "id") | .[1]')"
else
    bad 'запись capture-deny-args' 'нет'
fi

if post "$EDGE/http/capture-off/" /http/capture-off/ \
        -H "x-http-mark: $RUN" \
        -H 'content-type: text/plain' \
        --data-binary "off-$RUN"
then
    eq 'capture off: preview headers собрано' "$RUN" \
       "$(field '.headers_preview[]? | select(.[0] | ascii_downcase == "x-http-mark") | .[1]')"
    eq 'capture off: preview body собрано' true \
       "$(field 'if ((.body_preview // "") | startswith("off-")) then "true" else "false" end')"
    eq 'capture off: archive тела назван' 3600 \
       "$(field '.store.archive.body.ttl // empty')"
else
    bad 'запись capture-off' 'нет'
fi

# =============================================================================
say '--- взаимодействия: Redis max, preview из префикса, агент режет ---'

if post "$EDGE/http/max-three/" /http/max-three/ \
        -H 'content-type: text/plain' \
        --data-binary "$(bytes 800 m)"
then
    eq 'max-three: 200' 200 "$_code"
    # Размер в локаторе описывает то, что лежит по адресу, а адрес к моменту
    # чтения записи может быть уже архивным: агент переносит объект и режет его
    # по limit. Потолок архива проверяется ниже, веткой по состоянию.
    eq 'max-three: put ≥ preview (size ≥ 128)' true \
       "$(field 'if (.store.body.store == "archive")
                    or ((.store.body.size // 0) >= 128)
                 then "true" else "false" end')"
    eq 'max-three: put ≤ capture 256' true \
       "$(field 'if ((.store.body.size // 0) <= 256) then "true" else "false" end')"
    eq 'max-three: preview тела ≤ 128' true \
       "$(field 'if ((.body_preview // "") | length) <= 128 then "true" else "false" end')"
    eq 'max-three: preview — префикс put' true \
       "$(field 'if ((.body_preview // "") | startswith("mmm")) then "true" else "false" end')"
    eq 'max-three: агенту назван ttl 1h' 3600 \
       "$(field '.store.archive.body.ttl // empty')"
    eq 'max-three: агенту назван limit 64' 64 \
       "$(field '.store.archive.body.limit // empty')"
    # после агента размер на S3 ≤ archive limit; пока hot — это put
    st=$(field '.store.body.store // empty')
    sz=$(field '.store.body.size // 0')
    if [ "$st" = archive ]; then
        if [ "$sz" -le 64 ]; then
            ok 'max-three: агент обрезал archive до 64'
        else
            bad 'max-three: агент обрезал archive до 64' "store=$st size=$sz"
        fi
    else
        eq 'max-three: до агента put = 256' 256 "$sz"
    fi
else
    bad 'запись max-three' 'нет'
fi

say ''
say "итог: $pass ok, $fail fail"
say "запись: nats --server $NATS stream get WAF_AUDIT --last-for=$SUBJECT"

exit $fail
