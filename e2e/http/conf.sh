#!/bin/sh
# nginx -t по директивам docs/directives/http.md.
# Гоняется с хоста, образ waf-nginx уже собран:
#
#     sh tests/http/conf.sh
#
# Файлы -- существующие фикстуры nginx/tests/unit. Здесь они собраны
# в один прогон: 8–10 отказов и успехов на взаимодействие директив.

set -u

IMAGE=${IMAGE:-waf-nginx}
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
UNIT=$ROOT/nginx/tests/unit

pass=0
fail=0

ok()  { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

run() {
    want=$1
    name=$2
    file=$3

    out=$(docker run --rm --entrypoint nginx \
              -v "$UNIT:/t:ro" "$IMAGE" -t -c "/t/$file" 2>&1) || true

    case $out in
    *"test is successful"*) got=ok ;;
    *)                      got=fail ;;
    esac

    if [ "$got" = "$want" ]; then
        ok "$name"
    else
        bad "$name" "$(printf '%s' "$out" | tail -n 3 | tr '\n' ' ')"
    fi
}

# --- успех: синтаксис, который должен грузиться ---
run ok 'archive: размер на объекте'          archive-object-size.conf
run ok 'preview: размер на объекте'          preview-object-size.conf
run ok 'preview: allow/deny отдельными строками' preview-allow-deny.conf
run ok 'capture: размер на объекте'          capture-object-size.conf
run ok 'capture: mask/deny отдельными строками' capture-mask-deny.conf
run ok 'обменник + три оси, put = max'          redis-max-of-three.conf
run ok 'inspect: keep=on и resume= парой'     inspect-keep-pair-ok.conf
run ok 'inspect: keep на сервере, resume в location' inspect-keep-server-location-ok.conf
run ok 'inspect: четыре слота фазы, keep на сервере' phase-frame-ok.conf
run ok 'калитка: inspect/capture/preview сняты'  gate-page-preview-none.conf
run ok 'калитка: архив снят вслед за инспекторами' gate-page-inspect-none.conf

# --- отказ: то, что nginx -t обязан отсечь ---
run fail 'body_limit > client_max'           body-limit-over-client.conf
run fail 'archive: общий limit= снят'        archive-limit-retired.conf
run fail 'archive: when=redirect снят'       archive-when-redirect.conf
run fail 'preview: размер обязателен'        preview-size-required.conf
run fail 'preview: у body нет /item'         preview-body-item.conf
run fail 'preview: бюджет выше потолка'      preview-over-limit.conf
run fail 'preview: deny= на строке размера'  preview-inline-deny.conf
run fail 'capture: размер выше потолка'      capture-over-limit.conf
run fail 'capture: mask= на строке размера'  capture-inline-mask.conf
run fail 'capture: mask у body нет'          capture-body-mask.conf
run fail 'обменник обязателен, если кладём'     store-missing.conf
run fail 'retain_ttl короче ttl'             archive-retain-ttl.conf
run fail 'сокет обязателен при waf on'       agent-socket-required.conf
run fail 'архив без сокета'                  archive-no-agent.conf
run fail 'inspect: keep=on без потребителя'   inspect-keep-no-consumer.conf
run fail 'inspect: resume= без keep=on'       inspect-resume-no-keep.conf
run fail 'inspect: keep= на фазе ответа'      inspect-keep-on-response.conf
run fail 'калитка: превью шире снятого'       gate-page-preview-kept.conf
run fail 'калитка: архив без инспекторов'     gate-page-archive-kept.conf

printf '\nитог: %s ok, %s fail\n' "$pass" "$fail"
exit "$fail"
