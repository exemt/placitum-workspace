#!/usr/bin/env bash
# e2e на стенде placitum: эталон, сброс к нему и прогон набора между сбросами.
# Схема — e2e/README.md.
#
#     e2e/e2e.sh baseline [--force]      фикстуры, затем снять эталон: стенд останавливается,
#                                        тома уходят в архивы
#     e2e/e2e.sh reset                   вернуть стенд к эталону и дождаться его поколения
#     e2e/e2e.sh run <набор> [аргументы] сброс, node <набор>/run.mjs --no-bootstrap, сброс
#     e2e/e2e.sh status                  отпечаток образов, какие эталоны есть и какой подходит
#
# Эталон привязан к отпечатку: ID образов сервисов и отрисованный compose. Сменился
# образ — нужен новый эталон: старую базу под новый код не восстанавливаем.
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ws=$(CDPATH= cd -- "$here/.." && pwd)
core=$ws/core
sources=$ws/stand/sources.local.env
project=placitum
store=$here/.baseline

envval() { sed -n "s/^$1=//p" "$core/.env" 2>/dev/null; }
panel_port=$(envval PLC_PANEL_PORT)
node_port=$(envval PLC_HTTP_PORT)
panel=http://127.0.0.1:${panel_port:-8080}

# Не состояние, а кеш: веса модели качаются долго, сброс их не трогает.
skip_volumes="vlai-checkpoint"

# tar из alpine: busybox при распаковке от root возвращает владельцев по номерам —
# без этого postgres и clickhouse не встанут на своих каталогах.
tar_image=alpine

say() { printf '\n== %s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }

# Контур из core и надстройка e2e (витрина app): эталон снимается с ней вместе,
# иначе отпечаток не совпадёт с тем, что поднято.
compose() {
    docker compose -p "$project" --env-file "$core/.env" --env-file "$sources" \
        -f "$core/compose/waf.yml" -f "$here/compose.yml" "$@"
}

lock() {
    mkdir -p "$store"
    exec 9> "$store/.lock"
    flock -n 9 || die "на стенде уже работает e2e.sh (замок $store/.lock)"
}

images() {
    compose config --images | sort -u | while read -r img; do
        printf '%s %s\n' "$img" "$(docker image inspect -f '{{.Id}}' "$img" 2>/dev/null || echo missing)"
    done
}

fingerprint() {
    { images; compose config; } | sha256sum | cut -c1-12
}

volumes() {
    compose config --volumes | while read -r key; do
        case " $skip_volumes " in *" $key "*) continue ;; esac
        printf '%s\n' "$key"
    done
}

# Поколение, на котором сошлись все ноды; пусто — не сошлись.
generation() {
    curl -fsS "$panel/api/fleet" | jq -r '
        (.agents // []) as $a
        | if ($a | length) > 0 and all($a[]; .apply == "ok")
          then ($a | map(.health.config_hash) | unique | if length == 1 then .[0] else empty end)
          else empty end'
}

inspectors() {
    curl -fsS "$panel/api/fleet" | jq '[.inspectors[]?] | length'
}

# Ждать, пока каждый контейнер проекта станет healthy (или просто Up, если пробы у него
# нет). Своё ожидание, а не up --wait: тот сдаётся на первом unhealthy, а после рестарта
# процесс может провалить несколько проб, пока контроллер досылает поколение во
# внутренний Redis, и поправиться сам.
wait_healthy() {
    local deadline=$(( $(date +%s) + ${1:-300} )) bad
    while :; do
        bad=$(docker ps -a --filter "label=com.docker.compose.project=$project" \
            --format '{{.Names}} {{.Status}}' | grep -vE '\(healthy\)$|^[^ ]+ Up [^(]*$' || true)
        [ -z "$bad" ] && return 0
        [ "$(date +%s)" -lt "$deadline" ] || die "контейнеры не поднялись: $(printf '%s' "$bad" | tr '\n' ';')"
        sleep 3
    done
}

# Ждать, пока все ноды отчитаются поколением эталона с apply ok и инспекторов станет
# столько же, сколько было при снимке.
wait_converged() {
    local want=$1 count=$2 deadline=$(( $(date +%s) + ${3:-300} )) state
    while :; do
        state=$(curl -fsS "$panel/api/fleet" 2>/dev/null | jq -r --arg h "$want" --argjson n "$count" '
            (.agents // []) as $a
            | ([.inspectors[]?] | length) as $i
            | if ($a | length) == 0 then "нет нод"
              elif all($a[]; .health.config_hash == $h and .apply == "ok") and $i >= $n then "ok"
              else "\($a | map("\(.health.node_id): \(.apply) \(.health.config_hash // "-" | .[0:19])") | join(", ")); инспекторов \($i) из \($n)" end' 2>/dev/null) ||
            state="панель не отвечает"
        [ "$state" = ok ] && return 0
        [ "$(date +%s)" -lt "$deadline" ] || die "стенд не вернулся к эталону: $state"
        sleep 3
    done
}

# Фикстуры эталона: то, на что опираются наборы и чего нет в поставке (fixtures/stand.mjs).
fixtures() {
    say "фикстуры"
    WAF_CONTROLLER=$panel node "$here/fixtures/stand.mjs"
}

# Все каналы пространства. Их send идёт перед снимком: фикстуры правят базу, и поколение,
# изданное до них, больше не совпадает с базой. Такое поколение контроллер после сброса
# во внутренний Redis не дошлёт — край останется без поколения.
channels="rules auth captcha json action cookie counter vlai rewrite ip-profiles config agent haproxy"

publish_all() {
    say "издание всех каналов"
    local scope ch code deadline worst
    scope=$(curl -fsS "$panel/api/spaces" | jq -r '.spaces[] | select(.name == "default") | .uuid')
    for ch in $channels; do
        code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$panel/api/$scope/$ch/send" \
            -H 'content-type: application/json' -d '{}')
        [ "$code" = 200 ] || die "издание канала $ch: код $code"
    done

    # nobody — канал, у которого на стенде нет потребителя (haproxy, vlai за профилем).
    deadline=$(( $(date +%s) + 180 ))
    while :; do
        worst=$(curl -fsS "$panel/api/$scope/convergence" | jq -r '.worst')
        case "$worst" in ok | nobody) break ;; esac
        [ "$(date +%s)" -lt "$deadline" ] || die "каналы не сошлись после издания: $worst"
        sleep 3
    done
    printf 'каналы изданы и сошлись\n'
}

baseline() {
    lock
    local fp dir tmp gen count key vol
    fp=$(fingerprint)
    dir=$store/$fp

    if [ -f "$dir/meta" ] && [ "${1:-}" != --force ]; then
        say "эталон $fp уже есть"
        cat "$dir/meta"
        return 0
    fi

    say "стенд до снимка"
    wait_healthy 120
    fixtures
    publish_all
    gen=$(generation)
    [ -n "$gen" ] || die "ноды не сошлись на одном поколении — снимать нечего"
    count=$(inspectors)
    printf 'поколение %s, инспекторов %s\n' "$gen" "$count"

    say "останавливаю стенд"
    compose stop

    say "тома в архивы"
    tmp=$store/.tmp-$fp
    rm -rf "$tmp"
    mkdir -p "$tmp"
    for key in $(volumes); do
        vol=${project}_$key
        if ! docker volume inspect "$vol" >/dev/null 2>&1; then
            printf 'том %s не заведён — пропускаю\n' "$vol"
            continue
        fi
        docker run --rm -v "$vol":/v:ro -v "$tmp":/b "$tar_image" tar -C /v -cf "/b/$key.tar" .
        printf '%-28s %s\n' "$key" "$(du -h "$tmp/$key.tar" | cut -f1)"
    done

    {
        printf 'generation=%s\n' "$gen"
        printf 'inspectors=%s\n' "$count"
        printf 'taken=%s\n' "$(date -u +%FT%TZ)"
        printf 'core=%s\n' "$(git -C "$core" rev-parse --short HEAD)"
    } > "$tmp/meta"
    images > "$tmp/images"
    rm -rf "$dir"
    mv "$tmp" "$dir"

    say "поднимаю стенд"
    compose up -d
    wait_healthy 300
    wait_converged "$gen" "$count"
    printf '\nэталон %s снят\n' "$fp"
}

reset() {
    lock
    local fp dir gen count started restored healthy finished tarfile key vol
    fp=$(fingerprint)
    dir=$store/$fp
    [ -f "$dir/meta" ] || die "нет эталона под текущие образы ($fp): e2e/e2e.sh baseline"
    gen=$(sed -n 's/^generation=//p' "$dir/meta")
    count=$(sed -n 's/^inspectors=//p' "$dir/meta")
    started=$(date +%s)

    say "сношу контейнеры"
    compose down --remove-orphans

    say "тома из эталона $fp"
    for tarfile in "$dir"/*.tar; do
        key=$(basename "$tarfile" .tar)
        vol=${project}_$key
        docker volume inspect "$vol" >/dev/null 2>&1 ||
            docker volume create --label "com.docker.compose.project=$project" \
                --label "com.docker.compose.volume=$key" "$vol" >/dev/null
        docker run --rm -v "$vol":/v -v "$dir":/b:ro "$tar_image" sh -c \
            'find /v -mindepth 1 -maxdepth 1 -exec rm -rf {} \; && tar -C /v -xf "/b/$1.tar"' _ "$key"
        printf 'восстановлен %s\n' "$key"
    done

    # Тома проекта, которых нет в эталоне, завёл прогон — снимаем.
    for key in $(volumes); do
        [ -f "$dir/$key.tar" ] && continue
        vol=${project}_$key
        if docker volume inspect "$vol" >/dev/null 2>&1; then
            docker volume rm "$vol" >/dev/null
            printf 'снят том %s: в эталоне его нет\n' "$vol"
        fi
    done
    restored=$(date +%s)

    say "поднимаю стенд"
    compose up -d
    wait_healthy 300
    healthy=$(date +%s)

    say "жду поколение эталона"
    wait_converged "$gen" "$count"
    finished=$(date +%s)

    printf '\nсброс за %s с: снос и тома %s, подъём %s, сходимость %s\n' \
        $((finished - started)) $((restored - started)) $((healthy - restored)) $((finished - healthy))
}

# Набор между двумя сбросами: до — чистый старт, после — стенд снова эталон, даже если
# набор упал. Код возврата — код набора.
run() {
    local suite=${1:-}
    [ -n "$suite" ] || die "укажите набор: e2e/e2e.sh run logic [кейсы…]"
    shift
    [ -f "$here/$suite/run.mjs" ] || die "нет прогона $suite/run.mjs"

    reset
    say "набор $suite $*"
    local rc=0
    (
        cd "$here"
        WAF_CONTROLLER=$panel WAF_E2E_EDGE=${WAF_E2E_EDGE:-http://127.0.0.1:${node_port:-80}} \
            node "$suite/run.mjs" --no-bootstrap "$@"
    ) || rc=$?
    say "набор $suite: код $rc"
    reset
    return "$rc"
}

status() {
    local fp d name mark
    fp=$(fingerprint)
    printf 'отпечаток образов: %s\n' "$fp"
    for d in "$store"/*/; do
        [ -f "$d/meta" ] || continue
        name=$(basename "$d")
        mark=""
        [ "$name" = "$fp" ] && mark="  <- подходит"
        printf '%s  %s  %s%s\n' "$name" "$(sed -n 's/^taken=//p' "$d/meta")" "$(du -sh "$d" | cut -f1)" "$mark"
    done
}

case "${1:-help}" in
    baseline) shift; baseline "$@" ;;
    reset) reset ;;
    run) shift; run "$@" ;;
    status) status ;;
    help | -h | --help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' ;;
    *) die "неизвестная команда: $1 (см. e2e/e2e.sh help)" ;;
esac
