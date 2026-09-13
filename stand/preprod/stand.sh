#!/bin/sh
# Пре-прод: стенд раскатки и установки.
#
#     ./stand.sh fresh     полный сброс, установка с нуля, проверка, дым и снова проверка -- главный прогон
#     ./stand.sh reset     снести установку: контейнеры, тома, образы, ответы
#     ./stand.sh update    подтянуть core из публичного репозитория
#     ./stand.sh install   установка поверх текущего состояния
#     ./stand.sh check     чистая установка: один сервер -- панель, каналы сошлись, всё здорово
#     ./stand.sh status    что стоит
#     ./stand.sh doctor    что мешает установке прямо сейчас
#     ./stand.sh smoke     дым на поставленном контуре: маршрут через API и узел, с уборкой
#
# Стенд ставит ровно то, что ставит клиент: выкачивает публичный placitum-core
# и запускает его install.sh. Приватного монорепозитория на машине нет и быть
# не должно -- источники компонентов приезжают из их публичных репозиториев,
# по строке на компонент в core/sources.env.
#
# Ответы стенда (порты, имя узла, имя проекта) живут снаружи клона, в
# stand.env: install.sh заводит .env из .env.example со своими умолчаниями, а
# у стенда :80 и :443 заняты хостовым nginx. Держать ответы снаружи -- значит
# пережить ими полный сброс и не держать в клоне ни одной своей правки.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ws=$(CDPATH= cd -- "$root/../.." && pwd)
core=$ws/core
answers=$root/stand.env
origin=https://github.com/exemt/placitum-core.git
branch=${PLC_CORE_BRANCH:-develop}
project=placitum

say()  { printf '\n== %s\n' "$*"; }
warn() { printf '!! %s\n' "$*" >&2; }
die()  { printf '!! %s\n' "$*" >&2; exit 1; }

# Проект compose называет .env установки; до его появления берём своё имя,
# иначе down искал бы контейнеры в проекте по имени каталога.
compose_down() {
    [ -d "$core" ] || return 0

    # waf.yml требует источники компонентов: без sources.env compose отказывается
    # разбирать файл, и down по нему молча не делал ничего -- работал только
    # запасной путь через infra.yml.
    sources=
    [ -f "$core/sources.env" ] && sources="--env-file $core/sources.env"

    # shellcheck disable=SC2086
    docker compose -p "$project" \
        --env-file "$answers" $sources \
        -f "$core/compose/waf.yml" down -v --remove-orphans 2>/dev/null ||
        docker compose -p "$project" \
            --env-file "$answers" \
            -f "$core/compose/infra.yml" down -v --remove-orphans 2>/dev/null ||
        true
}

# --- команды --------------------------------------------------------------

clone() {
    if [ -d "$core/.git" ]; then
        say "core на месте: $(git -C "$core" rev-parse --short HEAD) ($branch)"
        return
    fi

    say "выкачиваю core"
    git clone --branch "$branch" "$origin" "$core"
}

update() {
    clone
    say "обновляю core из origin/$branch"

    # reset --hard, а не pull: клон обязан быть точной копией публичной ветки.
    # Любая местная правка здесь -- это стенд, который проверяет не то, что
    # получит клиент.
    git -C "$core" fetch --quiet origin "$branch"
    git -C "$core" reset --hard "origin/$branch"
    git -C "$core" clean -fd --quiet -e .env -e secrets -e config/edge/node.conf

    git -C "$core" log --oneline -1
}

reset() {
    say "сношу установку"
    compose_down

    # Образы компонентов -- те, что называет compose установки: их собирает
    # установка, и следующий прогон обязан собрать их заново. Имена у них двух
    # видов (placitum/<имя> и placitum-<имя>), поэтому список берётся из compose,
    # а не по приставке. Базовые образы (postgres, nats, ...) остаются -- они
    # приезжают из реестра, пересборки не требуют и качаются по десять минут;
    # образов e2e и профиля vlai compose установки не называет.
    sources=
    [ -f "$core/sources.env" ] && sources="--env-file $core/sources.env"
    # shellcheck disable=SC2086
    imgs=$(docker compose -p "$project" --env-file "$answers" $sources \
        -f "$core/compose/waf.yml" config --images 2>/dev/null | grep -E '^placitum[-/]' || true)
    [ -n "$imgs" ] && printf '%s\n' "$imgs" | xargs -r docker rmi -f >/dev/null 2>&1 || true

    # Ответы и секреты: установка обязана завести их сама, иначе прогон
    # проверяет не установку с нуля, а установку поверх вчерашней.
    rm -f "$core/.env" "$core/config/edge/node.conf" 2>/dev/null || true
    # Все выпущенные секреты, а не список: установка заводит новые (ключи подписи
    # калитки, капчи и cookie), и перечисление отставало бы от неё молча.
    find "$core/secrets" -type f ! -name .gitignore -delete 2>/dev/null || true

    printf 'снесено: контейнеры, тома, образы установки (%s), ответы и секреты\n' \
        "$(printf '%s' "$imgs" | grep -c . || true)"
}

answer() {
    [ -f "$answers" ] || die "нет ответов стенда: $answers"

    # Ответы кладём до install.sh: он заводит .env из .env.example, только
    # если .env нет, и умолчания там клиентские (:80, :443).
    cp "$answers" "$core/.env"
    printf 'ответы стенда положены в core/.env\n'
}

install() {
    clone
    answer
    say "установка"
    "$core/install.sh" install
}

fresh() {
    update
    reset
    install
    say "чистая установка"
    check
    smoke
    say "после дыма: установка та же"
    check
}

# Дым смотрит с самой машины, как оператор после установки: адреса API
# контроллера и узла -- из ответов стенда. API -- мимо калитки, на loopback:
# дым проверяет контур, а не вход в панель.
smoke() {
    [ -f "$root/smoke.sh" ] || die "нет smoke.sh рядом со stand.sh"
    . "$answers"
    sh "$root/smoke.sh" "http://127.0.0.1:${PLC_CONTROLLER_PORT:-8080}" "http://127.0.0.1:${PLC_HTTP_PORT:-80}"
}

# Чистая установка глазами пользователя: один сервер -- сама панель, каналы
# сошлись, флот и контейнеры здоровы. После дыма то же самое: он убирает за собой.
check() {
    [ -f "$root/clean.mjs" ] || die "нет clean.mjs рядом со stand.sh"
    command -v node >/dev/null 2>&1 || die "нужен node: им проверяется установка"
    . "$answers"
    node "$root/clean.mjs" "http://127.0.0.1:${PLC_CONTROLLER_PORT:-8080}" "$project-edge-1"
}

status() {
    [ -d "$core" ] || die "core не выкачан: ./stand.sh update"

    say "core"
    git -C "$core" log --oneline -1
    git -C "$core" status --short || true

    say "установка"
    docker ps --filter "label=com.docker.compose.project=$project" \
        --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
}

# Отдельная команда, потому что чаще всего установка падает не в себе, а в
# том, чего на машине нет: занятого порта, несуществующего образа, пустого
# репозитория компонента.
doctor() {
    say "порты хоста"
    . "$answers"
    for p in "${PLC_HTTP_PORT:-80}" "${PLC_HTTPS_PORT:-443}" "${PLC_PANEL_PORT:-8081}" "${PLC_CONTROLLER_PORT:-8080}"; do
        if ss -ltn "sport = :$p" 2>/dev/null | grep -q LISTEN; then
            warn "порт $p занят"
        else
            printf 'порт %s свободен\n' "$p"
        fi
    done

    say "источники компонентов"
    [ -f "$core/sources.env" ] || die "нет core/sources.env: ./stand.sh update"

    # Пустой репозиторий отвечает на ls-remote успехом и пустотой -- сборка
    # из него падает не в начале, а на середине прогона. Проверяем заранее.
    grep '^PLC_SRC_' "$core/sources.env" | while IFS='=' read -r name value; do
        url=${value%%#*}
        spec=${value#*#}
        # #ветка:подкаталог -- ls-remote знает только ветки, подкаталог разбирает
        # уже сборщик. Без среза агенты из общего репозитория выглядели бы как
        # «нет ветки develop:redis».
        ref=${spec%%:*}

        case "$url" in
            http*|git@*) ;;
            *) printf '%-22s путь: %s\n' "$name" "$url"; continue ;;
        esac

        if ! heads=$(git ls-remote --heads "$url" 2>/dev/null); then
            warn "$name: репозитория нет -- $url"
        elif [ -z "$heads" ]; then
            warn "$name: репозиторий пуст -- $url"
        elif ! printf '%s' "$heads" | grep -q "refs/heads/$ref$"; then
            warn "$name: нет ветки $ref в $url"
        else
            printf '%-22s готов (%s)\n' "$name" "$spec"
        fi
    done
}

case "${1:-help}" in
    fresh)   fresh ;;
    reset)   reset ;;
    update)  update ;;
    install) install ;;
    check)   check ;;
    status)  status ;;
    doctor)  clone; doctor ;;
    smoke)   smoke ;;
    help|-h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0" ;;
    *) die "неизвестная команда: ${1} (см. ./stand.sh help)" ;;
esac
