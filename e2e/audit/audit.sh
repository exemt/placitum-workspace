#!/bin/sh
#
# Запись аудита в WAF_AUDIT: что именно доезжает до шины после архивации.
# Гоняется из nats-box -- из контейнера nginx шину не видно, клиента там нет:
#
#     docker compose exec -T nats-box sh /t/audit/audit.sh
#
# Проверяется склейка секции store. Модуль на /body/archive/ оставляет жить
# заголовки и тело, называет их срок хранения в store.archive и передаёт
# владение агенту. Дальше судьба двух объектов расходится, и обе ветви видны в
# одной записи:
#
#     тело       -- бакет waf-bodies: локатор стал архивным,
#                   store=archive, driver=s3, ключ по дате, узлу и ray
#     заголовки  -- бакет waf-headers: тот же архивный локатор
#
# И главное свойство агента: всё остальное в записи он не трогает. Поля, о
# которых он не знает, доезжают до шины ровно такими, какими их собрал модуль.
#
# Судьба ключей в Redis -- в tests/body: отсюда Redis не видно.

set -u

NATS=${NATS_URL:-nats://nats:4222}
EDGE=${EDGE:-http://nginx-1:8080}
NODE=${NODE:-edge-01}

# waf_archive request ... ttl=7d на маршруте, в записи -- секунды.
TTL=${TTL:-604800}

# Датаграмма уходит агенту вдогонку ответу клиенту, дальше GET, PUT и PUB.
SETTLE=${SETTLE:-2}

SUBJECT="waf.audit.request.$NODE"

# Признак, на который смотрит CRS 942100. Пробел существенный: правило
# ищет SQLi в самом теле.
BODY='{"q":"1 union select 1"}'

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

# ожидаемое имя значение
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

say "--- запрос на маршрут с архивацией ---"

code=$(printf '%s' "$BODY" \
       | curl -s -o /dev/null -w '%{http_code}' -X POST \
              -H 'content-type: application/json' \
              --data-binary @- "$EDGE/body/archive/")

# 403 и на POST: страница отказа отдаётся через error_page с URI, а на этой
# форме nginx меняет метод на GET. Через именованный location POST доезжал до
# статики как есть и получал от неё 405 -- отказ выглядел по-разному в
# зависимости от метода, хотя решение модуля было одним и тем же.
eq 'вердикт клиенту' 403 "$code"

sleep "$SETTLE"

say "--- запись на шине ---"

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

eq 'конверт: kind'    'request' "$(field '.kind')"
eq 'конверт: v'       '1'       "$(field '.v')"
eq 'узел'             "$NODE"   "$(field '.node')"
eq 'вердикт в записи' 'deny'    "$(field '.verdict')"
eq 'код ответа'       '403'     "$(field '.http.status')"

say '--- тело: локатор подменён архивным ---'

eq 'store'  'archive' "$(field '.store.body.store')"
eq 'driver' 's3'      "$(field '.store.body.driver')"

key=$(field '.store.body.key')
ray=$(field '.ray')

case $key in
*/*/*/"$NODE"/"$ray".body)
    ok 'ключ: дата, узел, ray' ;;
*)
    bad 'ключ: дата, узел, ray' "$key" ;;
esac

# Описательные поля верны независимо от того, где объект лежит: содержимое не
# изменилось, изменилось только место.
eq 'размер на месте' 'true' \
   "$(field 'if (.store.body.size // 0) > 0 then "true" else "false" end')"

eq 'контрольная сумма на месте' 'true' \
   "$(field 'if (.store.body.sha256 // "") != "" then "true" else "false" end')"

# Подсказка узла относится к обменнику: в архиве узла нет, после переезда она бы
# лгала. Срок же подменён архивным -- его называет само хранилище своим
# правилом удаления (core/config/minio/lifecycle.json), и по нему разбор инцидента
# видит, лежит ли объект ещё на месте, не обращаясь к бакету. Правил в бакете
# нет -- поля не будет вовсе, и это не то же, что истёкший срок.
eq 'срок архива приехал' 'true' \
   "$(field 'if (.store.body.expires_at // 0) > now then "true" else "false" end')"

eq 'подсказка ушла' 'null' "$(field '.store.body.hint')"

say '--- заголовки: тот же архив, что и тело ---'

eq 'store заголовков' 'archive' "$(field '.store.headers.store')"
eq 'драйвер заголовков' 's3'    "$(field '.store.headers.driver')"
eq 'ключ заголовков есть' 'true' \
   "$(field 'if (.store.headers.key // "") != "" then "true" else "false" end')"
eq 'размер заголовков на месте' 'true' \
   "$(field 'if (.store.headers.size // 0) > 0 then "true" else "false" end')"

say '--- срок остался в записи ---'

# По сроку видно, когда объекта не станет. Сам по себе он ничего не открывает:
# локаторы к этому моменту уже архивные.
eq 'store.archive.body'    "$TTL" "$(field '.store.archive.body')"
eq 'store.archive.headers' "$TTL" "$(field '.store.archive.headers')"

say '--- остальное агент не трогал ---'

# Секции, к которым архивация отношения не имеет, обязаны доехать целиком.
eq 'inspectors на месте' 'true' \
   "$(field 'if (.inspectors | length) > 0 then "true" else "false" end')"

eq 'маршрут на месте' 'true' \
   "$(field 'if (.route.location // "") != "" then "true" else "false" end')"

# uuid пути (waf_route_id): по нему журнал схлопывает трафик маршрута, и у
# конфигурации от контроллера он есть в каждом блоке location.
eq 'uuid маршрута на месте' 'true' \
   "$(field 'if (.route.id // "") != "" then "true" else "false" end')"

eq 'латентность на месте' 'true' \
   "$(field 'if (.waf_latency_us // 0) > 0 then "true" else "false" end')"

say ''
say "итог: $pass ok, $fail fail"
say "запись целиком: nats --server $NATS stream get WAF_AUDIT --last-for=$SUBJECT"

exit $fail
