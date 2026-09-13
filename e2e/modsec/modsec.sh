#!/bin/sh
# Прогон инспектора правил (inspectors/modsec) на маршрутах /modsec* окружения
# deploy/.
#
#     docker compose up -d --wait
#     docker compose exec -T nginx-1 sh /t/modsec/modsec.sh
#
# Сначала send с контроллера — инспектор применяет пять профилей из KV.
# Дальше коды ответа: CRS по полезной нагрузке и фикстуры allow/deny.

BASE=http://127.0.0.1:8080
CONTROLLER=http://controller:8080

# Классическая инъекция: libinjection (942100) даёт 5 баллов на любом уровне
# паранойи. Экранировано для оболочки, в запрос уходит id=1' or 1=1--
SQLI="id=1%27+or+1%3D1--"

# Обход каталога: 930110 (path traversal), тоже 5 баллов.
TRAVERSAL="file=../../../../etc/passwd"

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

# имя url заголовок
show() {
    name=$1; url=$2; hdr=$3

    value=$(curl -s -o /dev/null -D - "$url" \
            | tr -d '\r' | grep -i "^${hdr}:" | cut -d' ' -f2-)

    printf '     %-46s %s\n' "$name" "${value:-<нет>}"
}

echo '--- send профилей ---'
SCOPE=$(curl -s "$CONTROLLER/api/spaces" | sed -n 's/.*"uuid":"\([^"]*\)".*/\1/p' | head -1)

if [ -z "$SCOPE" ]; then
    printf 'FAIL %-46s %s\n' "scope с контроллера" "пусто"
    fail=$((fail + 1))
else
    SEND=$(curl -s -o /tmp/waf-send.json -w '%{http_code}' \
           -X POST "$CONTROLLER/api/$SCOPE/rules/send")
    if [ "$SEND" = "200" ]; then
        printf 'ok   %-46s %s\n' "POST /rules/send" "$SEND"
        # инспектор пишет дерево и компилирует Coraza
        sleep 4
    else
        printf 'FAIL %-46s %s\n' "POST /rules/send" "$SEND"
        fail=$((fail + 1))
    fi
fi

echo '--- чистый трафик ---'
# Счёт у этих запросов не нулевой: обращение идёт на 127.0.0.1, и 920350
# (числовой IP в заголовке Host) даёт 3 балла, то есть score 30. Порог 50 он не
# берёт, и это ровно тот случай, ради которого счёт отделён от отказа --
# признак есть, обвинения нет. В профиле api протокол 920 не включён.
check 200 'обычный запрос'                      "$BASE/modsec/"
check 200 'обычный запрос, строгий профиль'     "$BASE/modsec-strict/"
check 200 'обычный запрос, профиль api'         "$BASE/modsec-api/"
# Тело есть, но безобидное. Инспектору его не присылают (драйвер тела -- этап 6),
# и это не должно менять исход: фазы 1-2 отрабатывают и без тела.
check 200 'POST с телом'                        "$BASE/modsec/" \
      -X POST -H 'content-type: application/x-www-form-urlencoded' -d 'q=hello'

echo '--- находки CRS ---'
check 403 'SQL-инъекция в строке запроса'       "$BASE/modsec/?$SQLI"
check 403 'обход каталога'                      "$BASE/modsec/?$TRAVERSAL"
# Находка не в строке запроса, а в заголовке: 913100 смотрит на User-Agent.
# Инъекция в произвольном заголовке здесь не сработала бы -- правила 942xxx на
# уровне паранойи 1 смотрят на ARGS, а не на все заголовки подряд.
check 403 'сканер по User-Agent'                "$BASE/modsec/" \
      -H 'user-agent: nikto/2.1.6'
# XSS в параметре ловится на уровне паранойи 1 правилом 941xxx.
check 403 'XSS в параметре'                     "$BASE/modsec/?q=%3Cscript%3Ealert(1)%3C/script%3E"
# 934110: словарь ssrf.data, подстрока облачного metadata.
check 403 'SSRF metadata'                       "$BASE/modsec/?url=http://169.254.169.254/latest/meta-data/"
# 944: класс из java-classes.data.
check 403 'Java class'                          "$BASE/modsec/?c=com.opensymphony.xwork2"
# 943 session id в query; 942 в cookie.
check 403 'session id в query'                  "$BASE/modsec/?jsessionid=abc123fix"
check 403 'SQLi в cookie'                       "$BASE/modsec/" \
      -H "cookie: id=1' or 1=1--"

echo '--- профиль по маршруту ---'
# Уровень паранойи 2 добавляет находки, но на этой нагрузке решение то же:
# профиль меняет счёт, а не смысл ответа.
check 403 'строгий профиль: та же инъекция'     "$BASE/modsec-strict/?$SQLI"
check 403 'строгий: доп. LFI сверху'            "$BASE/modsec-strict/?path=../../../etc/passwd"
check 403 'api: та же инъекция'                 "$BASE/modsec-api/?$SQLI"
check 403 'api: XSS сверху'                     "$BASE/modsec-api/?q=%3Cscript%3Ealert(1)%3C/script%3E"
# Профиля нет -- deny, не откат на default. Чистый запрос тоже 403:
# иначе разъезд тега и набора пропускал бы трафик.
check 403 'неизвестный профиль: чистый тоже отказ' "$BASE/modsec-unknown/"
check 403 'неизвестный профиль: инъекция тоже отказ' "$BASE/modsec-unknown/?$SQLI"

echo '--- фикстуры ---'
# allow не смотрит на запрос вовсе: инъекция проходит. deny отказывает на чистом.
check 200 'allow: инъекция не блокирует'        "$BASE/modsec-allow/?$SQLI"
check 403 'deny: чистый запрос всё равно отказ' "$BASE/modsec-deny/"

echo '--- пассивный режим ---'
check 200 'passive: находка не блокирует'       "$BASE/modsec-passive/?$SQLI"

echo '--- диагностика ---'
show 'чистый запрос'      "$BASE/modsec/"          X-WAF-Debug
show 'инъекция'           "$BASE/modsec/?$SQLI"    X-WAF-Debug
show 'инъекция, passive'  "$BASE/modsec-passive/?$SQLI" X-WAF-Debug
show 'allow'              "$BASE/modsec-allow/?$SQLI" X-WAF-Debug
show 'deny'               "$BASE/modsec-deny/"     X-WAF-Debug

echo ''
if [ $fail -eq 0 ]; then
    echo 'все проверки пройдены'
else
    echo "провалено проверок: $fail"
fi

echo 'вердикты инспектора: docker compose logs inspector-modsec'

exit $fail
