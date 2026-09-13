#!/bin/sh
# Счётчик на живом контуре: фаза ответа меряет, фаза запроса судит.
#
#     docker compose up -d --wait
#     sh tests/counter/counter.sh
#
# Гоняется с хоста, ходовая часть -- внутри nats-box: с хоста край виден через
# HAProxy, а маршруты стенда живут на edge-01..03:8080.
#
# Механика маршрута /counter/ -- deploy/nginx/nginx.conf и профиль stand
# (inspectors/counter/profiles/stand): бэкенд-эхо отражает строку запроса в
# поле url ответа, правило measure считает вхождения obj= в корзину
# stand_objects (ёмкость 20, потери 1%/с), правила judge судят адрес по
# заполнению -- score с 45%, deny с 90%. Запрос с десятью obj греет корзину до
# половины, второй такой же -- до потолка, следующий получает 429.

set -eu

# docker compose exec с хоста под MSYS: иначе /dev/null уезжает в путь Windows.
export MSYS_NO_PATHCONV=1

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

# Чистая корзина: прошлый прогон или ручной тык не должны судить этот.
# Паттерн покрывает и мерную stand_objects, и сигнальную stand_abuse.
clean() {
    docker compose exec -T redis sh -c \
        "redis-cli keys 'cnt:bkt:stand_*' | xargs -r redis-cli del" >/dev/null
}

clean

# HTTP-шаги написаны под эхо-маршрут с профилем stand: measure считает obj= в
# отражённом JSON, суд отвечает CNT_STAND_*. На джус-стенде счётчик тоже стоит
# на маршруте, но с профилем default и HTML-бэкендом -- считать там нечего,
# поэтому детект смотрит не на наличие инспектора, а на profile=stand в его
# записи. Иначе шаги пропускаются честно: шинная часть ниже гоняет инспектора
# той же формой сообщений, что шлёт модуль.
if docker compose exec -T nats-box sh -c \
    "curl -s -D - -o /dev/null --max-time 3 http://edge-01:8080/counter/x" \
    | grep -q "counter=[^ ]*profile=stand"; then
    ROUTE=1
else
    ROUTE=0
    echo "на маршруте /counter/ нет эхо-профиля stand -- HTTP-шаги пропущены (стенд juice)"
fi

if [ "$ROUTE" = 1 ]; then

docker compose exec -T nats-box sh -s <<'BOXED'
fail=0
BASE=http://edge-01:8080
OBJ='obj=1&obj=2&obj=3&obj=4&obj=5&obj=6&obj=7&obj=8&obj=9&obj=10'

check() {
    want=$1; name=$2; got=$3
    if [ "$got" = "$want" ]; then
        printf "ok   %-50s %s\n" "$name" "$got"
    else
        printf "FAIL %-50s %s, ожидался %s\n" "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

status() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

# Запись вердикта в X-WAF-Debug: allow -- <вердикт>/<мс>, deny --
# <вердикт>/<код>/<мс>, score -- <вердикт>/<счёт>/<взвешенный>/<код>/<мс>.
# Общее одно: код стоит перед полем длительности, если он есть вообще.
code() {
    awk -F/ '{
        out = $1
        for (i = 2; i <= NF; i++) {
            if ($i ~ /ms$/) {
                if (i > 2 && $(i - 1) !~ /^[0-9]+$/) out = out "/" $(i - 1)
                break
            }
        }
        print out
    }'
}

# Каждый запрос к маршруту греет корзину, поэтому шаг прогона -- ровно один
# запрос: статус в stdout, обе фазы из одного дампа заголовков. Первая запись
# counter= -- фаза запроса, последняя -- фаза ответа; на отказе запись одна --
# фаза ответа не бежит.
hit()  { curl -s -o /dev/null -D /tmp/hdrs -w "%{http_code}" "$@"; }
gate() { tr " " "\n" </tmp/hdrs | sed -n "s/^counter=//p" | head -1 | tr -d "\r" | code; }
rgate() { tr " " "\n" </tmp/hdrs | sed -n "s/^counter=//p" | tail -1 | tr -d "\r" | code; }

echo "--- шаг 1: чистый адрес получает десять объектов ---"

got=$(hit "$BASE/counter/x?$OBJ")
check 200 'запрос проходит' "$got"
check 'allow' 'суд молчит: корзина ещё пуста' "$(gate)"
check 'allow/COUNTER_MEASURED' 'фаза ответа посчитала объекты' "$(rgate)"

echo
echo "--- шаг 2: корзина на половине, суд отвечает счётом ---"

got=$(hit "$BASE/counter/x")
check 200 'счёт порога маршрута не берёт' "$got"
check 'score/CNT_STAND_HOT' 'уровень за порогом: счёт с поводом' "$(gate)"
# Без obj в запросе ответ ничего не добавляет: правило не совпало.
check 'allow' 'пустой ответ корзину не греет' "$(rgate)"

echo
echo "--- шаг 3: ещё десять объектов рядом со score ---"

got=$(hit "$BASE/counter/x?$OBJ")
check 200 'score не мешает учёту' "$got"
check 'allow/COUNTER_MEASURED' 'заряд едет и рядом со score' "$(rgate)"

echo
echo "--- шаг 4: перелив, отказ от имени инспектора ---"

got=$(hit "$BASE/counter/x")
check 429 'клиент видит 429, а не 403' "$got"
check 'deny/CNT_STAND_BAN' 'перелив: отказ с поводом правила' "$(gate)"

# Отказанный запрос до фазы ответа не доезжает и корзину не греет: считается
# то, что субъект реально получил. На отказе запись counter= одна.
check 'deny/CNT_STAND_BAN' 'фаза ответа не бежала: запись одна' "$(rgate)"

echo
if [ "$fail" -ne 0 ]; then
    echo "провалено: $fail"
    exit 1
fi
echo "все проверки прошли"
BOXED

echo
echo "--- корзина в Redis ---"

key=$(docker compose exec -T redis sh -c \
    "redis-cli keys 'cnt:bkt:stand_objects:ip:*'" | head -1 | tr -d '\r')

if [ -n "$key" ]; then
    echo "ok   счёт лежит общим ключом: $key"
else
    echo "FAIL ключа корзины в Redis нет"
    exit 1
fi

# Подчищаем за собой: перелитый адрес судился бы и в соседнем прогоне.
clean

fi # ROUTE

echo
echo "--- приём note: сосед греет сигнальную корзину ---"
#
# Живого отправителя на маршруте нет, поэтому сообщения с prior публикуются в
# шину напрямую -- ровно той формой, что доставляет модуль. Субъект выдуманный
# (192.0.2.77), profile=stand: правило приёма кладёт note от action в
# stand_abuse (проценты ёмкости), суд читает уровень со следующего запроса.

docker compose exec -T nats-box sh -s <<'NOTEBOX'
fail=0
NATS=${NATS_URL:-nats://nats:4222}
ADDR=192.0.2.77

check() {
    want=$1; name=$2; got=$3
    if [ "$got" = "$want" ]; then
        printf "ok   %-50s %s\n" "$name" "$got"
    else
        printf "FAIL %-50s %s, ожидался %s\n" "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

seq=0

# Сообщение фазы ответа с note от action: value -- проценты ёмкости корзины.
# Запись prior -- тоже фазы ответа: note снимается на фазе СВОЕЙ записи
# (chargeHere), а запись фазы запроса зарядилась бы только в сообщении фазы
# запроса -- которых этот прогон с prior не шлёт.
note() {
    seq=$((seq + 1))
    nats --server "$NATS" request --timeout 2s waf.req.counter "{
      \"v\":2,\"rid\":\"e2enote$$$seq\",\"phase\":\"response\",\"inspector\":\"counter\",
      \"deadline_ms\":1000,\"node\":\"e2e\",
      \"conn\":{\"client_ip\":\"$ADDR\",\"client_port\":4321,\"server_ip\":\"10.0.0.1\",\"server_port\":8080},
      \"http\":{\"method\":\"GET\",\"scheme\":\"http\",\"host\":\"e2e.local\",\"uri\":\"/counter/echo\",\"args_size\":0,\"version\":\"HTTP/1.1\"},
      \"route\":{\"server_name\":\"e2e.local\",\"location\":\"/counter/\",\"profile\":\"stand\"},
      \"score\":{\"deny_at\":100},
      \"response\":{\"status\":200},
      \"prior\":[{\"phase\":\"response\",\"wave\":0,\"inspector\":\"action\",\"verdict\":\"allow\",
        \"actions\":[{\"do\":\"note\",\"apply\":\"ip\",\"value\":$1,\"code\":\"E2E_NOTE\"}]}]
    }" 2>/dev/null
}

# Сообщение фазы запроса того же субъекта: суд по уровню корзины.
judge() {
    seq=$((seq + 1))
    nats --server "$NATS" request --timeout 2s waf.req.counter "{
      \"v\":2,\"rid\":\"e2ejudge$$$seq\",\"phase\":\"request\",\"inspector\":\"counter\",
      \"deadline_ms\":1000,\"node\":\"e2e\",
      \"conn\":{\"client_ip\":\"$ADDR\",\"client_port\":4321,\"server_ip\":\"10.0.0.1\",\"server_port\":8080},
      \"http\":{\"method\":\"GET\",\"scheme\":\"http\",\"host\":\"e2e.local\",\"uri\":\"/counter/echo\",\"args_size\":0,\"version\":\"HTTP/1.1\"},
      \"route\":{\"server_name\":\"e2e.local\",\"location\":\"/counter/\",\"profile\":\"stand\"},
      \"score\":{\"deny_at\":100}
    }" 2>/dev/null
}

verdict() { sed -n 's/.*"verdict":"\([a-z]*\)".*/\1/p' | head -1; }
reason()  { sed -n 's/.*"code":"\([A-Z0-9_]*\)".*/\1/p' | head -1; }

# Плюс: половина ёмкости. Ответ фазы ответа -- всегда allow, но с причиной
# COUNTER_MEASURED: заряд состоялся.
rsp=$(note 50)
check 'allow' 'фаза ответа: note принят, вердикт allow' "$(echo "$rsp" | verdict)"
check 'COUNTER_MEASURED' 'причина: заряд состоялся' "$(echo "$rsp" | reason)"

rsp=$(judge)
check 'score' 'суд: сигнальная корзина за порогом score' "$(echo "$rsp" | verdict)"
check 'CNT_ABUSE_HOT' 'повод правила по сигнальной корзине' "$(echo "$rsp" | reason)"

# Ещё половина: перелив, следующий запрос субъекта режется.
note 50 >/dev/null
rsp=$(judge)
check 'deny' 'суд после перелива: отказ' "$(echo "$rsp" | verdict)"
check 'CNT_ABUSE_BAN' 'повод отказа' "$(echo "$rsp" | reason)"

# Минус сто: обнуление -- «очистить корзину» это край той же шкалы.
note -100 >/dev/null
rsp=$(judge)
check 'allow' 'note -100 обнулил: суд молчит' "$(echo "$rsp" | verdict)"

# Селектор корзины с провода: названная корзина проходит только через
# правило, которое её выдало. Своё имя -- заряд, чужое -- no_rule и тишина.
seq=$((seq + 1))
picked=$(nats --server "$NATS" request --timeout 2s waf.req.counter "{
  \"v\":2,\"rid\":\"e2epick$$$seq\",\"phase\":\"response\",\"inspector\":\"counter\",
  \"deadline_ms\":1000,\"node\":\"e2e\",
  \"conn\":{\"client_ip\":\"$ADDR\",\"client_port\":4321,\"server_ip\":\"10.0.0.1\",\"server_port\":8080},
  \"http\":{\"method\":\"GET\",\"scheme\":\"http\",\"host\":\"e2e.local\",\"uri\":\"/counter/echo\",\"args_size\":0,\"version\":\"HTTP/1.1\"},
  \"route\":{\"server_name\":\"e2e.local\",\"location\":\"/counter/\",\"profile\":\"stand\"},
  \"score\":{\"deny_at\":100},
  \"response\":{\"status\":200},
  \"prior\":[{\"phase\":\"response\",\"wave\":0,\"inspector\":\"action\",\"verdict\":\"allow\",
    \"actions\":[{\"do\":\"note\",\"apply\":\"ip\",\"value\":50,\"code\":\"E2E_NOTE\",\"counter\":\"stand_abuse\"}]}]
}" 2>/dev/null)
check 'COUNTER_MEASURED' 'селектор своей корзины: заряд принят' "$(echo "$picked" | reason)"

rsp=$(judge)
check 'score' 'суд видит заряд по селектору' "$(echo "$rsp" | verdict)"

seq=$((seq + 1))
nats --server "$NATS" request --timeout 2s waf.req.counter "{
  \"v\":2,\"rid\":\"e2eforeign$$$seq\",\"phase\":\"response\",\"inspector\":\"counter\",
  \"deadline_ms\":1000,\"node\":\"e2e\",
  \"conn\":{\"client_ip\":\"$ADDR\",\"client_port\":4321,\"server_ip\":\"10.0.0.1\",\"server_port\":8080},
  \"http\":{\"method\":\"GET\",\"scheme\":\"http\",\"host\":\"e2e.local\",\"uri\":\"/counter/echo\",\"args_size\":0,\"version\":\"HTTP/1.1\"},
  \"route\":{\"server_name\":\"e2e.local\",\"location\":\"/counter/\",\"profile\":\"stand\"},
  \"score\":{\"deny_at\":100},
  \"response\":{\"status\":200},
  \"prior\":[{\"phase\":\"response\",\"wave\":0,\"inspector\":\"action\",\"verdict\":\"allow\",
    \"actions\":[{\"do\":\"note\",\"apply\":\"ip\",\"value\":50,\"code\":\"E2E_NOTE\",\"counter\":\"stand_objects\"}]}]
}" >/dev/null 2>&1

rsp=$(judge)
check 'score' 'чужой селектор не заряжает: уровень тот же' "$(echo "$rsp" | verdict)"

# Чистим селекторные заряды, чтобы не мешать шагу минуса ниже.
note -100 >/dev/null

rsp=$(judge)
check 'allow' 'минус после селектора обнуляет' "$(echo "$rsp" | verdict)"

# Просьба от отправителя без правила -- записанное молчание, заряда нет.
seq=$((seq + 1))
nats --server "$NATS" request --timeout 2s waf.req.counter "{
  \"v\":2,\"rid\":\"e2enorule$$$seq\",\"phase\":\"response\",\"inspector\":\"counter\",
  \"deadline_ms\":1000,\"node\":\"e2e\",
  \"conn\":{\"client_ip\":\"$ADDR\",\"client_port\":4321,\"server_ip\":\"10.0.0.1\",\"server_port\":8080},
  \"http\":{\"method\":\"GET\",\"scheme\":\"http\",\"host\":\"e2e.local\",\"uri\":\"/counter/echo\",\"args_size\":0,\"version\":\"HTTP/1.1\"},
  \"route\":{\"server_name\":\"e2e.local\",\"location\":\"/counter/\",\"profile\":\"stand\"},
  \"score\":{\"deny_at\":100},
  \"response\":{\"status\":200},
  \"prior\":[{\"phase\":\"response\",\"wave\":0,\"inspector\":\"modsec\",\"verdict\":\"allow\",
    \"actions\":[{\"do\":\"note\",\"apply\":\"ip\",\"value\":90,\"code\":\"E2E_NOTE\"}]}]
}" >/dev/null 2>&1

rsp=$(judge)
check 'allow' 'note без правила не заряжает' "$(echo "$rsp" | verdict)"

if [ "$fail" -ne 0 ]; then
    echo "приём note: провалено $fail"
    exit 1
fi
echo "приём note: все проверки прошли"
NOTEBOX

# Ключ сигнальной корзины -- по объявлению, без профиля.
key=$(docker compose exec -T redis sh -c \
    "redis-cli keys 'cnt:bkt:stand_abuse:ip:*'" | head -1 | tr -d '\r')

if [ -n "$key" ]; then
    echo "ok   сигнальный счёт лежит своим ключом: $key"
else
    echo "FAIL ключа сигнальной корзины в Redis нет"
    exit 1
fi

clean

echo
echo "--- личность вместо куки: ось user по логину калитки ---"
#
# Живой калитки в прогоне нет, поэтому секция sessions публикуется в шину
# напрямую -- ровно той формой, которой её возвращает модуль соседям. Проверяется
# то, ради чего она заведена: ключ корзины -- логин, а не адрес и не кука, и
# берётся он только с проверенной записи.

docker compose exec -T nats-box sh -s <<'PEOPLEBOX'
fail=0
NATS=${NATS_URL:-nats://nats:4222}

check() {
    want=$1; name=$2; got=$3
    if [ "$got" = "$want" ]; then
        printf "ok   %-50s %s\n" "$name" "$got"
    else
        printf "FAIL %-50s %s, ожидался %s\n" "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

seq=0

# Сообщение фазы ответа: статус 418 заряжает stand_people на единицу (source:
# const, ёмкость два). Адрес у каждого шага свой -- ключ берётся из личности.
# $1 -- логин, $2 -- проверена ли запись, $3 -- адрес клиента.
measure() {
    seq=$((seq + 1))
    nats --server "$NATS" request --timeout 2s waf.req.counter "{
      \"v\":2,\"rid\":\"e2eppl$$$seq\",\"phase\":\"response\",\"inspector\":\"counter\",
      \"deadline_ms\":1000,\"node\":\"e2e\",
      \"conn\":{\"client_ip\":\"$3\",\"client_port\":4321,\"server_ip\":\"10.0.0.1\",\"server_port\":8080},
      \"http\":{\"method\":\"GET\",\"scheme\":\"http\",\"host\":\"e2e.local\",\"uri\":\"/counter/echo\",\"args_size\":0,\"version\":\"HTTP/1.1\"},
      \"route\":{\"server_name\":\"e2e.local\",\"location\":\"/counter/\",\"profile\":\"stand\"},
      \"score\":{\"deny_at\":100},
      \"response\":{\"status\":418},
      \"sessions\":[{\"inspector\":\"auth\",\"source\":\"corp\",\"kind\":\"own\",
        \"user\":\"$1\",\"id\":\"sid-$1\",\"verified\":$2}]
    }" 2>/dev/null
}

# Сообщение фазы запроса того же человека: суд по уровню его корзины.
judge() {
    seq=$((seq + 1))
    nats --server "$NATS" request --timeout 2s waf.req.counter "{
      \"v\":2,\"rid\":\"e2epplj$$$seq\",\"phase\":\"request\",\"inspector\":\"counter\",
      \"deadline_ms\":1000,\"node\":\"e2e\",
      \"conn\":{\"client_ip\":\"$3\",\"client_port\":4321,\"server_ip\":\"10.0.0.1\",\"server_port\":8080},
      \"http\":{\"method\":\"GET\",\"scheme\":\"http\",\"host\":\"e2e.local\",\"uri\":\"/counter/echo\",\"args_size\":0,\"version\":\"HTTP/1.1\"},
      \"route\":{\"server_name\":\"e2e.local\",\"location\":\"/counter/\",\"profile\":\"stand\"},
      \"score\":{\"deny_at\":100},
      \"sessions\":[{\"inspector\":\"auth\",\"source\":\"corp\",\"kind\":\"own\",
        \"user\":\"$1\",\"id\":\"sid-$1\",\"verified\":$2}]
    }" 2>/dev/null
}

# Запрос без единой личности: калитки на маршруте нет либо она промолчала.
anon() {
    seq=$((seq + 1))
    nats --server "$NATS" request --timeout 2s waf.req.counter "{
      \"v\":2,\"rid\":\"e2eppla$$$seq\",\"phase\":\"request\",\"inspector\":\"counter\",
      \"deadline_ms\":1000,\"node\":\"e2e\",
      \"conn\":{\"client_ip\":\"198.51.100.30\",\"client_port\":4321,\"server_ip\":\"10.0.0.1\",\"server_port\":8080},
      \"http\":{\"method\":\"GET\",\"scheme\":\"http\",\"host\":\"e2e.local\",\"uri\":\"/counter/echo\",\"args_size\":0,\"version\":\"HTTP/1.1\"},
      \"route\":{\"server_name\":\"e2e.local\",\"location\":\"/counter/\",\"profile\":\"stand\"},
      \"score\":{\"deny_at\":100}
    }" 2>/dev/null
}

verdict() { sed -n 's/.*"verdict":"\([a-z]*\)".*/\1/p' | head -1; }
reason()  { sed -n 's/.*"code":"\([A-Z0-9_]*\)".*/\1/p' | head -1; }

rsp=$(measure e2e-alice true 198.51.100.11)
check 'allow' 'учёт по личности: вердикт фазы ответа' "$(echo "$rsp" | verdict)"
check 'COUNTER_MEASURED' 'учёт по личности: заряд состоялся' "$(echo "$rsp" | reason)"

# Второй заряд с ДРУГОГО адреса: корзина та же, потому что человек тот же.
measure e2e-alice true 198.51.100.12 >/dev/null

rsp=$(judge e2e-alice true 198.51.100.13)
check 'deny' 'суд по личности: корзина перелита с двух устройств' "$(echo "$rsp" | verdict)"
check 'CNT_PEOPLE_BAN' 'повод отказа' "$(echo "$rsp" | reason)"

# Сосед по маршруту -- другой человек: его корзина пуста, отказ не наследуется.
rsp=$(judge e2e-bob true 198.51.100.11)
check 'allow' 'чужая личность: своя корзина, чужой отказ не наследуется' "$(echo "$rsp" | verdict)"

# Непроверенная запись -- это то, что прислал клиент: ключа она не даёт, и
# правило по оси молчит, как при отсутствующей куке.
rsp=$(judge e2e-alice false 198.51.100.11)
check 'allow' 'непроверенная личность ключом счёта не становится' "$(echo "$rsp" | verdict)"

# Запрос без личности вовсе: субъекта нет, правило молчит.
rsp=$(anon)
check 'allow' 'без секции sessions: субъекта нет, правило молчит' "$(echo "$rsp" | verdict)"

if [ "$fail" -ne 0 ]; then
    echo "личность: провалено $fail"
    exit 1
fi
echo "личность: все проверки прошли"
PEOPLEBOX

# Ключ корзины -- по объявлению и по оси user: хеш логина, а не адреса.
key=$(docker compose exec -T redis sh -c \
    "redis-cli keys 'cnt:bkt:stand_people:user:*'" | head -1 | tr -d '\r')

if [ -n "$key" ]; then
    echo "ok   счёт по личности лежит своим ключом: $key"
else
    echo "FAIL ключа корзины по личности в Redis нет"
    exit 1
fi

clean

echo
echo "--- проба ---"
docker compose exec -T inspector-counter counter-probe --timeout 2s
docker compose exec -T inspector-counter counter-probe --timeout 2s \
    --profile stand --uri /counter/healthz --expect allow

echo
echo "счётчик: все проверки прошли"
