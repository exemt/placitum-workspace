#!/bin/sh
# Дым на поставленном контуре -- первое, что делает оператор после установки,
# одной командой:
#
#     ./smoke.sh [панель] [узел]     умолчания http://127.0.0.1:8080 и http://127.0.0.1
#
# Цепочка целиком: панель жива и видит базу; инспектор ip объявлен на
# пространстве; сервер smoke.local привязан к порту узла; путь /smoke
# проксирует на /healthz контроллера под инспектором ip; «Разослать» принято,
# и узел отчитался новым поколением;
# узел отдаёт 200 через сопоставление портов контейнера; инспектор ip эти
# запросы принял; у процессов во флоте видна сборка.
#
# Путь -- прокси, а не return: модуль работает в фазе доступа, а return
# отвечает раньше неё, и такой путь проверял бы узел, но не инспектора.
# Выключатель waf на пути включается явно: его умолчание -- off, и путь с
# инспекторами, но без waf on, модуль пропускает молча.
# Участие инспектора видно по счётчику accepted во флоте: запросов шлём с
# запасом, чтобы пробы HEALTHCHECK, которые ходят тем же путём, не сошли за
# трафик узла. Считать можно только после того, как узел отчитался новым
# поколением: применяет он его асинхронно, и до reload запросы обслуживают
# старые воркеры по старому поколению -- мимо инспектора, если там waf off.
#
# Дым убирает за собой, в том числе после сбоя: путь /smoke и всё, что он завёл
# сам -- апстрим, сервер, порт, объявление ip, -- снимается, и узлу уходит
# поколение без них. Установка после дыма остаётся той, что поставил
# установщик: в панели пользователя тестовым объектам не место. Оставить --
# SMOKE_KEEP=1. Объекты ищутся по имени, так что повторный запуск ничего не
# плодит. JSON разбирает python3 -- jq на машине установки не обещан.
set -eu

CTRL=${1:-http://127.0.0.1:8080}
NODE=${2:-http://127.0.0.1}
BURST=50
PY=$(command -v python3 || command -v python || true)
tmp=$(mktemp)

# Что завёл этот прогон: снимается только оно.
api=""
created_loc=""
created_srv=""
created_port=""
created_ups=""
declared_ip=""

say() { printf '\n== %s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }

# drop <путь> <что> -- DELETE без отказа: уборка не должна прятать причину сбоя.
drop() {
    code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$api$1" || true)

    case "$code" in
        2??) echo "снято: $2" ;;
        *) echo "не снято: $2 ($code)" ;;
    esac
}

cleanup() {
    rm -f "$tmp"

    [ "${SMOKE_KEEP:-}" != 1 ] || return 0
    [ -n "$api" ] || return 0
    [ -n "$created_loc$created_srv$created_port$created_ups$declared_ip" ] || return 0

    say "уборка: снимаю то, что завёл дым"

    [ -z "$created_loc" ] || drop "/locations/$created_loc" "путь /smoke"
    [ -z "$created_srv" ] || drop "/servers/$created_srv" "сервер smoke.local"
    [ -z "$created_port" ] || drop "/ports/$created_port" "порт 8080"
    [ -z "$created_ups" ] || drop "/upstreams/$created_ups" "апстрим smoke-controller"

    if [ -n "$declared_ip" ]; then
        "$PY" - "$api" <<'EOF' || echo "не снято: объявление ip"
import json
import sys
import urllib.request

api = sys.argv[1]


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(api + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read() or b"null")


doc = call("GET", "/http")
waf = dict(doc.get("waf") or {})
declared = dict(waf.get("inspectors") or {})
declared.pop("ip", None)
body = {k: doc.get(k) for k in ("nginx_main", "nginx", "waf_http", "raw", "raw_nginx")}
body["waf"] = {**waf, "inspectors": declared}
call("PUT", "/http", body)
print("снято: объявление ip")
EOF
    fi

    # Уборка кончается, когда узел применил поколение без дыма: следующий шаг
    # (./stand.sh check) иначе застал бы канал nginx посреди применения.
    out=$(curl -s -X POST "$api/config/send" || true)
    hash=$(printf '%s' "$out" | "$PY" -c 'import json, sys; print(json.load(sys.stdin).get("config_hash", ""))' 2>/dev/null || true)

    if [ -z "$hash" ]; then
        echo "поколение без дыма не разослано: $out"
        return 0
    fi

    i=0
    while [ "$(applied "$hash")" != ok ]; do
        i=$((i + 1))
        if [ $i -ge 30 ]; then
            echo "узел не отчитался поколением без дыма за минуту"
            return 0
        fi
        sleep 2
    done
    echo "узел применил поколение без дыма"
}

trap cleanup EXIT

[ -n "$PY" ] || die "нужен python3: им разбирается JSON ответов"

# json <выражение> -- значение выражения над разобранным stdin (d).
json() { "$PY" -c "import json, sys; d = json.load(sys.stdin); print($1)"; }

# send <метод> <путь> [тело] -- запрос к API пространства; не 2xx -- отказ с
# телом ответа, в нём контроллер называет причину.
send() {
    if [ $# -ge 3 ]; then
        code=$(curl -sS -o "$tmp" -w '%{http_code}' -X "$1" "$api$2" \
            -H 'Content-Type: application/json' -d "$3" || true)
    else
        code=$(curl -sS -o "$tmp" -w '%{http_code}' -X "$1" "$api$2" || true)
    fi

    case "$code" in
        2??) cat "$tmp" ;;
        *) die "$1 $2 -> $code: $(cat "$tmp")" ;;
    esac
}

# applied <хеш> -- ok, если все ноды отчитались в пульсе этим поколением и
# применили его; иначе -- что у каждой.
applied() {
    curl -fsS "$CTRL/api/fleet" | "$PY" -c '
import json, sys

want = sys.argv[1]
nodes = json.load(sys.stdin).get("agents", [])

if not nodes:
    print("нет нод")
elif all(a["health"].get("config_hash") == want and a.get("apply") == "ok" for a in nodes):
    print("ok")
else:
    print(", ".join("%s: %s %s" % (a["health"].get("node_id"), a.get("apply"), a["health"].get("config_hash"))
                    for a in nodes))
' "$1"
}

# accepted -- сколько сообщений приняли все реплики инспектора ip.
accepted() {
    curl -fsS "$CTRL/api/fleet" |
        json 'sum((i.get("work") or {}).get("accepted", 0) for i in d.get("inspectors", []) if i["name"] == "ip")'
}

say "панель"
code=$(curl -s -o /dev/null -w '%{http_code}' "$CTRL/healthz" || true)
[ "$code" = 200 ] || die "панель не отвечает: $CTRL/healthz -> $code"
health=$(curl -fsS "$CTRL/api/health" | json '"ok" if d.get("db") else d')
[ "$health" = ok ] || die "панель без базы: $health"
echo "панель и база: ok"

say "пространство default"
out=$(curl -fsS "$CTRL/api/spaces")
scope=$(printf '%s' "$out" | json 'next(s["uuid"] for s in d["spaces"] if s["name"] == "default")')
api=$CTRL/api/$scope
echo "$scope"

say "инспектор ip объявлен на пространстве"
declared=$("$PY" - "$api" <<'EOF'
import json
import sys
import urllib.request

api = sys.argv[1]


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(api + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read() or b"null")


doc = call("GET", "/http")
waf = dict(doc.get("waf") or {})
declared = dict(waf.get("inspectors") or {})

if "ip" in declared:
    print("уже объявлен")
else:
    declared["ip"] = {}
    body = {k: doc.get(k) for k in ("nginx_main", "nginx", "waf_http", "raw", "raw_nginx")}
    body["waf"] = {**waf, "inspectors": declared}
    saved = call("PUT", "/http", body)
    print("объявлены:", ", ".join(sorted(saved["waf"]["inspectors"])))
EOF
)
echo "$declared"
case "$declared" in объявлены*) declared_ip=1 ;; esac

say "апстрим smoke-controller: controller:8080"
out=$(send GET /upstreams)
ups=$(printf '%s' "$out" |
    json 'next((u["uuid"] for u in (d.get("upstreams", []) if isinstance(d, dict) else d) if u["name"] == "smoke-controller"), "")')
if [ -z "$ups" ]; then
    out=$(send POST /upstreams \
        '{"name":"smoke-controller","method":"round_robin","peers":[{"host":"controller","port":8080,"weight":1}]}')
    ups=$(printf '%s' "$out" | json 'd["uuid"]')
    created_ups=$ups
fi
echo "$ups"

say "сервер smoke.local на порту узла 8080"
out=$(send GET /servers)
srv=$(printf '%s' "$out" | json 'next((s["uuid"] for s in d.get("servers", []) if s["name"] == "smoke.local"), "")')
if [ -z "$srv" ]; then
    out=$(send POST /servers '{"name":"smoke.local","server_names":["smoke.local"],"enabled":true}')
    srv=$(printf '%s' "$out" | json 'd["uuid"]')
    created_srv=$srv
fi

out=$(send GET /ports)
port=$(printf '%s' "$out" | json 'next((p["uuid"] for p in d.get("ports", []) if p["port"] == 8080), "")')
if [ -z "$port" ]; then
    out=$(send POST /ports \
        '{"name":"http-8080","address":"0.0.0.0","port":8080,"ssl":false,"http2":false,"proxy_protocol":false}')
    port=$(printf '%s' "$out" | json 'd["uuid"]')
    created_port=$port
fi

out=$(send GET "/servers/$srv/ports")
bound=$(printf '%s' "$out" | json 'len(d.get("listens", []))')
if [ "$bound" = 0 ]; then
    # default_server не берём: на живом контуре он принадлежит оператору.
    send POST "/servers/$srv/ports" "{\"port_id\":\"$port\",\"default_server\":false}" >/dev/null
fi
echo "server=$srv port=$port"

say "путь /smoke: waf on, прокси на /healthz контроллера под инспектором ip"
out=$(send GET "/servers/$srv/locations")
stale=$(printf '%s' "$out" | json '" ".join(l["uuid"] for l in d.get("locations", []) if l.get("path") == "/smoke")')
for u in $stale; do
    send DELETE "/locations/$u" >/dev/null
done
out=$(send POST "/servers/$srv/locations" "{
  \"match\": \"exact\", \"path\": \"/smoke\", \"upstream_id\": \"$ups\", \"upstream_uri\": \"/healthz\",
  \"nginx\": {}, \"position\": 10, \"enabled\": true, \"handler\": \"proxy\", \"protocol\": \"http\",
  \"return_status\": null, \"return_page\": null, \"return_url\": null, \"raw\": false, \"raw_nginx\": \"\",
  \"waf\": {\"enabled\": true, \"localChecks\": [], \"requestInspectors\": [{\"name\": \"ip\", \"wave\": 0}],
          \"responseInspectors\": \"none\", \"scoreDeny\": {\"threshold\": 50, \"response\": \"suspicious\"},
          \"preview\": [\"request headers=2k/256 args=512\"]}
}")
created_loc=$(printf '%s' "$out" | json 'd["uuid"]')
echo "location=$created_loc"

say "«Разослать» и узел применил поколение"
out=$(send POST /config/send)
hash=$(printf '%s' "$out" | json 'd["config_hash"]')
echo "rev $(printf '%s' "$out" | json 'd.get("rev")'): $hash"

i=0
while :; do
    state=$(applied "$hash")
    [ "$state" = ok ] && break
    i=$((i + 1))
    [ $i -lt 30 ] || die "узел не отчитался поколением за минуту: $state"
    sleep 2
done
echo "узел отчитался этим поколением, apply ok"

say "запрос через узел"
i=0
while :; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: smoke.local' "$NODE/smoke" || true)
    [ "$code" = 200 ] && break
    i=$((i + 1))
    [ $i -lt 30 ] || die "узел не отдал 200 за минуту: последний код $code"
    sleep 2
done
echo "GET $NODE/smoke (Host: smoke.local) -> 200"

say "инспектор ip принял запросы узла"
before=$(accepted)
n=0
while [ $n -lt $BURST ]; do
    curl -s -o /dev/null -H 'Host: smoke.local' "$NODE/smoke" || true
    n=$((n + 1))
done
i=0
while :; do
    after=$(accepted)
    [ "$after" -ge $((before + BURST)) ] && break
    i=$((i + 1))
    [ $i -lt 15 ] || die "инспектор ip не видел запросов узла: accepted $before -> $after на $BURST запросов"
    sleep 2
done
echo "accepted у ip: $before -> $after на $BURST запросов"

say "флот"
out=$(curl -fsS "$CTRL/api/fleet")
printf '%s' "$out" | "$PY" -c '
import json, sys

d = json.load(sys.stdin)
nodes = d.get("agents", [])
print("ноды:", ", ".join("%s (%s, сборка %s)" % (a["health"].get("node_id"), a.get("apply"), a["health"].get("version"))
                        for a in nodes) or "нет")
for key, title in (("inspectors", "инспекторы"), ("services", "сервисы"), ("stores", "хранилища")):
    rows = d.get(key, [])
    names = sorted(set("%s %s" % (r.get("name"), r.get("version") or "?") for r in rows))
    print("%s (%d): %s" % (title, len(rows), ", ".join(names)))
'
nodes=$(printf '%s' "$out" | json 'len(d.get("agents", []))')
[ "$nodes" -gt 0 ] || die "во флоте нет ни одной ноды"

echo
echo "дым прошёл"
