#!/bin/sh
# Капча на живом контуре: лестница вердикта, страница виджета, картинка,
# клиренс, заголовок приложению, одноразовость ответа, режим наблюдения.
#
#     docker compose up -d --wait
#     sh tests/captcha/captcha.sh
#
# Гоняется с хоста; ходовая часть -- внутри nats-box, чтобы банка cookie
# пережила сценарий. Ответ картинки сценарий подглядывает в Redis
# (cap:img:<nonce>): браузера в контуре нет. Отсюда несколько заходов в
# nats-box: банка и счёт провалов между ними лежат в /tmp контейнера.

set -eu

# docker compose exec с хоста под MSYS: иначе /dev/null уезжает в путь Windows.
export MSYS_NO_PATHCONV=1

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT/deploy"

clean() {
    docker compose exec -T redis sh -c "
        redis-cli --scan --pattern 'cap:ban:*'    | xargs -r redis-cli del
        redis-cli --scan --pattern 'cap:fail:*'   | xargs -r redis-cli del
        redis-cli --scan --pattern 'cap:issue:*'  | xargs -r redis-cli del
        redis-cli --scan --pattern 'cap:verify:*' | xargs -r redis-cli del
        redis-cli --scan --pattern 'cap:nonce:*'  | xargs -r redis-cli del
        redis-cli --scan --pattern 'cap:img:*'    | xargs -r redis-cli del
        redis-cli --scan --pattern 'cap:bkt:*'    | xargs -r redis-cli del
    " > /dev/null 2>&1 || true
}

trap clean EXIT INT TERM

clean

# Общая часть обоих заходов: проверки и доступ к краю.
LIB='
fail=0
# Рига nginx-1 с маршрутами капчи на стенде не поднимается: маршрутов капчи у
# стенда нет. Без неё прогон не о чем -- пропуск, а не ложный FAIL.
if ! docker compose ps --services 2>/dev/null | grep -qx nginx-1; then
    echo "skip: рига nginx-1 не поднята, маршрутов капчи на стенде нет"
    exit 0
fi

BASE=http://nginx-1:8080
J=/tmp/captcha-jar

check() {
    want=$1; name=$2; got=$3
    if [ "$got" = "$want" ]; then
        printf "ok   %-44s %s\n" "$name" "$got"
    else
        printf "FAIL %-44s %s, ожидался %s\n" "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

status() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

# Решение видно в диагностическом заголовке модуля:
# X-WAF-Debug: ... captcha-login=<вердикт>/<код>/...
gate() {
    curl -s -o /dev/null -D - "$@" \
        | tr " " "\n" | sed -n "s/^captcha[a-z-]*=//p" | head -1 | cut -d/ -f1,2 | tr -d "\r"
}
'

echo "--- лестница вердикта ---"

docker compose exec -T nats-box sh -s <<BOXED
$LIB
check 303 'навигационный GET без клиренса' \
    "\$(status -H 'Accept: text/html' \$BASE/captcha/echo)"
check 403 'POST без клиренса' \
    "\$(status -X POST -d x=1 -H 'Accept: text/html' \$BASE/captcha/echo)"
check 403 'XHR без text/html в Accept' \
    "\$(status -H 'Accept: application/json' \$BASE/captcha/echo)"
check 'redirect/CAPTCHA_REQUIRED' 'инспектор: redirect с кодом' \
    "\$(gate -H 'Accept: text/html' \$BASE/captcha/echo)"
check 200 'наблюдение пропускает' \
    "\$(status -H 'Accept: text/html' \$BASE/captcha-observe/echo)"
check 'allow/CAPTCHA_NOT_REQUIRED' 'наблюдение: порог не взят -- не требуется' \
    "\$(gate -H 'Accept: text/html' \$BASE/captcha-observe/echo)"

loc=\$(curl -s -o /dev/null -D - -H 'Accept: text/html' "\$BASE/captcha/echo?page=2" \
      | sed -n 's/^[Ll]ocation: //p' | tr -d '\r')
case "\$loc" in
    */waf/captcha\?rd=%2Fcaptcha%2Fecho%3Fpage%3D2) echo "ok   редирект несёт возврат вместе с query" ;;
    *) echo "FAIL редирект несёт возврат: \$loc"; fail=\$((fail + 1)) ;;
esac

echo
echo "--- виджет ---"

rm -f \$J
check 403 'страница без билета -- 403' \
    "\$(status -c \$J -b \$J -H 'Accept: text/html' \$BASE/waf/captcha)"

# Билет приезжает с 303; страница его требует.
curl -s -o /dev/null -c \$J -b \$J -H 'Accept: text/html' \$BASE/captcha/echo
curl -s -c \$J -b \$J -H 'Accept: text/html' "\$BASE/waf/captcha?rd=%2Fcaptcha%2Fecho" > /tmp/captcha-page

nonce=\$(sed -n 's/.*name="csrf" value="\([a-f0-9]*\)".*/\1/p' /tmp/captcha-page | head -1)
[ -n "\$nonce" ] && echo "ok   nonce билета на странице" \
    || { echo "FAIL nonce не найден"; fail=\$((fail + 1)); }
grep -q 'data-kind="image" data-primary="1"' /tmp/captcha-page \
    && echo "ok   первый виджет -- картинка" \
    || { echo "FAIL первый виджет не картинка"; fail=\$((fail + 1)); }
grep -q 'src="data:image/png;base64,' /tmp/captcha-page \
    && echo "ok   картинка встроена без JS" \
    || { echo "FAIL картинка не встроена"; fail=\$((fail + 1)); }
printf '%s\n' "\$nonce" > /tmp/captcha-nonce
[ "\$fail" -eq 0 ]
BOXED

# Ответ картинки лежит в Redis под nonce билета: браузера в контуре нет,
# сценарий подглядывает как оператор.
nonce=$(docker compose exec -T nats-box cat /tmp/captcha-nonce | tr -d '\r')
answer=$(docker compose exec -T redis redis-cli --raw get "cap:img:$nonce" | tr -d '\r\n')
echo "     image: answer=$answer"

docker compose exec -T nats-box sh -s "$nonce" "$answer" <<BOXED
$LIB
nonce=\$1; answer=\$2

check 400 'неверные символы -- страница снова' \
    "\$(status -c \$J -b \$J -X POST --data-urlencode "csrf=\$nonce" -d answer_image=NOPE \$BASE/waf/captcha)"
# Промах перерисовал картинку: прежний текст уже не принимается.
check 400 'после промаха прежний ответ не принимается' \
    "\$(status -c \$J -b \$J -X POST --data-urlencode "csrf=\$nonce" -d "answer_image=\$answer" \$BASE/waf/captcha)"
printf '%s\n' "\$fail" > /tmp/captcha-fail
BOXED

answer=$(docker compose exec -T redis redis-cli --raw get "cap:img:$nonce" | tr -d '\r\n')

docker compose exec -T nats-box sh -s "$nonce" "$answer" <<BOXED
$LIB
fail=\$(cat /tmp/captcha-fail)
nonce=\$1; answer=\$2

check 303 'верные символы (регистр не важен) -- клиренс' \
    "\$(status -c \$J -b \$J -X POST --data-urlencode "csrf=\$nonce" -d "answer_image=\$(echo \$answer | tr A-Z a-z)" \$BASE/waf/captcha)"
check 403 'повтор того же ответа: страница без билета' \
    "\$(status -c \$J -b \$J -X POST --data-urlencode "csrf=\$nonce" -d "answer_image=\$answer" \$BASE/waf/captcha)"

echo
echo "--- с клиренсом ---"

check 200 'навигационный GET проходит' \
    "\$(status -b \$J -H 'Accept: text/html' \$BASE/captcha/echo)"
check 'allow/CAPTCHA_OK' 'инспектор: allow' \
    "\$(gate -b \$J -H 'Accept: text/html' \$BASE/captcha/echo)"
check 200 'POST проходит' \
    "\$(status -b \$J -X POST -d x=1 \$BASE/captcha/echo)"

seen=\$(curl -s -b \$J -H 'X-WAF-Captcha: forged' \$BASE/captcha/echo | tr -d ' \n')
case "\$seen" in
    *'"x-waf-captcha","image"'*) echo "ok   заголовок приложению: провайдер, подделка перезаписана" ;;
    *) echo "FAIL заголовок приложению"; fail=\$((fail + 1)) ;;
esac

check '{"cleared":true' 'status видит клиренс' \
    "\$(curl -s -b \$J \$BASE/waf/captcha/status | cut -c1-15)"

# Область решает профиль маршрута: у observe scope: host, и клиренс, выданный
# профилем login, там зачтён -- код OK, а не NOT_REQUIRED.
check 'allow/CAPTCHA_OK' 'scope host: клиренс другого профиля зачтён' \
    "\$(gate -b \$J -H 'Accept: text/html' \$BASE/captcha-observe/echo)"

printf '%s\n' "\$fail" > /tmp/captcha-fail
BOXED

echo
echo "--- корзины: счёт фазы больше не триггер ---"

# /captcha-score/: modsec скорит, но капча его счёта не читает -- единственная
# её шкала теперь корзины (docs/inspectors/captcha/buckets.md). XSS даёт 100
# баллов и всё равно проходит; на виджет уводит заполнение корзины.
docker compose exec -T nats-box sh -s <<BOXED
$LIB
fail=\$(cat /tmp/captcha-fail)
check 'allow/CAPTCHA_NOT_REQUIRED' 'чистый запрос: не требуется' \
    "\$(gate -H 'Accept: text/html' "\$BASE/captcha-score/echo?q=1")"
check 'allow/CAPTCHA_NOT_REQUIRED' 'XSS: счёт фазы виджета не требует' \
    "\$(gate -H 'Accept: text/html' "\$BASE/captcha-score/echo?q=%3Cscript%3E")"
hostname -i | awk '{print \$1}' > /tmp/captcha-addr
printf '%s\n' "\$fail" > /tmp/captcha-fail
BOXED

# Горячую корзину наполняют соседи просьбами note; отправителя на этом
# маршруте нет, поэтому сценарий кладёт заполнение прямо в контурный Redis --
# ровно то же, что увидел бы инспектор от соседа. Хранение сдвинутое:
# stored = effective + rate*(сейчас - 2024-01-01), rate = loss/100*max
# (у корзины ip профиля default -- 1 ед/с). 70% -- выше captcha_at (60) и
# ниже ban_at (90): виджет требуется, бан не срабатывает.
addr=$(docker compose exec -T nats-box cat /tmp/captcha-addr | tr -d '\r\n')
stored=$(( 70 + $(date -u +%s) - 1704067200 ))
docker compose exec -T redis redis-cli set "cap:bkt:default:ip:$addr/32" "$stored" EX 100 > /dev/null
echo "     корзина ip $addr/32 = 70% ёмкости"

docker compose exec -T nats-box sh -s <<BOXED
$LIB
fail=\$(cat /tmp/captcha-fail)
check 'redirect/CAPTCHA_REQUIRED' 'горячая корзина ip уводит на виджет' \
    "\$(gate -H 'Accept: text/html' "\$BASE/captcha-score/echo?q=1")"

# Отказ с телом из каталога: страницы смонтированы на nginx-1..3.
body=\$(curl -s -X POST -d x=1 -H 'Accept: application/json' "\$BASE/captcha-score/echo?q=1")
case "\$body" in
    *'"error": "captcha_required"'*'"challenge": "/waf/captcha/api"'*) echo "ok   403 с JSON-телом captcha_required" ;;
    *) echo "FAIL тело отказа: \$(echo "\$body" | head -c 120)"; fail=\$((fail + 1)) ;;
esac
printf '%s\n' "\$fail" > /tmp/captcha-fail
BOXED

docker compose exec -T redis redis-cli --scan --pattern 'cap:bkt:*' 2>/dev/null \
    | xargs -r docker compose exec -T redis redis-cli del > /dev/null 2>&1 || true

docker compose exec -T nats-box sh -s <<BOXED
$LIB
fail=\$(cat /tmp/captcha-fail)
check 'allow/CAPTCHA_NOT_REQUIRED' 'корзина остыла -- виджет снова не нужен' \
    "\$(gate -H 'Accept: text/html' "\$BASE/captcha-score/echo?q=1")"

echo
echo "--- SPA: задание и проверка без редиректа ---"

rm -f \$J
# POST без клиренса -> 403, но билет в cookie есть: модуль кладёт cookie и на deny.
check 403 'POST без клиренса: отказ' \
    "\$(status -c \$J -b \$J -X POST -d x=1 \$BASE/captcha/echo)"
api=\$(curl -s -c \$J -b \$J \$BASE/waf/captcha/api)
nonce=\$(echo "\$api" | sed -n 's/.*"nonce":"\([a-f0-9]*\)".*/\1/p')
[ -n "\$nonce" ] && echo "ok   /api отдаёт задание по билету с deny" \
    || { echo "FAIL /api без nonce: \$(echo "\$api" | head -c 120)"; fail=\$((fail + 1)); }
case "\$api" in
    *'"kind":"image"'*) echo "ok   /api несёт виджет картинки" ;;
    *) echo "FAIL /api без картинки"; fail=\$((fail + 1)) ;;
esac
printf '%s\n' "\$nonce" > /tmp/captcha-nonce
printf '%s\n' "\$fail" > /tmp/captcha-fail
BOXED

nonce=$(docker compose exec -T nats-box cat /tmp/captcha-nonce | tr -d '\r')
answer=$(docker compose exec -T redis redis-cli --raw get "cap:img:$nonce" | tr -d '\r\n')

docker compose exec -T nats-box sh -s "$nonce" "$answer" <<BOXED
$LIB
fail=\$(cat /tmp/captcha-fail)
nonce=\$1; answer=\$2
check 204 '/verify принимает JSON и выдаёт клиренс' \
    "\$(status -c \$J -b \$J -X POST -H 'Content-Type: application/json' \
        -d "{\"nonce\":\"\$nonce\",\"provider\":\"image\",\"answer\":\"\$answer\"}" \$BASE/waf/captcha/verify)"
check 200 'повтор исходного POST проходит' \
    "\$(status -b \$J -X POST -d x=1 \$BASE/captcha/echo)"

echo
echo "--- быстрый путь и лимит по клиренсу ---"

# waf_cid в cap_cleared: контроллер принял .event и переиздал набор. Ждём
# переиздания, потом на /captcha-fast/ инспектора не спрашивают вовсе.
i=0
while [ \$i -lt 20 ]; do
    g=\$(gate -b \$J -H 'Accept: text/html' \$BASE/captcha-fast/echo)
    [ -z "\$g" ] && break
    i=\$((i + 1)); sleep 1
done
check '' 'быстрый путь: капчу не спрашивают' "\$g"
check 200 'быстрый путь: приложение отвечает' \
    "\$(status -b \$J -H 'Accept: text/html' \$BASE/captcha-fast/echo)"

# Лимит 5r/s burst=5 по cid: пачка из 20 запросов упирается в 429, а
# превысивший попадает в cap_banned -- следующий запрос режет локальный слой.
codes=\$(for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do status -b \$J \$BASE/captcha-fast/echo; echo; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')
case "\$codes" in
    *429*) echo "ok   лимит по клиренсу срабатывает: \$codes" ;;
    *) echo "FAIL лимита нет: \$codes"; fail=\$((fail + 1)) ;;
esac
sleep 2
check 429 'после превышения -- бан через cap_banned' \
    "\$(status -b \$J \$BASE/captcha-fast/echo)"

rm -f \$J
check 303 'без клиренса быстрый путь спрашивает капчу' \
    "\$(status -H 'Accept: text/html' \$BASE/captcha-fast/echo)"

echo
if [ "\$fail" -ne 0 ]; then
    echo "провалено: \$fail"
    exit 1
fi
echo "все проверки прошли"
BOXED
