# waf_hold

Держим ли мы то, что инспектируем, до вердикта. Кого спрашиваем —
[inspect.md](inspect.md), сколько ждём — [deadline.md](deadline.md).

Фаза — первое слово. У кадров направление в том же слове:
`frame:c2s` — от клиента, `frame:s2c` — к клиенту, `frame` — оба.

```
waf_hold request|response|frame|frame:c2s|frame:s2c gate|monitor;
```

Контекст: `http`, `server`, `location`, наследуемая.
Умолчание: `gate`. Нет строки `response` / `frame` — берёт `request`.

На фазе ответа обе величины работают. На кадрах пока только `gate`:
`monitor` для `frame` / `frame:c2s` / `frame:s2c` `nginx -t` отвергает
(«monitor on frames is not implemented yet»), обе стороны держатся до
вердикта.

`gate` — байт не уходит получателю, пока фаза не закрылась. Отказ
успевает стать страницей каталога или Close-кадром.

`monitor` — уходит сразу, волны идут вслед. `deny` тогда не
отменяет отправленное: он обрывает поток и пишет аудит. Защита
работает как «прекратить», а не «не пропустить».

```nginx
http {
    waf_hold response gate;
    waf_hold frame    gate;      # обе стороны кадра

    location /api/ {
        waf_capture response headers=8k body=64k;
        waf_inspect response dlp wave=0 timeout=20ms;
    }

    location /events/ {           # text/event-stream
        waf_hold response monitor;
        waf_inspect response dlp wave=0 timeout=20ms;
    }

    location /ws/ {
        waf_hold frame:s2c monitor;   # ЗАДУМАНО: частая выдача, не держим;
                                      # c2s остаётся gate от http.
                                      # Сегодня строка не проходит nginx -t.
    }
}
```

# цена

| | |
| --- | --- |
| `gate` на ответе | латентность ответа растёт на дедлайн фазы; память — размер `waf_capture response body=` на каждый удерживаемый ответ |
| `gate` на кадрах | порядок обязан сохраняться, поэтому в направлении соединения один вердикт за раз: потолок пропускной способности — обратная величина RTT |
| `monitor` | латентности не добавляет, но `deny` приходит после доставки |

Держим ровно то, что снимаем: потолок удержания — размер
[waf_capture](capture.md) этой фазы, отдельной директивы под буфер
нет. Что за размером снимка — уходит потоком уже после вердикта.

# правила

- нет фазы — `nginx -t`
- `frame` задаёт оба направления. `frame` и `frame:s2c` на одном
  уровне — `nginx -t`, слот уже задан
- `waf_hold request monitor` — `nginx -t`. Наблюдение без гейта на
  запросе — это `mode=passive` у инспектора, а не отпущенный запрос
- `gate` держит ровно до предела [waf_body_limit](body_limit.md) этой
  фазы. Ответ, переваливший предел раньше вердикта, отпускается, и в
  лог уходит предупреждение: молча превратить `gate` в `monitor`
  нельзя — это разница между «не пропустил» и «не успел»
- апгрейд (`101`) фаза ответа не трогает вовсе: это фаза кадров
- `monitor` на ответе: `deny` не рисует страницу, а обрывает тело
- `monitor` на кадрах: `deny` закрывает соединение формой протокола
  ([deny_response.md](deny_response.md))
- `waf_frame_mode` / `waf_frame_mode_c2s` / `waf_response_buffer_max`
  — `nginx -t`

#TEST waf_hold gate без фазы — nginx -t
#TEST waf_hold request monitor — nginx -t
#TEST waf_frame_mode gate — nginx -t
#TEST waf_hold response monitor: заголовки ушли до вердикта, deny оборвал тело
#TEST waf_hold response gate: при deny клиент не получил ни байта тела приложения
#TEST нет строки response: держим как request
#TEST waf_hold frame gate выше + frame:s2c monitor на location — c2s держим, s2c нет
#TEST waf_hold frame gate и frame:s2c monitor на одном уровне — nginx -t
