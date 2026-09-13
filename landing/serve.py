"""Локальный просмотр лендинга.

`landing/index.html` — фрагмент страницы: так его требует публикация артефактом
(обёртку `<!doctype html>…<head>` добавляет она сама). Чтобы посмотреть то же
самое локально, этот сервер надевает на фрагмент обёртку из `shell.html` —
ту же самую, что кладёт в сборку `build.mjs`.

    python landing/serve.py [порт]      # по умолчанию 4180
"""

import sys
from functools import partial
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4180

# Обёртку берём из shell.html — тот же файл кладёт в сборку build.mjs,
# чтобы локальный просмотр и боевая страница не разъезжались. Читаем на каждый
# запрос: правку обёртки видно по F5, перезапуск не нужен.
MARK = "<!--landing:body-->"


def page() -> bytes:
    head, tail = (ROOT / "shell.html").read_text(encoding="utf-8").split(MARK, 1)
    body = (ROOT / "index.html").read_text(encoding="utf-8")
    return (head + body + tail).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        # Проверка живости от панели браузера ходит методом HEAD.
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if path in ("/", "/index.html"):
            body = page()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        # Значок вкладки и проба devtools: отвечаем пусто, без шума в логе.
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def handle_one_request(self):
        # Браузер закрывает соединение первым — это не ошибка сервера.
        try:
            super().handle_one_request()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    def log_message(self, fmt, *args):
        sys.stdout.write("%s %s\n" % (self.address_string(), fmt % args))
        sys.stdout.flush()


if __name__ == "__main__":
    print(f"landing: http://127.0.0.1:{PORT}/", flush=True)
    # Потоками, а не по одному: браузер держит keep-alive, и однопоточный
    # сервер на такой висящей связи перестаёт отвечать всем остальным.
    server = ThreadingHTTPServer(("127.0.0.1", PORT), partial(Handler))
    server.daemon_threads = True
    server.serve_forever()
