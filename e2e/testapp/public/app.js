/*
 * Клиент сокетов для /socket. Скрипт отдаётся отдельным файлом намеренно:
 * маршрут `\.js$` -- та самая статика, на которой проверяют вызов инспекторов
 * `none` и правила действий по суффиксу пути.
 *
 * На остальных страницах он ничего не делает: элементов чата там нет.
 */

(function () {
  "use strict";

  var chatLog = document.getElementById("chat-log");

  if (!chatLog) {
    return;
  }

  var feedLog = document.getElementById("feed-log");
  var base = (location.protocol === "https:" ? "wss://" : "ws://") + location.host;

  function put(box, line) {
    box.textContent += line + "\n";
    box.scrollTop = box.scrollHeight;
  }

  function describe(data) {
    if (typeof data === "string") {
      return "text " + data;
    }

    return "binary " + (data.byteLength || data.size || 0) + " байт";
  }

  /* --- чат: обе стороны в одном соединении ---------------------------- */

  var chat = new WebSocket(base + "/socket/chat");

  chat.binaryType = "arraybuffer";
  chat.onopen = function () { put(chatLog, "→ соединение открыто"); };
  chat.onclose = function (e) { put(chatLog, "× закрыто, код " + e.code); };
  chat.onerror = function () { put(chatLog, "× ошибка соединения"); };
  chat.onmessage = function (e) { put(chatLog, "← " + describe(e.data)); };

  document.getElementById("chat-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var text = document.getElementById("chat-text").value;
    chat.send(text);
    put(chatLog, "→ " + text);
  });

  document.getElementById("chat-binary").addEventListener("click", function () {
    var bytes = new Uint8Array(32);
    for (var i = 0; i < bytes.length; i++) { bytes[i] = i; }
    chat.send(bytes);
    put(chatLog, "→ binary 32 байта");
  });

  document.getElementById("chat-big").addEventListener("click", function () {
    var payload = JSON.stringify({ type: "say", text: new Array(64 * 1024).join("x") });
    chat.send(payload);
    put(chatLog, "→ крупный кадр, " + payload.length + " байт");
  });

  /* Две отправки подряд: между волнами у ключа подмены разный rid. */
  document.getElementById("chat-split").addEventListener("click", function () {
    chat.send(JSON.stringify({ type: "say", text: "первый" }));
    chat.send(JSON.stringify({ type: "say", text: "второй" }));
    put(chatLog, "→ два кадра подряд");
  });

  /* --- поток: сервер шлёт сам ----------------------------------------- */

  var feed = new WebSocket(base + "/socket/feed");

  feed.onopen = function () { put(feedLog, "→ поток открыт, клиент молчит"); };
  feed.onclose = function (e) { put(feedLog, "× закрыто, код " + e.code); };
  feed.onmessage = function (e) { put(feedLog, "← " + e.data); };
})();
