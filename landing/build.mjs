// Сборка лендинга под отдачу статикой.
//
// `index.html` — фрагмент: обёртку `<!doctype html>…<head>` подставляет публикация
// артефактом. Здесь ту же обёртку берём из `shell.html` (её же читает serve.py,
// чтобы локальный просмотр и боевая страница не разъезжались) и кладём рядом
// сжатые копии — nginx отдаёт их через gzip_static/brotli_static, на лету не жмёт.
//
//     node landing/build.mjs        # -> landing/dist/
import { readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { gzipSync, brotliCompressSync, constants } from "node:zlib";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const REPO = join(ROOT, "..");
const DIST = join(ROOT, "dist");
const MARK = "<!--landing:body-->";

const shell = readFileSync(join(ROOT, "shell.html"), "utf8");
if (!shell.includes(MARK)) throw new Error(`shell.html: нет метки ${MARK}`);
const page = shell.replace(MARK, readFileSync(join(ROOT, "index.html"), "utf8"));

rmSync(DIST, { recursive: true, force: true });
mkdirSync(DIST, { recursive: true });

// Сжимаем текст: gzip для старых клиентов, brotli — всем остальным.
const emit = (name, body) => {
  const buf = Buffer.from(body);
  writeFileSync(join(DIST, name), buf);
  const gz = gzipSync(buf, { level: 9 });
  const br = brotliCompressSync(buf, {
    params: {
      [constants.BROTLI_PARAM_QUALITY]: 11,
      [constants.BROTLI_PARAM_SIZE_HINT]: buf.length,
    },
  });
  writeFileSync(join(DIST, `${name}.gz`), gz);
  writeFileSync(join(DIST, `${name}.br`), br);
  const kb = (n) => `${(n / 1024).toFixed(1)} КБ`;
  console.log(`${name.padEnd(14)} ${kb(buf.length).padStart(9)} -> gzip ${kb(gz.length)} / brotli ${kb(br.length)}`);
};

emit("index.html", page);
emit("favicon.svg", readFileSync(join(REPO, "brand", "favicon.svg")));
console.log(`\nготово: ${DIST}`);
