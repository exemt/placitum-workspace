/*
 * Замок на стенд: два прогона одновременно ходить не могут.
 *
 * Стенд один, и сущности у прогонов пересекаются по общим документам --
 * реестру объявлений инспекторов и каналам. Два прогона разом читают и пишут
 * один и тот же документ, теряют правки друг друга, и падение выглядит как
 * поломка продукта: «маршрут зовёт необъявленного инспектора», «набор
 * недоступен». Проверено 10.09.2026 -- ровно так и вышло.
 *
 * Замок -- файл в системном temp с номером процесса. Мёртвый номер не держит:
 * прогон, убитый по Ctrl+C, не должен запирать стенд навсегда.
 */

import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const FILE = join(tmpdir(), "waf-e2e-stand.lock");

function alive(pid) {
  try {
    /* Сигнал 0 ничего не шлёт, только проверяет право и наличие процесса. */
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === "EPERM";
  }
}

/** Занять стенд. Возвращает функцию освобождения. */
export function lockStand() {
  try {
    const row = JSON.parse(readFileSync(FILE, "utf8"));

    if (alive(row.pid)) {
      throw new Error(
        `стенд занят прогоном ${row.what} (pid ${row.pid}, с ${row.at}). ` +
          "Два прогона разом теряют правки общих документов, поэтому второй не запускается. " +
          `Если тот прогон точно мёртв -- удалите ${FILE}.`,
      );
    }
  } catch (err) {
    if (err.message.startsWith("стенд занят")) {
      throw err;
    }
    /* Файла нет или он битый -- значит, свободно. */
  }

  writeFileSync(
    FILE,
    JSON.stringify({ pid: process.pid, what: process.argv[1] ?? "e2e", at: new Date().toISOString() }),
  );

  let released = false;
  const release = () => {
    if (released) {
      return;
    }
    released = true;
    try {
      rmSync(FILE, { force: true });
    } catch {
      /* уже убран */
    }
  };

  process.on("exit", release);
  process.on("SIGINT", () => {
    release();
    process.exit(130);
  });

  return release;
}
