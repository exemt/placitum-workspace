/*
 * Журнал строками JSON в stdout: его читает docker logs, и он же -- то, с чем
 * сверяют вердикт контура. Никакой ротации и файлов: контейнер живёт в compose.
 */

type Level = "debug" | "info" | "warn" | "error";

const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

let threshold = ORDER.info;

export function setLevel(name: string): void {
  const level = name as Level;

  if (level in ORDER) {
    threshold = ORDER[level];
  }
}

export function log(level: Level, msg: string, fields: Record<string, unknown> = {}): void {
  if (ORDER[level] < threshold) {
    return;
  }

  process.stdout.write(
    `${JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields })}\n`,
  );
}
