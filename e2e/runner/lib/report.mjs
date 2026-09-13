/**
 * Отчёт по фазам. Каждая фаза копит проверки ok/FAIL — тот же стиль, что в
 * текущих tests/*.sh, но со структурой: фаза знает свою длительность и свой
 * счёт, а не тонет в общем потоке echo.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

function safeDetails(details) {
  if (details === undefined || details === null) {
    return "";
  }

  if (typeof details === "string") {
    return details;
  }

  try {
    return JSON.stringify(details);
  } catch {
    return String(details);
  }
}

export class Report {
  constructor(name, runId) {
    this.name = name;
    this.runId = runId;
    this.startedAt = new Date();
    this.phases = [];
    this.current = null;
  }

  /** Открывает фазу и возвращает объект с check()/note() для неё. */
  phase(title) {
    if (this.current !== null) {
      this._closeCurrent();
    }

    this.current = {
      name: title,
      checks: [],
      notes: [],
      startedAt: Date.now(),
      durationMs: 0,
    };
    this.phases.push(this.current);

    process.stdout.write(`\n--- ${title} ---\n`);

    return {
      check: (label, ok, details) => this.check(label, ok, details),
      note: (text) => this.note(text),
    };
  }

  check(label, ok, details) {
    if (this.current === null) {
      throw new Error(`report: check("${label}") вне фазы`);
    }

    this.current.checks.push({ label, ok, details: details ?? null });

    const rendered = safeDetails(details);

    process.stdout.write(
      `${ok ? "ok  " : "FAIL"} ${label}${rendered ? "  " + rendered : ""}\n`,
    );

    return ok;
  }

  note(text) {
    if (this.current !== null) {
      this.current.notes.push(text);
    }

    process.stdout.write(`     ${text}\n`);
  }

  _closeCurrent() {
    if (this.current !== null) {
      this.current.durationMs = Date.now() - this.current.startedAt;
    }
  }

  /** Оборачивает фазу так, что необработанное исключение становится FAIL, а не обвалом процесса. */
  async run(title, fn) {
    const p = this.phase(title);

    try {
      await fn(p);
    } catch (err) {
      p.check(`${title}: без необработанной ошибки`, false, {
        error: err instanceof Error ? err.message : String(err),
      });
    }

    return p;
  }

  finish() {
    this._closeCurrent();
    this.finishedAt = new Date();
  }

  summary() {
    let passed = 0;
    let failed = 0;

    for (const phase of this.phases) {
      for (const c of phase.checks) {
        if (c.ok) {
          passed += 1;
        } else {
          failed += 1;
        }
      }
    }

    return { passed, failed, total: passed + failed };
  }

  toJSON() {
    const { passed, failed, total } = this.summary();

    return {
      name: this.name,
      run_id: this.runId,
      started_at: this.startedAt.toISOString(),
      finished_at: (this.finishedAt ?? new Date()).toISOString(),
      summary: { passed, failed, total },
      phases: this.phases.map((p) => ({
        name: p.name,
        duration_ms: p.durationMs,
        checks: p.checks,
        notes: p.notes,
      })),
    };
  }

  printText() {
    const { passed, failed, total } = this.summary();

    process.stdout.write(`\n=== ${this.name} (run ${this.runId}) ===\n`);

    for (const phase of this.phases) {
      const phaseFailed = phase.checks.filter((c) => !c.ok).length;
      process.stdout.write(
        `  ${phaseFailed === 0 ? "ok  " : "FAIL"} ${phase.name}` +
          ` (${phase.checks.length} проверок, ${phase.durationMs}ms)\n`,
      );
    }

    process.stdout.write(`\nитого: ${passed}/${total} пройдено`);
    process.stdout.write(failed === 0 ? ", всё ок\n" : `, провалено ${failed}\n`);
  }

  async writeFiles(dir) {
    await mkdir(dir, { recursive: true });

    const stamp = this.startedAt.toISOString().replace(/[:.]/g, "-");
    const base = join(dir, `${this.name}-${stamp}`);
    const data = this.toJSON();

    await writeFile(`${base}.json`, JSON.stringify(data, null, 2) + "\n", "utf8");
    await writeFile(`${base}.txt`, renderText(data), "utf8");

    return { json: `${base}.json`, txt: `${base}.txt` };
  }
}

function renderText(data) {
  const lines = [];

  lines.push(`${data.name} — run ${data.run_id}`);
  lines.push(`${data.started_at} .. ${data.finished_at}`);
  lines.push("");

  for (const phase of data.phases) {
    lines.push(`--- ${phase.name} (${phase.duration_ms}ms) ---`);

    for (const c of phase.checks) {
      const details = c.ok
        ? ""
        : "  " + (typeof c.details === "string" ? c.details : JSON.stringify(c.details));
      lines.push(`${c.ok ? "ok  " : "FAIL"} ${c.label}${details}`);
    }

    for (const note of phase.notes) {
      lines.push(`     ${note}`);
    }

    lines.push("");
  }

  lines.push(
    `итого: ${data.summary.passed}/${data.summary.total} пройдено, провалено ${data.summary.failed}`,
  );

  return lines.join("\n") + "\n";
}
