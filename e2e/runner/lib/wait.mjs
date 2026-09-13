/**
 * Поллинг до сходимости — то же, что делает wait_code в tests/lists/lists.sh,
 * но переиспользуемо: контроллер применяет конфигурацию асинхронно (KV +
 * такт цикла инспектора), поэтому "не сошлось за один опрос" — норма, а не
 * ошибка.
 */

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * @param {() => Promise<{ok: boolean} & Record<string, unknown>>} fn
 * @param {{timeoutMs?: number, intervalMs?: number}} [opts]
 */
export async function pollUntil(fn, opts = {}) {
  const { timeoutMs = 15_000, intervalMs = 500 } = opts;
  const deadline = Date.now() + timeoutMs;
  let last = { ok: false };

  for (;;) {
    last = await fn();

    if (last.ok) {
      return last;
    }

    if (Date.now() >= deadline) {
      return last;
    }

    await sleep(intervalMs);
  }
}
