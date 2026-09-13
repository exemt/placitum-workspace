/**
 * Разбор stdout wrk 4.x: сводка самого wrk (запросы, задержки, ошибки сокета)
 * плюс строка `waf-summary: {...}`, которую печатает done() в script.lua --
 * коды ответов, вердикты и fail= модуля, ожидание инспекторов.
 */

/** Единицы длительности из итоговой строки wrk, в секундах. */
const SECONDS_IN = { us: 1e-6, ms: 1e-3, s: 1, m: 60, h: 3600 };

export function parseWrk(log, step) {
  const text = String(log || "");
  /*
   * «56321 requests in 1.00m»: от минуты wrk печатает длительность в минутах,
   * а не в секундах. Единица разбирается вместе с числом -- иначе ступень от
   * минуты давала запросов 0, суд «no_requests» и status=error на прогоне,
   * который прошёл целиком.
   */
  const ran = /(\d+)\s+requests in\s+([\d.]+)(us|ms|s|m|h)\b/.exec(text);
  const reqs = ran === null ? null : Number(ran[1]);
  const seconds = ran === null ? null : Number(ran[2]) * SECONDS_IN[ran[3]];
  const non2xx = num(/Non-2xx or 3xx responses:\s+(\d+)/.exec(text), 1) ?? 0;
  const rate =
    num(/Requests\/sec:\s+([\d.]+)/.exec(text), 1) ??
    (reqs != null && seconds > 0 ? reqs / seconds : null);
  const p50 = ms(/^\s+50%\s+([\d.]+)(\w+)/m.exec(text));
  const p90 = ms(/^\s+90%\s+([\d.]+)(\w+)/m.exec(text));
  const p99 = ms(/^\s+99%\s+([\d.]+)(\w+)/m.exec(text));
  const avg = ms(/Latency\s+([\d.]+)(\w+)/.exec(text));
  const max = thirdLatency(text);
  const timeouts = num(/timeout\s+(\d+)/.exec(text), 1) ?? 0;
  const sockets =
    (num(/connect\s+(\d+)/.exec(text), 1) ?? 0) +
    (num(/read\s+(\d+)/.exec(text), 1) ?? 0) +
    (num(/write\s+(\d+)/.exec(text), 1) ?? 0);
  const threads = num(/(\d+)\s+threads and\s+(\d+)\s+connections/.exec(text), 1);
  const connections = num(/(\d+)\s+threads and\s+(\d+)\s+connections/.exec(text), 2);
  const waf = parseWafSummary(text);

  return {
    step: { rate: step.rate, duration_s: step.duration_s },
    seconds,
    reqs: reqs ?? 0,
    rps: rate,
    latency: { avg, p50, p90, p99, max },
    unexpected: waf?.unexpected ?? non2xx,
    sockets,
    timeouts,
    codes: waf?.codes ?? {},
    waf: waf === null ? null : {
      seen: waf.seen,
      verdicts: waf.verdicts,
      fails: waf.fails,
      none: waf.none,
      wait: waf.wait,
      inspectors: waf.inspectors,
    },
    threads,
    connections,
  };
}

function parseWafSummary(text) {
  const m = /^waf-summary: (\{.*\})\s*$/m.exec(text);

  if (!m) {
    return null;
  }

  try {
    const row = JSON.parse(m[1]);
    return {
      codes: asCounts(row.codes),
      unexpected: Number(row.unexpected) || 0,
      seen: Number(row.seen) || 0,
      verdicts: asCounts(row.verdicts),
      fails: asCounts(row.fails),
      none: Number(row.none) || 0,
      wait: row.wait ?? null,
      inspectors: Array.isArray(row.inspectors) ? row.inspectors : [],
    };
  } catch {
    return null;
  }
}

/** Пустая таблица в Lua печатается как `[]`: в объект. */
function asCounts(raw) {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    return {};
  }
  return raw;
}

/**
 * Итог по ступеням: суммы -- суммами, квантили задержки -- взвешенно по числу
 * запросов ступени (точнее нет: у wrk только квантили, не гистограмма).
 */
export function mergeWrk(rows, planSec, connections) {
  const out = {
    reqs: 0,
    rps: null,
    latency: { avg: null, p50: null, p90: null, p99: null, max: null },
    unexpected: 0,
    sockets: 0,
    timeouts: 0,
    codes: {},
    waf: null,
    connections,
  };
  const acc = { avg: 0, p50: 0, p90: 0, p99: 0, weight: 0, max: null };
  const waf = { seen: 0, verdicts: {}, fails: {}, none: 0, wait: null, inspectors: new Map() };
  let anyWaf = false;

  for (const row of rows) {
    out.reqs += row.reqs;
    out.unexpected += row.unexpected;
    out.sockets += row.sockets;
    out.timeouts += row.timeouts;
    addCounts(out.codes, row.codes);
    const w = row.reqs;
    if (row.latency.p50 != null && w > 0) {
      acc.avg += (row.latency.avg ?? 0) * w;
      acc.p50 += row.latency.p50 * w;
      acc.p90 += (row.latency.p90 ?? 0) * w;
      acc.p99 += (row.latency.p99 ?? 0) * w;
      acc.weight += w;
      acc.max = Math.max(acc.max ?? 0, row.latency.max ?? 0);
    }
    if (row.waf !== null) {
      anyWaf = true;
      waf.seen += row.waf.seen;
      waf.none += row.waf.none;
      addCounts(waf.verdicts, row.waf.verdicts);
      addCounts(waf.fails, row.waf.fails);
      waf.wait = mergeStat(waf.wait, row.waf.wait);
      for (const insp of row.waf.inspectors) {
        waf.inspectors.set(insp.name, mergeStat(waf.inspectors.get(insp.name) ?? null, insp));
      }
    }
  }

  if (acc.weight > 0) {
    out.latency = {
      avg: acc.avg / acc.weight,
      p50: acc.p50 / acc.weight,
      p90: acc.p90 / acc.weight,
      p99: acc.p99 / acc.weight,
      max: acc.max,
    };
  }
  out.rps = planSec > 0 ? out.reqs / planSec : null;

  if (anyWaf) {
    out.waf = {
      seen: waf.seen,
      verdicts: waf.verdicts,
      fails: waf.fails,
      none: waf.none,
      wait: waf.wait,
      inspectors: [...waf.inspectors.entries()]
        .map(([name, stat]) => ({ name, ...stat }))
        .sort((a, b) => a.name.localeCompare(b.name)),
    };
  }

  return out;
}

function addCounts(into, from) {
  for (const [k, v] of Object.entries(from ?? {})) {
    into[k] = (into[k] ?? 0) + Number(v);
  }
}

/** Слияние двух сводок: среднее взвешенно, квантили взвешенно, максимум -- максимум. */
function mergeStat(a, b) {
  if (b == null || !(b.count > 0)) {
    return a;
  }
  if (a == null || !(a.count > 0)) {
    return { count: b.count, avg: b.avg, p50: b.p50, p90: b.p90, p99: b.p99, max: b.max };
  }
  const n = a.count + b.count;
  const w = (x, y) => ((x ?? 0) * a.count + (y ?? 0) * b.count) / n;
  return {
    count: n,
    avg: w(a.avg, b.avg),
    p50: w(a.p50, b.p50),
    p90: w(a.p90, b.p90),
    p99: w(a.p99, b.p99),
    max: Math.max(a.max ?? 0, b.max ?? 0),
  };
}

function thirdLatency(text) {
  const m = /Latency\s+[\d.]+\w+\s+[\d.]+\w+\s+([\d.]+)(\w+)/.exec(text);
  return ms(m);
}

function ms(m) {
  if (!m) {
    return null;
  }
  const n = Number(m[1]);
  if (!Number.isFinite(n)) {
    return null;
  }
  const u = String(m[2] || "ms");
  if (u === "s") {
    return n * 1000;
  }
  if (u === "us" || u === "µs") {
    return n / 1000;
  }
  if (u === "m") {
    return n * 60000;
  }
  return n;
}

function num(m, i) {
  if (!m) {
    return null;
  }
  const n = Number(m[i]);
  return Number.isFinite(n) ? n : null;
}
