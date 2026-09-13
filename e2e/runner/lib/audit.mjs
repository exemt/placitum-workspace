/**
 * Клиент waf-search через прокси контроллера (/api/search/...,
 * controller/src/search-http.ts -> logger/internal/httpapi). Не по
 * пространству: поиск глобален для контура.
 */

import { fetchJson } from "./http.mjs";

export function auditClient(baseUrl) {
  const base = baseUrl.replace(/\/$/, "");

  async function list(params = {}) {
    const qs = new URLSearchParams(params).toString();
    const { status, json } = await fetchJson(`${base}/api/search/audit?${qs}`);

    if (status !== 200 || json === null) {
      return { status, items: [], total: 0 };
    }

    return { status, items: json.items ?? [], total: json.total ?? 0 };
  }

  async function findings(node, ray, phase) {
    const qs = phase === undefined ? "" : `?phase=${encodeURIComponent(phase)}`;
    const { status, json } = await fetchJson(
      `${base}/api/search/audit/${encodeURIComponent(node)}/${encodeURIComponent(ray)}/findings${qs}`,
    );

    if (status !== 200 || json === null) {
      return { status, items: [] };
    }

    return { status, items: json.items ?? [] };
  }

  // phase -- обязательна там, где записей две: у запроса и ответа общий
  // ray, и без неё бэкенд отдаёт запись запроса.
  async function content(node, ray, kind, phase) {
    const qs = phase === undefined ? "" : `?phase=${encodeURIComponent(phase)}`;
    const { status, json } = await fetchJson(
      `${base}/api/search/audit/${encodeURIComponent(node)}/${encodeURIComponent(ray)}/${kind}${qs}`,
    );

    if (status !== 200 || json === null) {
      return { status, available: false };
    }

    return { status, ...json };
  }

  /** Одна запись целиком -- с превью; в списке превью нет. */
  async function get(node, ray, phase) {
    const qs = phase === undefined ? "" : `?phase=${encodeURIComponent(phase)}`;
    const { status, json } = await fetchJson(
      `${base}/api/search/audit/${encodeURIComponent(node)}/${encodeURIComponent(ray)}${qs}`,
    );
    return status === 200 ? json : null;
  }

  return { list, get, findings, content };
}
