/**
 * Клиент API контроллера — только то, что нужно раннеру: пространства, флот,
 * rule-files/rule-sets (заливка конфига modsec) и send. Формы ответов — по
 * controller/src/{spaces,fleet,rule-files,rule-sets,rules}-http.ts и
 * docs/requirements.md (/api/<scope_uuid>/...).
 */

import { fetchJson } from "./http.mjs";

export function controllerClient(baseUrl) {
  const base = baseUrl.replace(/\/$/, "");

  async function spaces() {
    const { status, json } = await fetchJson(`${base}/api/spaces`);

    if (status !== 200 || json === null) {
      throw new Error(`GET /api/spaces: ${status}`);
    }

    return json.spaces ?? [];
  }

  async function scopeByName(name) {
    const rows = await spaces();
    const row = rows.find((s) => s.name === name);
    return row?.uuid ?? null;
  }

  async function fleet() {
    const { status, json } = await fetchJson(`${base}/api/fleet`);

    if (status !== 200 || json === null) {
      throw new Error(`GET /api/fleet: ${status}`);
    }

    return json;
  }

  function scopedUrl(scope, path) {
    return `${base}/api/${scope}${path}`;
  }

  const ruleFiles = {
    async list(scope) {
      const { status, json } = await fetchJson(scopedUrl(scope, "/rule-files"));

      if (status !== 200 || json === null) {
        throw new Error(`GET /rule-files: ${status}`);
      }

      return json.rule_files ?? [];
    },

    async get(scope, id) {
      const { status, json } = await fetchJson(scopedUrl(scope, `/rule-files/${id}`));

      if (status !== 200 || json === null) {
        throw new Error(`GET /rule-files/${id}: ${status}`);
      }

      return json;
    },

    async create(scope, body) {
      const { status, json } = await fetchJson(scopedUrl(scope, "/rule-files"), {
        method: "POST",
        body,
      });

      if (status !== 201 || json === null) {
        throw new Error(`POST /rule-files: ${status} ${JSON.stringify(json)}`);
      }

      return json;
    },

    async update(scope, id, body) {
      const { status, json } = await fetchJson(scopedUrl(scope, `/rule-files/${id}`), {
        method: "PUT",
        body,
      });

      if (status !== 200 || json === null) {
        throw new Error(`PUT /rule-files/${id}: ${status} ${JSON.stringify(json)}`);
      }

      return json;
    },

    /**
     * Создать-или-обновить по имени. Идемпотентно: повторный прогон с тем же
     * содержимым не трогает файл вовсе (action: "unchanged"), поэтому фаза 1
     * не гоняет send и не ждёт сходимость флота, если конфиг не менялся.
     */
    async upsert(scope, { name, description = "", textRaw }) {
      const rows = await ruleFiles.list(scope);
      const found = rows.find((r) => r.name === name);

      if (found === undefined) {
        const row = await ruleFiles.create(scope, {
          name,
          description,
          text_raw: textRaw,
        });
        return { row, action: "created" };
      }

      const full = await ruleFiles.get(scope, found.uuid);

      if (full.text_raw === textRaw && full.description === description) {
        return { row: full, action: "unchanged" };
      }

      const row = await ruleFiles.update(scope, found.uuid, {
        name,
        description,
        text_raw: textRaw,
      });
      return { row, action: "updated" };
    },
  };

  const ruleSets = {
    async list(scope) {
      const { status, json } = await fetchJson(scopedUrl(scope, "/rule-sets"));

      if (status !== 200 || json === null) {
        throw new Error(`GET /rule-sets: ${status}`);
      }

      return json.rule_sets ?? [];
    },

    async get(scope, id) {
      const { status, json } = await fetchJson(scopedUrl(scope, `/rule-sets/${id}`));

      if (status !== 200 || json === null) {
        throw new Error(`GET /rule-sets/${id}: ${status}`);
      }

      return json;
    },

    async create(scope, body) {
      const { status, json } = await fetchJson(scopedUrl(scope, "/rule-sets"), {
        method: "POST",
        body,
      });

      if (status !== 201 || json === null) {
        throw new Error(`POST /rule-sets: ${status} ${JSON.stringify(json)}`);
      }

      return json;
    },

    async update(scope, id, body) {
      const { status, json } = await fetchJson(scopedUrl(scope, `/rule-sets/${id}`), {
        method: "PUT",
        body,
      });

      if (status !== 200 || json === null) {
        throw new Error(`PUT /rule-sets/${id}: ${status} ${JSON.stringify(json)}`);
      }

      return json;
    },

    /** Как ruleFiles.upsert, но сверяет состав файлов (в порядке) вместо текста. */
    async upsert(scope, { name, description = "", fileIds }) {
      const rows = await ruleSets.list(scope);
      const found = rows.find((r) => r.name === name);

      if (found === undefined) {
        const row = await ruleSets.create(scope, {
          name,
          description,
          files: fileIds,
        });
        return { row, action: "created" };
      }

      const full = await ruleSets.get(scope, found.uuid);
      const currentIds = full.files.map((f) => f.uuid);
      const same =
        full.description === description &&
        currentIds.length === fileIds.length &&
        currentIds.every((id, i) => id === fileIds[i]);

      if (same) {
        return { row: full, action: "unchanged" };
      }

      const row = await ruleSets.update(scope, found.uuid, {
        name,
        description,
        files: fileIds,
      });
      return { row, action: "updated" };
    },
  };

  async function rulesSend(scope) {
    const { status, json } = await fetchJson(scopedUrl(scope, "/rules/send"), {
      method: "POST",
      body: {},
    });

    if (status !== 200 || json === null) {
      throw new Error(`POST /rules/send: ${status} ${JSON.stringify(json)}`);
    }

    return json;
  }

  /*
   * Сходимость: три уровня одним документом (docs/config-convergence.md).
   * `refresh` -- пересчёт без ожидания срока годности плана: между правкой
   * через API и вопросом «разошлось ли» тесту стоять незачем.
   */
  const convergence = {
    async get(scope) {
      const { status, json } = await fetchJson(scopedUrl(scope, "/convergence"));

      if (status !== 200 || json === null) {
        throw new Error(`GET /convergence: ${status}`);
      }

      return json;
    },

    async refresh(scope, channel) {
      const tail = channel === undefined ? "" : `?channel=${channel}`;
      const { status, json } = await fetchJson(
        scopedUrl(scope, `/convergence/refresh${tail}`),
        { method: "POST", body: {} },
      );

      if (status !== 200 || json === null) {
        throw new Error(`POST /convergence/refresh: ${status}`);
      }

      return json;
    },

    async channel(scope, id) {
      const snap = await convergence.refresh(scope);
      const row = (snap.channels ?? []).find((c) => c.id === id);

      if (row === undefined) {
        throw new Error(`в снимке нет канала ${id}`);
      }

      return row;
    },

    /** Разослать канал его собственным `send`. */
    async send(scope, id) {
      const row = await convergence.channel(scope, id);
      const { status, json } = await fetchJson(scopedUrl(scope, `/${row.send}`), {
        method: "POST",
        body: {},
      });

      if (status !== 200 || json === null) {
        throw new Error(`POST /${row.send}: ${status} ${JSON.stringify(json)}`);
      }

      return json;
    },
  };

  /*
   * Прямой доступ к скоупнутому API. Типизированных обёрток на каждую сущность
   * здесь нет намеренно: сценарий правок ходит по двум десяткам эндпоинтов, и
   * повторять для них формы из controller/ux/src/api.ts значило бы завести
   * третью копию, которая разъедется первой.
   */
  const api = {
    async get(scope, path) {
      const { status, json } = await fetchJson(scopedUrl(scope, path));

      if (status !== 200 || json === null) {
        throw new Error(`GET ${path}: ${status}`);
      }

      return json;
    },

    async send(scope, path, method, body) {
      const { status, json } = await fetchJson(scopedUrl(scope, path), {
        method,
        body: body ?? {},
      });

      if (status >= 400) {
        throw new Error(`${method} ${path}: ${status} ${JSON.stringify(json)}`);
      }

      return json;
    },

    put(scope, path, body) {
      return api.send(scope, path, "PUT", body);
    },

    post(scope, path, body) {
      return api.send(scope, path, "POST", body);
    },
  };

  return {
    api,
    spaces,
    scopeByName,
    fleet,
    ruleFiles,
    ruleSets,
    rulesSend,
    convergence,
  };
}
