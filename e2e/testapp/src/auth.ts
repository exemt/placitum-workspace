/*
 * Два способа входа, которые приложение держит САМО, -- под провайдеры калитки
 * `app` и `jwt`. Третий (`local`) держит калитка, приложению там делать нечего:
 * оно только читает подставленные ей заголовки, см. src/view.ts.
 *
 * Форма ответов на входе и выходе продиктована тем, как калитка подглядывает
 * (docs/README.md репозитория auth, провайдер `app`):
 *
 *   - удачный вход ставит куку, которой в запросе НЕ было, и отвечает
 *     `{"ok": true}` со статусом 200; неудачный не ставит куку вовсе, иначе
 *     калитка подписала бы чужую сессию первым же неудачным POST;
 *   - выход обязан отвечать ТЕЛОМ. На 204 и 304 модуль фазу ответа не
 *     запускает, и подглядывать там нечего -- запись о сессии не снялась бы.
 */

import { createPrivateKey, createPublicKey, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import type { KeyObject } from "node:crypto";

import { findUser } from "./data.ts";
import type { User } from "./data.ts";
import { log } from "./log.ts";

export const SESSION_COOKIE = "sid";

interface Session {
  sid: string;
  login: string;
  groups: string[];
  expiresAt: number;
}

export class Sessions {
  readonly #live = new Map<string, Session>();
  readonly #ttlMs: number;

  constructor(ttlS: number) {
    this.#ttlMs = ttlS * 1000;
  }

  open(user: User): Session {
    const session: Session = {
      sid: randomBytes(16).toString("hex"),
      login: user.login,
      groups: user.groups,
      expiresAt: Date.now() + this.#ttlMs,
    };

    this.#live.set(session.sid, session);
    return session;
  }

  get(sid: string | undefined): Session | undefined {
    if (sid === undefined) {
      return undefined;
    }

    const session = this.#live.get(sid);

    if (session === undefined) {
      return undefined;
    }

    /* Просроченную не отдаём и убираем сразу: иначе карта растёт молча. */
    if (session.expiresAt <= Date.now()) {
      this.#live.delete(sid);
      return undefined;
    }

    return session;
  }

  close(sid: string | undefined): boolean {
    return sid === undefined ? false : this.#live.delete(sid);
  }

  get size(): number {
    return this.#live.size;
  }
}

/* --- токен RS256 -------------------------------------------------------- */

export interface Claims {
  iss: string;
  sub: string;
  email: string;
  groups: string[];
  sid: string;
  iat: number;
  exp: number;
}

export class Tokens {
  readonly #privateKey: KeyObject;
  readonly publicPem: string;
  readonly #ttlS: number;
  readonly #issuer: string;

  /**
   * Без заданного PEM пара генерируется на старте. Это осознанный размен:
   * секрета в git нет, зато публичный ключ меняется на каждый рестарт, и
   * источник входа `jwt` в контроллере после него надо перенастроить с
   * /keys/jwt.pub. Чтобы ключ пережил рестарт -- APP_JWT_PRIVATE_KEY.
   */
  constructor(pem: string, ttlS: number, issuer: string) {
    if (pem === "") {
      const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
      this.#privateKey = pair.privateKey;
      this.publicPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
      log("warn", "jwt key generated at boot", {
        hint: "публичный ключ сменился, источник jwt надо перенастроить с /keys/jwt.pub",
      });
    } else {
      this.#privateKey = createPrivateKey(pem);
      this.publicPem = createPublicKey(this.#privateKey)
        .export({ type: "spki", format: "pem" })
        .toString();
    }

    this.#ttlS = ttlS;
    this.#issuer = issuer;
  }

  issue(user: User): { token: string; claims: Claims } {
    const now = Math.floor(Date.now() / 1000);
    const claims: Claims = {
      iss: this.#issuer,
      sub: user.login,
      email: `${user.login}@${this.#issuer}`,
      groups: user.groups,
      sid: randomBytes(8).toString("hex"),
      iat: now,
      exp: now + this.#ttlS,
    };

    const head = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
    const body = b64url(JSON.stringify(claims));
    const signature = createSign("RSA-SHA256").update(`${head}.${body}`).sign(this.#privateKey);

    return { token: `${head}.${body}.${b64url(signature)}`, claims };
  }
}

function b64url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

/**
 * Разбор токена БЕЗ проверки подписи: приложению она не нужна -- за подпись
 * отвечает калитка, а /whoami показывает притязания как есть, чтобы было
 * видно, что именно она читала. `verified` здесь всегда false: приложение не
 * притворяется, что что-то проверило.
 */
export function peekClaims(authorization: string | undefined): Record<string, unknown> | null {
  if (authorization === undefined || !authorization.toLowerCase().startsWith("bearer ")) {
    return null;
  }

  const parts = authorization.slice(7).trim().split(".");

  if (parts.length !== 3) {
    return null;
  }

  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function authenticate(login: unknown, password: unknown): User | undefined {
  return typeof login === "string" && typeof password === "string"
    ? findUser(login, password)
    : undefined;
}
