/*
 * Конфигурация из переменных окружения. Приложение не знает про WAF: оно не
 * решает про вердикты и не проверяет, кто перед ним стоит. Всё, что оно умеет
 * про контур, -- прочитать заголовки, которые ему подставила калитка, и
 * показать их на /whoami.
 */

export interface Config {
  port: number;
  name: string;
  logLevel: string;
  /** сколько карточек в наборе; фиксировано, чтобы пагинация была предсказуема */
  items: number;
  /** потолок тела запроса: /upload и /api/bulk принимают крупное намеренно */
  maxBodyBytes: number;
  /** потолок /big, чтобы шальной запрос не выел память контейнера */
  maxBigBytes: number;
  /** срок сессии приложения (кука sid) */
  sessionTtlS: number;
  /** срок токена RS256 */
  tokenTtlS: number;
  /**
   * PEM приватного ключа RS256. Пусто -- пара генерируется на старте, и
   * публичный ключ отдаётся на /keys/jwt.pub. Тогда после перезапуска
   * приложения источник входа `jwt` надо перенастроить: ключ сменился.
   * Чтобы ключ пережил рестарт, положить сюда PEM (или примонтировать файл
   * и подставить его содержимое).
   */
  jwtPrivateKeyPem: string;
  /** как часто /socket/feed сам шлёт кадр клиенту: поток s2c без действий клиента */
  feedIntervalMs: number;
  /** потолок кадра сокета; крупнее -- соединение закрывается с 1009 */
  maxFrameBytes: number;
}

export function load(env: NodeJS.ProcessEnv = process.env): Config {
  return {
    port: Number(env.PORT ?? 8080),
    name: env.APP_NAME ?? "shop",
    logLevel: env.APP_LOG ?? "info",
    items: Number(env.APP_ITEMS ?? 120),
    maxBodyBytes: Number(env.APP_MAX_BODY_BYTES ?? 16 * 1024 * 1024),
    maxBigBytes: Number(env.APP_MAX_BIG_BYTES ?? 8 * 1024 * 1024),
    sessionTtlS: Number(env.APP_SESSION_TTL_S ?? 8 * 3600),
    tokenTtlS: Number(env.APP_TOKEN_TTL_S ?? 900),
    jwtPrivateKeyPem: env.APP_JWT_PRIVATE_KEY ?? "",
    feedIntervalMs: Number(env.APP_FEED_INTERVAL_MS ?? 1000),
    maxFrameBytes: Number(env.APP_MAX_FRAME_BYTES ?? 1024 * 1024),
  };
}
