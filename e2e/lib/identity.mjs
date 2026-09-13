/*
 * Личности прогона: своя пара ключей и свои токены на каждый запуск.
 *
 * Кейсу нужна живая калитка -- иначе секции `sessions` в сообщении не будет, а
 * с ней и оси `user` у счётчика. Поднимать ради этого форму входа, набор
 * учёток и живые сессии значит завести полстенда; вместо этого прогон берёт
 * внешнего провайдера `jwt`: подпись проверяет калитка, а токены выписывает
 * сам прогон -- пара RSA генерируется здесь же и живёт ровно один запуск.
 *
 * Два следствия, ради которых это и сделано.
 *
 * 1. **Ключи корзин свежие на каждый запуск.** Корзины счётчика живут в Redis
 *    и переживают прогон; доступа к Redis у автономного прогона нет и быть не
 *    должно. Поэтому логин каждого запуска свой (`alice-lq3f8x`), и вчерашняя
 *    полная корзина сегодняшнему прогону не мешает.
 * 2. **Проверенность -- настоящая.** Калитка ставит `verified: true` только
 *    подписанной сессии (`alg != none`), и счётчик ключует корзину лишь ей.
 *    Поддельная и непроверенная личности проверяются тем же способом -- вторым
 *    источником с `alg: none`.
 */

import { createSign, generateKeyPairSync } from "node:crypto";

const b64u = (value) => Buffer.from(value).toString("base64url");

/** Метка запуска: ею разводятся логины соседних прогонов. */
export function runTag() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

/**
 * Личности кейса: пара ключей, PEM для источника и токен на каждый логин.
 *
 * `logins` -- имена из кейса (`["alice", "bob"]`); наружу они выходят с
 * меткой запуска, поэтому корзина каждого прогона своя. `ttlS` -- срок
 * токена; калитка сверяет `exp` с допуском источника.
 */
export function identities(logins, { ttlS = 3600, tag = runTag() } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const now = Math.floor(Date.now() / 1000);
  const people = {};

  for (const login of logins) {
    const sub = `${login}-${tag}`;

    people[login] = {
      login,
      sub,
      sid: `sid-${sub}`,
      /* Подписанный: калитка проверит подпись и назовёт личность проверенной. */
      token: token(privateKey, { sub, sid: `sid-${sub}`, iat: now, exp: now + ttlS }),
      /*
       * Тот же человек без подписи -- для источника с `alg: none`. Разбирается
       * так же, но приезжает с `verified: false`, и ключом счёта не станет.
       */
      unsigned: unsigned({ sub, sid: `sid-${sub}`, iat: now, exp: now + ttlS }),
    };
  }

  return { tag, publicPem: publicKey, people };
}

/** RS256: заголовок, тело, подпись -- ровно то, что ждёт калитка. */
function token(privateKey, claims) {
  const data = `${b64u(JSON.stringify({ alg: "RS256", typ: "JWT" }))}.${b64u(JSON.stringify(claims))}`;
  const sig = createSign("RSA-SHA256").update(data).end().sign(privateKey);

  return `${data}.${b64u(sig)}`;
}

/** Без подписи: место подписи пустое, как у `alg: none`. */
function unsigned(claims) {
  return `${b64u(JSON.stringify({ alg: "none", typ: "JWT" }))}.${b64u(JSON.stringify(claims))}.`;
}

/**
 * Подстановки для описания кейса. Кейс -- только данные, а PEM и токены
 * рождаются в прогоне, поэтому в тексте кейса стоят имена, а значения
 * подставляются здесь:
 *
 *   "@jwt.public"        -- PEM открытого ключа (в документ источника),
 *   "@bearer.alice"      -- готовый заголовок Authorization подписанного,
 *   "@bearer-unsigned.alice" -- то же, но без подписи,
 *   "@login.alice"       -- логин с меткой запуска (для ожиданий и наборов).
 */
export function substOf(ident) {
  const subst = { "@jwt.public": ident.publicPem };

  for (const [name, person] of Object.entries(ident.people)) {
    subst[`@bearer.${name}`] = `Bearer ${person.token}`;
    subst[`@bearer-unsigned.${name}`] = `Bearer ${person.unsigned}`;
    subst[`@login.${name}`] = person.sub;
  }

  return subst;
}
