#!/usr/bin/env node
/*
 * Пара ключей контура: RSA-4096, OAEP-SHA-256.
 * Приватный — только агентам. Публичный — контроллеру и GET /api/<scope>/crypto.
 *
 *     node gen.mjs
 *     node gen.mjs --force
 *     node gen.mjs --fingerprint   # только напечатать fingerprint существующего contour.pub,
 *                                  # ничего не трогая
 *
 * Генерация заодно прописывает VITE_CONTOUR_FINGERPRINT в deploy/.env, откуда
 * его берёт docker compose: пин, отставший от ключа, -- это жёлтое
 * предупреждение на странице «Сертификаты» и отключённая защита от подмены
 * ключа. Забыть пересчитать его вручную слишком легко, поэтому он пишется
 * здесь же, где ключ и появляется. См. docs/deploy/README.md.
 */

import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const force = process.argv.includes("--force");
const printFingerprint = process.argv.includes("--fingerprint");
const privPath = join(here, "contour.key");
const pubPath = join(here, "contour.pub");
const envPath = join(here, "..", ".env");

const ENV_KEY = "VITE_CONTOUR_FINGERPRINT";

function fingerprintOf(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return "sha256:" + createHash("sha256").update(der).digest("hex");
}

if (printFingerprint) {
  if (!existsSync(pubPath)) {
    process.stderr.write(`${pubPath} not found; run node gen.mjs first\n`);
    process.exit(1);
  }
  process.stdout.write(fingerprintOf(readFileSync(pubPath, "utf8")) + "\n");
  process.exit(0);
}

/**
 * Переписывает одну строку в deploy/.env, не трогая остальные: файл может
 * содержать и другие переменные окружения compose.
 */
function writeEnvFingerprint(fingerprint) {
  const line = `${ENV_KEY}=${fingerprint}`;

  if (!existsSync(envPath)) {
    writeFileSync(envPath, line + "\n");
    return;
  }

  const lines = readFileSync(envPath, "utf8").split(/\r?\n/);
  const at = lines.findIndex((row) => row.startsWith(`${ENV_KEY}=`));

  if (at === -1) {
    lines.push(line);
  } else {
    lines[at] = line;
  }

  writeFileSync(envPath, lines.join("\n").replace(/\n*$/, "\n"));
}

if (!force && (existsSync(privPath) || existsSync(pubPath))) {
  process.stderr.write("keys already exist; pass --force to replace\n");
  process.exit(1);
}

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 4096,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

writeFileSync(privPath, privateKey, { mode: 0o600 });
writeFileSync(pubPath, publicKey, { mode: 0o644 });

const fingerprint = fingerprintOf(publicKey);
writeEnvFingerprint(fingerprint);

process.stdout.write(`wrote ${privPath}\n`);
process.stdout.write(`wrote ${pubPath}\n`);
process.stdout.write(`wrote ${envPath} (${ENV_KEY})\n`);
process.stdout.write(`fingerprint ${fingerprint}\n`);
process.stdout.write("rebuild controller so the pin lands in the UX bundle:\n");
process.stdout.write("    docker compose up -d --build controller\n");
