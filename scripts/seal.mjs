#!/usr/bin/env node
// Seal private/content.html into vault.json (AES-256-GCM, PBKDF2-SHA256).
// Usage: npm run seal          (prompts for the key twice)
//        MMM_KEY=... npm run seal   (non-interactive)
// private/content.html is gitignored; only vault.json is committed.

import { readFile, writeFile } from "node:fs/promises";
import { webcrypto as crypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "private", "content.html");
const OUT = path.join(ROOT, "vault.json");
const ITERATIONS = 600000; // OWASP 2023 guidance for PBKDF2-SHA256

const b64 = (buf) => Buffer.from(buf).toString("base64");

function askHidden(question) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    process.stdout.write(question);
    let value = "";
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    const onData = (ch) => {
      if (ch === "\r" || ch === "\n" || ch === "\u0004") {
        stdin.setRawMode?.(false);
        stdin.pause();
        stdin.off("data", onData);
        process.stdout.write("\n");
        resolve(value);
      } else if (ch === "\u0003") {
        process.stdout.write("\n");
        process.exit(130);
      } else if (ch === "\u007f" || ch === "\b") {
        value = value.slice(0, -1);
      } else {
        value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

async function deriveKey(password, salt, usage) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: ITERATIONS },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    [usage]
  );
}

async function main() {
  let html;
  try {
    html = await readFile(SRC, "utf8");
  } catch {
    console.error(`missing ${path.relative(ROOT, SRC)}. copy private/content.example.html to private/content.html and edit it.`);
    process.exit(1);
  }

  let password = process.env.MMM_KEY;
  if (!password) {
    password = await askHidden("key: ");
    const again = await askHidden("again: ");
    if (password !== again) {
      console.error("keys do not match. nothing sealed.");
      process.exit(1);
    }
  }
  if (password.length < 16) {
    console.warn("warning: use at least 16 characters. the ciphertext is public, so the key is the only lock.");
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, "encrypt");
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(html));

  // Prove it opens before writing.
  const check = await deriveKey(password, salt, "decrypt");
  const back = new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, check, ct));
  if (back !== html) throw new Error("round trip failed");

  const vault = { v: 1, kdf: "PBKDF2-SHA256", iter: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
  await writeFile(OUT, JSON.stringify(vault) + "\n");
  console.log(`sealed ${html.length} bytes into vault.json. commit and push it.`);
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
