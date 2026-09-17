import fs from "node:fs";
import crypto from "node:crypto";

const key = Buffer.from(process.env.SNAPSHOT_KEY || "", "base64");
if (key.length !== 32) throw new Error("SNAPSHOT_KEY_INVALID");

const blob = fs.readFileSync("snapshot.enc");
if (blob.length < 29) throw new Error("SNAPSHOT_BLOB_INVALID");

const nonce = blob.subarray(0, 12);
const tag = blob.subarray(12, 28);
const ciphertext = blob.subarray(28);

const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
decipher.setAuthTag(tag);
const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
fs.writeFileSync("snapshot.tar", plain);

const hash = crypto.createHash("sha256").update(plain).digest("hex");
const manifest = JSON.parse(fs.readFileSync("manifest.json", "utf8"));
if (hash !== manifest.archive_sha256) throw new Error("SNAPSHOT_SHA256_MISMATCH");
console.log(JSON.stringify({ decrypted_bytes: plain.length, archive_sha256: hash, source_sha: manifest.source_sha }));
