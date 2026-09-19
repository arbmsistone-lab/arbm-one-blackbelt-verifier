import fs from "node:fs";
import crypto from "node:crypto";

const key = Buffer.from(process.env.SNAPSHOT_KEY || "", "base64");
if (key.length !== 32) throw new Error("SNAPSHOT_KEY_INVALID");

const blob = fs.readFileSync("snapshot.enc");
let plain;

if (blob.subarray(0, 5).toString("utf8") === "ARBM2") {
  const ephLen = blob.readUInt16BE(5);
  const ephStart = 7;
  const ephEnd = ephStart + ephLen;
  const nonceStart = ephEnd;
  const tagStart = nonceStart + 12;
  const cipherStart = tagStart + 16;
  if (blob.length <= cipherStart) throw new Error("SNAPSHOT_BLOB_V2_INVALID");

  const privatePrefix = Buffer.from("302e020100300506032b656e04220420", "hex");
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([privatePrefix, key]),
    format: "der",
    type: "pkcs8",
  });
  const ephemeralPublicKey = crypto.createPublicKey({
    key: blob.subarray(ephStart, ephEnd),
    format: "der",
    type: "spki",
  });
  const shared = crypto.diffieHellman({ privateKey, publicKey: ephemeralPublicKey });
  const aesKey = crypto.createHash("sha256")
    .update(shared)
    .update("ARBM_ONE_BLACKBELT_V2")
    .digest();
  const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, blob.subarray(nonceStart, tagStart));
  decipher.setAuthTag(blob.subarray(tagStart, cipherStart));
  plain = Buffer.concat([decipher.update(blob.subarray(cipherStart)), decipher.final()]);
} else {
  if (blob.length < 29) throw new Error("SNAPSHOT_BLOB_INVALID");
  const nonce = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ciphertext = blob.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

fs.writeFileSync("snapshot.tar", plain);
const hash = crypto.createHash("sha256").update(plain).digest("hex");
const manifest = JSON.parse(fs.readFileSync("manifest.json", "utf8"));
if (hash !== manifest.archive_sha256) throw new Error("SNAPSHOT_SHA256_MISMATCH");
console.log(JSON.stringify({
  decrypted_bytes: plain.length,
  archive_sha256: hash,
  source_sha: manifest.source_sha,
}));
