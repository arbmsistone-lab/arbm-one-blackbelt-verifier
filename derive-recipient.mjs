import crypto from "node:crypto";

const raw = Buffer.from(process.env.SNAPSHOT_KEY || "", "base64");
if (raw.length !== 32) throw new Error("SNAPSHOT_KEY_INVALID");

const prefix = Buffer.from("302e020100300506032b656e04220420", "hex");
const privateKey = crypto.createPrivateKey({
  key: Buffer.concat([prefix, raw]),
  format: "der",
  type: "pkcs8",
});
const publicKey = crypto.createPublicKey(privateKey).export({
  format: "der",
  type: "spki",
});
console.log("BLACKBELT_RECIPIENT_PUBLIC_KEY=" + publicKey.toString("base64"));
