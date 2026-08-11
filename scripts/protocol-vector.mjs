import { createECDH, createHash, webcrypto } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const subtle = webcrypto.subtle;
const here = dirname(fileURLToPath(import.meta.url));
const vectorPath = resolve(here, "../testdata/protocol-v1.json");
const algorithm = "ECDH-P256+HKDF-SHA256+AES-256-GCM-CHUNKED";
const encoder = new TextEncoder();

const b64 = (value) => Buffer.from(value).toString("base64url");
const unb64 = (value) => new Uint8Array(Buffer.from(value, "base64url"));
const hex = (value) => Buffer.from(value).toString("hex");
const concat = (...values) => Buffer.concat(values.map((value) => Buffer.from(value)));
const sha256 = async (value) => new Uint8Array(await subtle.digest("SHA-256", value));
const nonce = (prefix, index) => { const out = new Uint8Array(12); out.set(prefix); new DataView(out.buffer).setUint32(8, index, false); return out; };

function keyMaterial(scalarValue) {
  const scalar = Buffer.alloc(32);
  scalar[31] = scalarValue;
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(scalar);
  const point = ecdh.getPublicKey(undefined, "uncompressed");
  return {
    scalar,
    point,
    privateJwk: { kty: "EC", crv: "P-256", x: b64(point.subarray(1, 33)), y: b64(point.subarray(33, 65)), d: b64(scalar), ext: true, key_ops: ["deriveBits"] },
    publicJwk: { kty: "EC", crv: "P-256", x: b64(point.subarray(1, 33)), y: b64(point.subarray(33, 65)), ext: true, key_ops: [] }
  };
}

function canonical(header) {
  return `opaquedrop/v1/header\nversion=${header.version}\nrequest_id=${header.request_id}\nupload_id=${header.upload_id}\nalgorithm=${header.algorithm}\nephemeral_public_key=${header.ephemeral_public_key}\nsalt=${header.salt}\nnonce_prefix=${header.nonce_prefix}\nchunk_size=${header.chunk_size}\nchunk_count=${header.chunk_count}\nplain_size=${header.plain_size}\n`;
}

async function derive(recipientPrivateJwk, ephemeralPublicJwk, header) {
  const recipientPrivate = await subtle.importKey("jwk", recipientPrivateJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const ephemeralPublic = await subtle.importKey("jwk", ephemeralPublicJwk, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await subtle.deriveBits({ name: "ECDH", public: ephemeralPublic }, recipientPrivate, 256);
  const material = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: unb64(header.salt), info: encoder.encode(`OpaqueDrop/v1/request/${header.request_id}/upload/${header.upload_id}`) }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function generate() {
  const recipient = keyMaterial(1);
  const ephemeral = keyMaterial(2);
  const plaintext = encoder.encode("browser-to-go vector: two authenticated chunks, ordered.");
  const salt = Uint8Array.from({ length: 32 }, (_, i) => i);
  const noncePrefix = Uint8Array.from({ length: 8 }, (_, i) => 0xa0 + i);
  const header = {
    version: 1,
    request_id: "AQEBAQEBAQEBAQEBAQEBAQ",
    upload_id: "AgICAgICAgICAgICAgICAg",
    algorithm,
    ephemeral_public_key: b64(ephemeral.point),
    salt: b64(salt),
    nonce_prefix: b64(noncePrefix),
    chunk_size: 32,
    chunk_count: 2,
    plain_size: plaintext.length
  };
  const headerHash = hex(await sha256(encoder.encode(canonical(header))));
  const aes = await derive(ephemeral.privateJwk, recipient.publicJwk, header);
  // ECDH is symmetric. For generation, the ephemeral private key derives with the recipient public key.
  const metadata = encoder.encode(JSON.stringify({ name: "../vector?.txt", type: "text/plain", last_modified: 1700000000000 }));
  const encryptedMetadata = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce(noncePrefix, 0xffffffff), additionalData: encoder.encode(`opaquedrop/v1|${header.request_id}|${header.upload_id}|header|${headerHash}|metadata`), tagLength: 128 }, aes, metadata));
  const chunks = [];
  for (let index = 0; index < header.chunk_count; index++) {
    const part = plaintext.slice(index * header.chunk_size, Math.min(plaintext.length, (index + 1) * header.chunk_size));
    const cipher = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce(noncePrefix, index), additionalData: encoder.encode(`opaquedrop/v1|${header.request_id}|${header.upload_id}|header|${headerHash}|chunk|${index}`), tagLength: 128 }, aes, part));
    chunks.push(cipher);
  }
  const manifest = { ...header, header_sha256: headerHash, encrypted_metadata: b64(encryptedMetadata) };
  const manifestJSON = JSON.stringify(manifest);
  const receiptInput = concat(encoder.encode("OpaqueDrop receipt v1\0"), await sha256(encoder.encode(manifestJSON)), ...(await Promise.all(chunks.map(sha256))));
  const vector = {
    vector_version: 1,
    generated_by: "Node.js WebCrypto with fixed P-256 scalars",
    recipient_private_key: b64(recipient.scalar),
    recipient_public_key: b64(recipient.point),
    manifest_json: manifestJSON,
    ciphertext_chunks: chunks.map(b64),
    plaintext_base64url: b64(plaintext),
    metadata_json: new TextDecoder().decode(metadata),
    nonces_hex: [hex(nonce(noncePrefix, 0xffffffff)), ...chunks.map((_, i) => hex(nonce(noncePrefix, i)))],
    receipt_sha256: hex(await sha256(receiptInput))
  };
  await mkdir(dirname(vectorPath), { recursive: true });
  await writeFile(vectorPath, `${JSON.stringify(vector, null, 2)}\n`, { flag: "w" });
  console.log(`wrote ${vectorPath}`);
}

async function verify() {
  const vector = JSON.parse(await readFile(vectorPath, "utf8"));
  const manifest = JSON.parse(vector.manifest_json);
  const recipient = keyMaterial(1);
  if (b64(recipient.scalar) !== vector.recipient_private_key || b64(recipient.point) !== vector.recipient_public_key) throw new Error("recipient fixture mismatch");
  if (hex(await sha256(encoder.encode(canonical(manifest)))) !== manifest.header_sha256) throw new Error("header binding mismatch");
  const ephemeralPoint = unb64(manifest.ephemeral_public_key);
  const ephemeralPublic = { kty: "EC", crv: "P-256", x: b64(ephemeralPoint.slice(1, 33)), y: b64(ephemeralPoint.slice(33, 65)), ext: true, key_ops: [] };
  const aes = await derive(recipient.privateJwk, ephemeralPublic, manifest);
  const prefix = unb64(manifest.nonce_prefix);
  const metadataPlain = await subtle.decrypt({ name: "AES-GCM", iv: nonce(prefix, 0xffffffff), additionalData: encoder.encode(`opaquedrop/v1|${manifest.request_id}|${manifest.upload_id}|header|${manifest.header_sha256}|metadata`), tagLength: 128 }, aes, unb64(manifest.encrypted_metadata));
  if (new TextDecoder().decode(metadataPlain) !== vector.metadata_json) throw new Error("metadata plaintext mismatch");
  const plaintext = [];
  for (let index = 0; index < manifest.chunk_count; index++) {
    const part = await subtle.decrypt({ name: "AES-GCM", iv: nonce(prefix, index), additionalData: encoder.encode(`opaquedrop/v1|${manifest.request_id}|${manifest.upload_id}|header|${manifest.header_sha256}|chunk|${index}`), tagLength: 128 }, aes, unb64(vector.ciphertext_chunks[index]));
    plaintext.push(new Uint8Array(part));
  }
  if (b64(concat(...plaintext)) !== vector.plaintext_base64url) throw new Error("file plaintext mismatch");
  if (new Set(vector.nonces_hex).size !== vector.nonces_hex.length) throw new Error("nonce collision in vector");
  const receiptInput = concat(encoder.encode("OpaqueDrop receipt v1\0"), await sha256(encoder.encode(vector.manifest_json)), ...(await Promise.all(vector.ciphertext_chunks.map((chunk) => sha256(unb64(chunk))))));
  if (hex(await sha256(receiptInput)) !== vector.receipt_sha256) throw new Error("receipt mismatch");
  console.log("browser WebCrypto vector verified");
}

if (process.argv.includes("--write")) await generate();
await verify();
