import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import fs from "node:fs";
import vm from "node:vm";

class FakeClassList {
  constructor(...names) { this.names = new Set(names); }
  add(...names) { names.forEach((name) => this.names.add(name)); }
  remove(...names) { names.forEach((name) => this.names.delete(name)); }
  contains(name) { return this.names.has(name); }
}

class FakeElement {
  constructor() {
    this.classList = new FakeClassList();
    this.dataset = {};
    this.listeners = new Map();
    this.children = [];
    this.style = { setProperty() {} };
    this.disabled = false;
    this.files = [];
    this.textContent = "";
  }
  addEventListener(name, listener) { this.listeners.set(name, listener); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  querySelector() { return new FakeElement(); }
}

const elements = new Map();
for (const id of ["loading", "error-panel", "error-message", "upload-panel", "file-input", "file-list", "upload-button", "drop-zone", "results", "receipt-list", "request-label", "expiry", "remaining"]) {
  elements.set(id, new FakeElement());
}
elements.get("upload-panel").classList.add("hidden");
elements.get("error-panel").classList.add("hidden");
elements.get("results").classList.add("hidden");

const requestId = "RRRRRRRRRRRRRRRRRRRRRR";
const submitToken = "SUBMIT-CAPABILITY-NEVER-LOG";
const recipient = await webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
const recipientPublic = new Uint8Array(await webcrypto.subtle.exportKey("raw", recipient.publicKey));
const publicKey = Buffer.from(recipientPublic).toString("base64url");
const encoder = new TextEncoder();

let manifestBody = "";
let chunk = null;
let receipt = null;
const counts = { info: 0, manifest: 0, chunk: 0, head: 0, complete: 0 };

function jsonResponse(status, value, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json", ...headers } });
}

function interruptedJSONResponse(status) {
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode('{"committed":'));
      controller.error(new TypeError("response body interrupted"));
    }
  });
  return new Response(body, { status, headers: { "Content-Type": "application/json" } });
}

async function digestHex(value) {
  return Buffer.from(await webcrypto.subtle.digest("SHA-256", value)).toString("hex");
}

async function fetchStub(path, options = {}) {
  const method = options.method || "GET";
  if (options.headers?.Authorization !== `OpaqueDrop ${submitToken}`) throw new Error("missing submit authorization");
  if (method === "GET" && path === `/api/v1/requests/${requestId}`) {
    counts.info += 1;
    return jsonResponse(200, {
      id: requestId,
      label: "Headless retry fixture",
      expires_at: "2026-08-12T00:00:00Z",
      max_files: 1,
      max_bytes: 1048576,
      used_files: 0,
      used_bytes: 0,
      public_key: publicKey
    });
  }
  if (method === "POST" && path === `/api/v1/requests/${requestId}/uploads`) {
    counts.manifest += 1;
    const body = String(options.body);
    if (counts.manifest === 1) {
      manifestBody = body;
      return interruptedJSONResponse(201);
    }
    assert.equal(body, manifestBody, "manifest retry changed bytes");
    return jsonResponse(201, { upload_id: JSON.parse(body).upload_id, chunk_count: 1 });
  }
  if (method === "PUT" && path.includes("/chunks/0")) {
    counts.chunk += 1;
    if (counts.chunk === 1) {
      chunk = new Uint8Array(options.body);
      throw new Error("chunk response lost after commit");
    }
    return new Response("incomplete conflict response", { status: 409, headers: { "Content-Type": "application/json" } });
  }
  if (method === "HEAD" && path.includes("/chunks/0")) {
    counts.head += 1;
    return new Response(null, { status: 200, headers: { "X-OpaqueDrop-SHA256": await digestHex(chunk) } });
  }
  if (method === "POST" && path.endsWith("/complete")) {
    counts.complete += 1;
    if (!receipt) {
      const prefix = encoder.encode("OpaqueDrop receipt v1\0");
      const manifestDigest = new Uint8Array(await webcrypto.subtle.digest("SHA-256", encoder.encode(manifestBody)));
      const chunkDigest = new Uint8Array(await webcrypto.subtle.digest("SHA-256", chunk));
      const receiptInput = new Uint8Array(prefix.length + manifestDigest.length + chunkDigest.length);
      receiptInput.set(prefix);
      receiptInput.set(manifestDigest, prefix.length);
      receiptInput.set(chunkDigest, prefix.length + manifestDigest.length);
      receipt = {
        upload_id: JSON.parse(manifestBody).upload_id,
        receipt_sha256: await digestHex(receiptInput),
        chunk_count: 1,
        completed_at: "2026-08-11T12:00:00Z"
      };
    }
    if (counts.complete === 1) return interruptedJSONResponse(200);
    return jsonResponse(200, receipt);
  }
  throw new Error(`unexpected request ${method} ${path}`);
}

const storage = new Map();
const document = {
  getElementById(id) { return elements.get(id); },
  createElement() { return new FakeElement(); }
};
const context = vm.createContext({
  Blob,
  DataView,
  Date,
  Error,
  Headers,
  Math,
  Promise,
  Response,
  Set,
  TextEncoder,
  URLSearchParams,
  Uint8Array,
  atob,
  btoa,
  console,
  crypto: webcrypto,
  document,
  fetch: fetchStub,
  history: { replaceState() {} },
  location: { pathname: `/r/${requestId}`, hash: `#t=${submitToken}` },
  sessionStorage: {
    getItem(key) { return storage.get(key) || null; },
    setItem(key, value) { storage.set(key, value); }
  },
  setTimeout(callback) { queueMicrotask(callback); return 1; }
});
context.globalThis = context;
context.window = context;
context.isSecureContext = true;

for (const name of ["retry.js", "app.js"]) {
  const source = fs.readFileSync(new URL(`../internal/server/web/${name}`, import.meta.url), "utf8");
  vm.runInContext(source, context, { filename: name });
}
await new Promise((resolve) => setImmediate(resolve));

assert.equal(counts.info, 1);
assert.equal(elements.get("upload-panel").classList.contains("hidden"), false, "upload panel did not open");

const file = new Blob([encoder.encode("same-tab retry plaintext")], { type: "text/plain" });
Object.defineProperties(file, {
  name: { value: "retry.txt" },
  lastModified: { value: 1700000000000 }
});
const input = elements.get("file-input");
input.files = [file];
input.listeners.get("change")();
await elements.get("upload-button").listeners.get("click")();

assert.deepEqual(counts, { info: 1, manifest: 2, chunk: 2, head: 1, complete: 2 });
assert.equal(elements.get("upload-button").textContent, "Upload complete");
assert.equal(elements.get("receipt-list").children.length, 1, "receipt was not rendered");
assert.equal(elements.get("error-panel").classList.contains("hidden"), true, "upload exposed the error panel");

console.log("browser upload response-loss recovery verified");
