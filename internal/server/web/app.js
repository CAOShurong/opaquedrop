(() => {
  "use strict";

  const text = new TextEncoder();
  const requestId = location.pathname.split("/").filter(Boolean).pop();
  const tokenKey = `opaquedrop-submit-${requestId}`;
  const hash = new URLSearchParams(location.hash.slice(1));
  if (hash.get("t")) {
    sessionStorage.setItem(tokenKey, hash.get("t"));
    history.replaceState(null, "", location.pathname);
  }
  const token = sessionStorage.getItem(tokenKey) || "";
  const state = { info: null, files: [], busy: false };

  const $ = (id) => document.getElementById(id);
  const loading = $("loading");
  const errorPanel = $("error-panel");
  const uploadPanel = $("upload-panel");
  const input = $("file-input");
  const list = $("file-list");
  const button = $("upload-button");
  const drop = $("drop-zone");

  boot();

  async function boot() {
    if (!token) return showError("This upload link is missing its private capability. Ask the recipient for the complete link.");
    if (!window.crypto?.subtle || !window.isSecureContext) return showError("Browser encryption requires HTTPS. Localhost is also allowed for testing.");
    try {
      state.info = await api(`/api/v1/requests/${requestId}`);
      $("request-label").textContent = state.info.label;
      $("expiry").textContent = new Date(state.info.expires_at).toLocaleString();
      $("remaining").textContent = `${state.info.max_files - state.info.used_files} files · ${formatBytes(state.info.max_bytes - state.info.used_bytes)}`;
      loading.classList.add("hidden");
      uploadPanel.classList.remove("hidden");
    } catch (error) {
      showError(error.message);
    }
  }

  input.addEventListener("change", () => setFiles([...input.files]));
  ["dragenter", "dragover"].forEach((event) => drop.addEventListener(event, (e) => { e.preventDefault(); drop.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((event) => drop.addEventListener(event, (e) => { e.preventDefault(); drop.classList.remove("dragging"); }));
  drop.addEventListener("drop", (e) => setFiles([...e.dataTransfer.files]));
  button.addEventListener("click", uploadAll);

  function setFiles(files) {
    if (state.busy) return;
    const slots = Math.max(0, state.info.max_files - state.info.used_files);
    const bytes = Math.max(0, state.info.max_bytes - state.info.used_bytes);
    let used = 0;
    state.files = files.slice(0, slots).filter((file) => {
      if (used + file.size > bytes) return false;
      used += file.size;
      return true;
    });
    list.replaceChildren(...state.files.map((file, index) => fileRow(file, index)));
    button.disabled = state.files.length === 0;
    button.textContent = state.files.length ? `Encrypt and upload ${state.files.length} file${state.files.length === 1 ? "" : "s"}` : "Encrypt and upload";
  }

  function fileRow(file, index) {
    const row = document.createElement("div");
    row.className = "file-row";
    row.dataset.index = index;
    const name = document.createElement("span");
    name.className = "file-name";
    name.textContent = file.name;
    const meta = document.createElement("span");
    meta.className = "file-meta";
    meta.textContent = formatBytes(file.size);
    const progress = document.createElement("span");
    progress.className = "file-progress";
    progress.innerHTML = "<i></i>";
    row.append(name, meta, progress);
    return row;
  }

  async function uploadAll() {
    if (state.busy || !state.files.length) return;
    state.busy = true;
    button.disabled = true;
    const results = $("results");
    results.classList.remove("hidden");
    for (let i = 0; i < state.files.length; i++) {
      try {
        button.textContent = `Encrypting ${i + 1} of ${state.files.length}…`;
        const receipt = await uploadFile(state.files[i], i);
        addReceipt(state.files[i], receipt);
      } catch (error) {
        button.textContent = `Stopped: ${error.message}`;
        button.disabled = false;
        state.busy = false;
        return;
      }
    }
    button.textContent = "Upload complete";
    state.busy = false;
    state.info.used_files += state.files.length;
    state.info.used_bytes += state.files.reduce((sum, file) => sum + file.size, 0);
    $("remaining").textContent = `${state.info.max_files - state.info.used_files} files · ${formatBytes(state.info.max_bytes - state.info.used_bytes)}`;
  }

  async function uploadFile(file, rowIndex) {
    const chunkSize = 1024 * 1024;
    const chunkCount = Math.max(1, Math.ceil(file.size / chunkSize));
    const uploadId = randomId();
    const recipientPublic = await crypto.subtle.importKey("raw", fromB64(state.info.public_key), { name: "ECDH", namedCurve: "P-256" }, false, []);
    const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: recipientPublic }, ephemeral.privateKey, 256);
    const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const noncePrefix = crypto.getRandomValues(new Uint8Array(8));
    const aes = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: text.encode(`OpaqueDrop/v1/request/${requestId}/upload/${uploadId}`) }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const ephemeralPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
    const header = {
      version: 1,
      request_id: requestId,
      upload_id: uploadId,
      algorithm: "ECDH-P256+HKDF-SHA256+AES-256-GCM-CHUNKED",
      ephemeral_public_key: toB64(ephemeralPublic),
      salt: toB64(salt),
      nonce_prefix: toB64(noncePrefix),
      chunk_size: chunkSize,
      chunk_count: chunkCount,
      plain_size: file.size
    };
    const headerHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", text.encode(headerCanonical(header)))));
    const metadata = text.encode(JSON.stringify({ name: file.name, type: file.type || "", last_modified: file.lastModified || 0 }));
    const encryptedMetadata = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce(noncePrefix, 0xffffffff), additionalData: text.encode(`opaquedrop/v1|${requestId}|${uploadId}|header|${headerHash}|metadata`), tagLength: 128 }, aes, metadata));
    const manifest = {
      ...header,
      header_sha256: headerHash,
      encrypted_metadata: toB64(encryptedMetadata)
    };
    const manifestBody = JSON.stringify(manifest);
    const manifestDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", text.encode(manifestBody)));
    await api(`/api/v1/requests/${requestId}/uploads`, { method: "POST", body: manifestBody, headers: { "Content-Type": "application/json" } });
    const chunkDigests = [];
    for (let index = 0; index < chunkCount; index++) {
      const start = index * chunkSize;
      const plain = await file.slice(start, Math.min(file.size, start + chunkSize)).arrayBuffer();
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce(noncePrefix, index), additionalData: text.encode(`opaquedrop/v1|${requestId}|${uploadId}|header|${headerHash}|chunk|${index}`), tagLength: 128 }, aes, plain));
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ciphertext));
      chunkDigests.push(digest);
      await putChunk(uploadId, index, ciphertext, hex(digest));
      setProgress(rowIndex, ((index + 1) / chunkCount) * 100);
    }
    const receipt = await api(`/api/v1/requests/${requestId}/uploads/${uploadId}/complete`, { method: "POST" });
    const localReceipt = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", concat(text.encode("OpaqueDrop receipt v1\0"), manifestDigest, ...chunkDigests))));
    if (localReceipt !== receipt.receipt_sha256) throw new Error("server receipt did not match browser ciphertext");
    return receipt;
  }

  async function putChunk(uploadId, index, ciphertext, digest) {
    const path = `/api/v1/requests/${requestId}/uploads/${uploadId}/chunks/${index}`;
    try {
      await api(path, { method: "PUT", body: ciphertext });
    } catch (error) {
      if (!error.message.includes("UPLOAD_CONFLICT")) throw error;
      const response = await fetch(path, { method: "HEAD", headers: authHeaders() });
      if (!response.ok || response.headers.get("X-OpaqueDrop-SHA256") !== digest) throw error;
    }
  }

  async function api(path, options = {}) {
    const headers = { ...authHeaders(), ...(options.headers || {}) };
    const response = await fetch(path, { ...options, headers });
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try {
        const payload = await response.json();
        message = `${payload.error.code}: ${payload.error.message}`;
      } catch (_) { /* keep HTTP status */ }
      throw new Error(message);
    }
    if (response.status === 204) return null;
    return response.json();
  }

  function authHeaders() { return { Authorization: `OpaqueDrop ${token}` }; }
  function headerCanonical(value) { return `opaquedrop/v1/header\nversion=${value.version}\nrequest_id=${value.request_id}\nupload_id=${value.upload_id}\nalgorithm=${value.algorithm}\nephemeral_public_key=${value.ephemeral_public_key}\nsalt=${value.salt}\nnonce_prefix=${value.nonce_prefix}\nchunk_size=${value.chunk_size}\nchunk_count=${value.chunk_count}\nplain_size=${value.plain_size}\n`; }
  function nonce(prefix, index) { const value = new Uint8Array(12); value.set(prefix); new DataView(value.buffer).setUint32(8, index, false); return value; }
  function randomId() { return toB64(crypto.getRandomValues(new Uint8Array(16))); }
  function toB64(bytes) { let binary = ""; for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, ""); }
  function fromB64(value) { const base = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4); const binary = atob(base); return Uint8Array.from(binary, (char) => char.charCodeAt(0)); }
  function concat(...arrays) { const size = arrays.reduce((sum, value) => sum + value.length, 0); const out = new Uint8Array(size); let offset = 0; for (const value of arrays) { out.set(value, offset); offset += value.length; } return out; }
  function hex(bytes) { return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join(""); }
  function setProgress(index, percent) { const bar = list.querySelector(`[data-index="${index}"] .file-progress i`); if (bar) bar.style.setProperty("--progress", `${percent}%`); }

  function addReceipt(file, receipt) {
    const card = document.createElement("article");
    card.className = "receipt";
    const top = document.createElement("div");
    top.className = "receipt-top";
    const name = document.createElement("strong"); name.textContent = file.name;
    const status = document.createElement("span"); status.textContent = "VERIFIED · STORED";
    top.append(name, status);
    const code = document.createElement("code"); code.textContent = receipt.receipt_sha256;
    const detail = document.createElement("small"); detail.textContent = `${formatBytes(file.size)} · ${receipt.chunk_count} encrypted chunk${receipt.chunk_count === 1 ? "" : "s"} · ${new Date(receipt.completed_at).toLocaleString()}`;
    card.append(top, code, detail);
    $("receipt-list").append(card);
  }

  function formatBytes(value) {
    if (value < 1024) return `${value} B`;
    const units = ["KiB", "MiB", "GiB", "TiB"];
    let n = value / 1024, unit = units[0];
    for (let i = 1; i < units.length && n >= 1024; i++) { n /= 1024; unit = units[i]; }
    return `${n.toFixed(n >= 10 ? 1 : 2)} ${unit}`;
  }

  function showError(message) {
    loading.classList.add("hidden");
    uploadPanel.classList.add("hidden");
    $("error-message").textContent = message;
    errorPanel.classList.remove("hidden");
  }
})();
