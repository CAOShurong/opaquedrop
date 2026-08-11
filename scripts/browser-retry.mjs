import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("../internal/server/web/retry.js", import.meta.url), "utf8");
vm.runInThisContext(source, { filename: "retry.js" });

const retry = globalThis.OpaqueDropRetry;
assert.ok(retry, "retry helper was not exported to globalThis");

const delays = [];
const notices = [];
let attempts = 0;
const value = await retry.run(async () => {
  attempts += 1;
  if (attempts < 3) {
    const error = new Error("connection interrupted");
    error.opaqueDropNetworkFailure = true;
    throw error;
  }
  return "complete";
}, {
  sleep: async (delay) => delays.push(delay),
  onRetry: (notice) => notices.push(notice)
});
assert.equal(value, "complete");
assert.equal(attempts, 3);
assert.deepEqual(delays, [250, 500]);
assert.deepEqual(notices.map(({ attempt, totalAttempts, delay }) => ({ attempt, totalAttempts, delay })), [
  { attempt: 1, totalAttempts: 4, delay: 250 },
  { attempt: 2, totalAttempts: 4, delay: 500 }
]);

attempts = 0;
await assert.rejects(() => retry.run(async () => {
  attempts += 1;
  const error = new Error("conflict");
  error.status = 409;
  throw error;
}, { sleep: async () => {} }), /conflict/);
assert.equal(attempts, 1, "permanent status was retried");

attempts = 0;
await assert.rejects(() => retry.run(async () => {
  attempts += 1;
  const error = new Error("temporary");
  error.status = 503;
  throw error;
}, { retries: 2, sleep: async () => {} }), /temporary/);
assert.equal(attempts, 3, "temporary status did not use the bounded attempt count");

const retryAfterDelays = [];
attempts = 0;
await assert.rejects(() => retry.run(async () => {
  attempts += 1;
  const error = new Error("temporarily unavailable");
  error.status = 503;
  error.retryAfter = "7";
  throw error;
}, { retries: 1, sleep: async (delay) => retryAfterDelays.push(delay) }), /temporarily unavailable/);
assert.equal(attempts, 2);
assert.deepEqual(retryAfterDelays, [7000]);

attempts = 0;
await assert.rejects(() => retry.run(async () => {
  attempts += 1;
  const error = new Error("slow down");
  error.status = 429;
  error.retryAfter = "31";
  throw error;
}, { sleep: async () => assert.fail("excessive Retry-After must not sleep") }), /Retry-After exceeds 30 seconds/);
assert.equal(attempts, 1);

assert.equal(retry.retryAfterDelay("999999999999999999999999999999"), Infinity);
assert.equal(retry.retryAfterDelay("Thu, 01 Jan 2026 00:00:07 GMT", Date.parse("Thu, 01 Jan 2026 00:00:00 GMT")), 7000);

assert.equal(retry.isRetryable({ status: 408 }), true);
assert.equal(retry.isRetryable({ status: 425 }), true);
assert.equal(retry.isRetryable({ status: 429 }), true);
assert.equal(retry.isRetryable({ status: 500 }), true);
assert.equal(retry.isRetryable({ status: 502 }), true);
assert.equal(retry.isRetryable({ status: 503 }), true);
assert.equal(retry.isRetryable({ status: 504 }), true);
assert.equal(retry.isRetryable({ status: 404 }), false);

console.log("browser upload retry helper verified");
