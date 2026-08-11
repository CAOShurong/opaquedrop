(() => {
  "use strict";

  const temporaryStatuses = new Set([408, 425, 429, 500, 502, 503, 504]);

  function isRetryable(error) {
    return Boolean(error && (error.opaqueDropNetworkFailure === true || temporaryStatuses.has(error.status)));
  }

  function retryAfterDelay(value, now = Date.now()) {
    const trimmed = String(value || "").trim();
    if (!trimmed) return 0;
    if (/^\d+$/.test(trimmed)) {
      const seconds = Number(trimmed);
      if (!Number.isSafeInteger(seconds) || seconds > Number.MAX_SAFE_INTEGER / 1000) return Infinity;
      return seconds * 1000;
    }
    const when = Date.parse(trimmed);
    return Number.isNaN(when) ? 0 : Math.max(0, when - now);
  }

  async function run(operation, options = {}) {
    const retries = Number.isInteger(options.retries) && options.retries >= 0 ? Math.min(options.retries, 10) : 3;
    const sleep = options.sleep || ((delay) => new Promise((resolve) => setTimeout(resolve, delay)));
    const onRetry = options.onRetry || (() => {});
    const maxDelay = Number.isFinite(options.maxDelay) && options.maxDelay >= 0 ? options.maxDelay : 30000;
    const totalAttempts = retries + 1;
    for (let attempt = 1; attempt <= totalAttempts; attempt++) {
      try {
        return await operation();
      } catch (error) {
        if (!isRetryable(error) || attempt === totalAttempts) throw error;
        const retryAfter = retryAfterDelay(error.retryAfter, options.now ? options.now() : Date.now());
        if (retryAfter > maxDelay) {
          error.message = `${error.message} (Retry-After exceeds ${maxDelay / 1000} seconds)`;
          throw error;
        }
        const delay = Math.max(retryAfter, Math.min(1000, 250 * (2 ** (attempt - 1))));
        onRetry({ attempt, totalAttempts, delay, error });
        await sleep(delay);
      }
    }
    throw new Error("upload retry loop exhausted");
  }

  globalThis.OpaqueDropRetry = Object.freeze({ run, isRetryable, retryAfterDelay });
})();
