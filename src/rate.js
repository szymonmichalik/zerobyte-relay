// Per-mailbox rate limits: token buckets kept in memory, next to the mailbox.
//
// They protect the relay, not the devices: a buggy client in a write loop, or
// a stolen token used to flood a mailbox, runs out of tokens and gets 429
// with Retry-After. Nothing is persisted. When a Durable Object is evicted or
// the Node relay restarts, every bucket starts full again, which is harmless:
// the limits are far above what an honest client needs.
//
// A bucket holds at most `burst` tokens and refills `perSecond` tokens a second.

export const RATES = Object.freeze({
  /** Envelopes stored. */
  write: Object.freeze({ burst: 120, perSecond: 2 }),
  /** Fetches, HEADs and prunes. */
  read: Object.freeze({ burst: 240, perSecond: 4 }),
  /** WebSocket upgrades, watch and signal together. */
  connect: Object.freeze({ burst: 20, perSecond: 0.2 }),
  /** Signal frames, per side. */
  signal: Object.freeze({ burst: 400, perSecond: 50 }),
  /** Push notifications sent, per direction. */
  push: Object.freeze({ burst: 20, perSecond: 0.5 }),
  /** Push token registrations. */
  register: Object.freeze({ burst: 10, perSecond: 1 / 60 }),
  /** ICE server credentials minted. */
  ice: Object.freeze({ burst: 6, perSecond: 1 / 30 }),
});

/**
 * Takes one token from the bucket `name` (a key of RATES, optionally followed
 * by `:<anything>` to keep separate buckets of one kind). Returns 0 when
 * allowed, or the whole seconds to wait.
 */
export function take(memory, name, now, rates = RATES) {
  const rate = rates[name.split(":")[0]];
  if (!rate) throw new Error(`unknown rate ${name}`);
  memory.buckets ??= {};
  memory.at = now;
  const bucket = memory.buckets[name] ?? { tokens: rate.burst, at: now };
  const elapsed = Math.max(0, now - bucket.at) / 1000;
  bucket.tokens = Math.min(rate.burst, bucket.tokens + elapsed * rate.perSecond);
  bucket.at = now;
  memory.buckets[name] = bucket;
  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return 0;
  }
  return Math.max(1, Math.ceil((1 - bucket.tokens) / rate.perSecond));
}
