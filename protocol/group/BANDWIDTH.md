# URLTest bandwidth qualification

Optional URLTest configuration (omitting it preserves latency-only behavior):

```json
"bandwidth_test": {
  "enabled": true,
  "url": "https://proof.ovh.net/files/100Mb.dat",
  "interval": "6h",
  "timeout": "10s",
  "max_bytes": 33554432,
  "minimum_mbps": 50,
  "confirmations": 2
}
```

The URL is required when enabled. Interval: 1m..168h; timeout: 1s..1m;
download limit: 1..512 MiB; threshold: 1..100000 Mbps; confirmations: 1..10.
The other values above are defaults. URLs cannot contain credentials or a
fragment. Requests do not follow redirects and use normal certificate checks.

Each leaf member is dialed independently; production selectors are never
changed to perform a measurement. Transfers are serialized across URLTest
groups, with a one-second pause before each request to avoid bursts against
the origin. The rate includes connection setup, is bounded by both bytes and time,
and only accepts HTTP 200/206 with at least 1 MiB received. An own download
timeout can produce a rate from the bytes received; caller cancellation cannot.
Compression is disabled. This is TCP HTTP payload throughput over the member,
not an independent UDP benchmark or a guarantee for another destination.

Consecutive passing observations admit a member and consecutive failures remove
it. First-time members receive `confirmations` samples in their initial sweep;
later sweeps take one. Ordinary latency hysteresis chooses among fresh,
admitted, reachable members. If none exist for the requested network, the normal
latency policy remains the reserve. Observations older than two test intervals
expire. Provider replacements invalidate changed members. State is per group,
held in memory, and resets on core restart. Automatic sweeps follow the existing
URLTest lifecycle and suspend in idle groups. Group closure cancels pending work.

HTTP 429 is inconclusive: it preserves the last measurement and its original
timestamp, so an origin's rate limit neither disqualifies a node nor renews an
old qualification.

Clash API `/proxies` and `/proxies/{encoded-tag}` include a `bandwidth` object
only when enabled: `running`, `minimum_mbps`, and `results` keyed by member tag.
Each result has `time`, `mbps`, `bytes`, `admitted`, and an optional `error`.
`POST /proxies/{encoded-tag}/bandwidth` returns 202 and starts an asynchronous
sweep using only configured settings; a request during a sweep joins it. No
client-supplied download URL, timeout, or byte limit is accepted. Non-URLTest or
disabled groups return 400. The usual Clash API authentication applies.
