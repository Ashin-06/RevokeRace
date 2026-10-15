# RevokeRace: method and limits

## Model

Time advances in integer seconds sampled at `step`. Requests occur at 0 and each step up to duration; outage intervals use `[start, end)`. At online samples, server contact is instantaneous and revocation knowledge is permanent. The initial contact age is zero, modeling provisioning at time zero even if a device immediately goes offline.

`cached_ttl` uses the local wall clock for expiry and cached revocation state. `bounded_lease` rejects offline contact age greater than or equal to the configured lease and uses authority elapsed time as the monotonic expiry fixture; it also conservatively rejects wall-clock expiry. `online_only` requires connectivity and authority token expiry. Invalid HMAC capability signatures are denied by all policies.

`stale_grants` counts accepted requests at or after revocation. `legitimate_denials` counts denials of valid, unrevoked, authority-unexpired capabilities. Observed exposure is the last stale request’s time minus revocation time, with sampling resolution determined by step. It does not estimate unobserved requests or prove a worst-case bound.

## Input limits

The top-level object is `{"scenario": {...}}`. Required scenario fields: `name`, `duration` (1–3600), `revoke_at` (0–duration), `token_ttl` (1–7200), `lease_seconds` (0–3600), `devices` (1–16). Optional `step` defaults to 1 (range 1–60). At most 100,000 total policy decisions are allowed.

Devices require `id` and `outages` (up to 20 intervals). Optional fields: `offset` (±3600), `drift_ppm` (±100000), `rollback_at`, `rollback_seconds` (0–7200), and boolean `tamper`. Unknown fields, duplicate IDs, invalid intervals, boolean-as-integer values, duplicate JSON keys, and non-finite numbers are rejected.

## Assumptions

The HMAC key is derived from public scenario fixture material for deterministic reproduction. It is not a production signing secret. The monotonic clock is a simulator assumption, not a hardware-backed counter. Malicious enforcement clients, restored snapshots, monotonic rollback, transport latency, intermittent server failures while nominally online, and real deployment integration are outside the model.
