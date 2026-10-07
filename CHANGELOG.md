# Changelog

## 0.1.0 — 2026-10-07

Initial release.

- `Client` + module-level helpers over the public Ninja Labz feeds:
  `groups`, `group`, `recent`, `monthly`, `predictions`, `surging`, `predict`, `risk`.
- `ninja` / `ninjasignal` CLI with table or `--json` output.
- Zero runtime dependencies; optional pandas via `frame()`.
- Non-JSON responses are rejected (a stale CDN entry or error page can never be
  parsed into bad data).
