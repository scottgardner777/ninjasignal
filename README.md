# ninjasignal

**The Python client for [Ninja Labz](https://ninjalabz.io) predictive threat intelligence.**

Ninja Labz tracks the ransomware ecosystem on live data and publishes *what it predicts next* — surging groups, new entrants, sectors in the crosshairs, and calibrated forward calls. `ninjasignal` puts that in three lines of Python.

```bash
pip install ninjasignal
```

```python
import ninjasignal as ns

ns.surging()          # groups accelerating right now
ns.predict("qilin")   # what the lab predicts for a group
ns.groups()           # active groups + victim counts, top sector/country, origin
ns.recent(limit=20)   # latest claimed victims (date, group, sector, country)
```

Zero runtime dependencies. Talks only to the public feeds over HTTPS. Pandas is an optional convenience, never required.

---

## Why

Ransomware intel is everywhere; *predictive* ransomware intel, published openly, is not. Ninja Labz runs an AI-native lab that scans dated victim activity, scores the ecosystem, and calls what's next — then publishes it. This library is how you consume it from a notebook, a pipeline, or a terminal.

## CLI

Installs `ninja` (and `ninjasignal`):

```bash
ninja surging                       # groups accelerating now
ninja predict qilin                 # the lab's calls for a group
ninja groups                        # active groups
ninja recent --limit 20 --sector Healthcare
ninja report                        # latest monthly stats
ninja risk --sector Healthcare      # exposure concentration (descriptive)
```

Add `--json` to any command for raw output, `--base URL` to point at a mirror.

## API

| Call | Returns |
|------|---------|
| `ns.groups()` | active ransomware groups: `name, victims, top_sector, top_country, origin, sanctioned` |
| `ns.group(slug)` | one group's full dossier data (sectors, countries, recent, aliases) |
| `ns.recent(limit=, group=, sector=, country=)` | recent claimed victims, newest first |
| `ns.monthly()` | per-month totals + top groups (the trend series) |
| `ns.predictions(kind=)` | the lab's predictions: `type, subject, statement, confidence, basis` |
| `ns.surging()` | predictions of type `rising_group` |
| `ns.predict(group)` | predictions matching a group |
| `ns.risk(sector=, country=)` | a transparent exposure-concentration score (see note) |

Use a `Client` directly to set caching / host:

```python
from ninjasignal import Client
nl = Client(cache_ttl=600)
nl.frame(nl.groups())   # a pandas DataFrame if pandas is installed, else a list
```

> **Note on `risk()`** — this is a simple, transparent *descriptive* measure (a sector's share of recent claims, scaled 0–100). It is **not** a probabilistic forecast and **not** the lab's model. For the model's forward calls, use `predictions()`.

## Data & provenance

All data comes from the public feeds under `https://ninjalabz.io/feeds/`, documented at **<https://ninjalabz.io/feeds/>**. The monthly **Predictive Intel Report** lives at **<https://ninjalabz.io/intel-report/>**.

- **Data license:** Creative Commons Attribution 4.0 (CC BY 4.0). Attribute *"Ninja Labz — ninjalabz.io"*.
- **This client's code:** Apache License 2.0.

## Intellectual property

This client library **embodies none of Ninja Labz's predictive methods** — it only reads already-published outputs. The models, correlation/inference algorithms, and systems that produce those outputs are **proprietary to Ninja Labz and patent-pending**. Neither the Apache-2.0 code license nor the CC-BY data license grants any right to those methods. See [`NOTICE`](NOTICE).

## Contributing & security

Issues and PRs welcome for the client itself. Please report security concerns privately via GitHub Security Advisories — see [`SECURITY.md`](SECURITY.md).

---

*Built by [Ninja Labz](https://ninjalabz.io) — the name in predictive threat intelligence.*
