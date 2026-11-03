"""The Ninja Signal client — a thin, dependency-free reader over the public
Ninja Labz predictive threat-intelligence feeds.

Everything here talks to ONE public host (https://ninjalabz.io) over HTTPS and
reads only the open, CC-BY data feeds under /feeds/ransomware/. There are no
credentials, no private endpoints, and nothing internal — point it somewhere else
with `Client(base=...)` if you mirror the feeds yourself.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

__all__ = ["Client", "NinjaSignalError"]

DEFAULT_BASE = "https://ninjalabz.io"
_FEED = "/feeds/ransomware"


class NinjaSignalError(RuntimeError):
    """Raised when a feed can't be fetched or isn't valid JSON."""


class Client:
    """Reader for the Ninja Labz predictive-intel feeds.

    >>> from ninjasignal import Client
    >>> nl = Client()
    >>> [g["name"] for g in nl.groups()][:3]
    """

    def __init__(self, base: str = DEFAULT_BASE, timeout: float = 15.0,
                 cache_ttl: float = 300.0, user_agent: str | None = None):
        self.base = base.rstrip("/")
        # Honour the HTTPS-only contract: reject file://, ftp://, bare paths, etc.
        # so a mistyped mirror can't turn into a local-file read or cleartext fetch.
        scheme = urllib.parse.urlsplit(self.base).scheme
        if scheme not in ("http", "https"):
            raise ValueError(f"base must be an http(s) URL, got {base!r}")
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.user_agent = user_agent or "ninjasignal-python"
        self._cache: dict[str, tuple[float, dict]] = {}

    # ── transport ────────────────────────────────────────────────────────────
    def _get(self, path: str) -> dict:
        now = time.time()
        hit = self._cache.get(path)
        if hit and (now - hit[0]) < self.cache_ttl:
            return hit[1]
        url = self.base + path
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent,
                                                    "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raise NinjaSignalError(f"{url} returned HTTP {e.code}") from e
        except urllib.error.URLError as e:
            raise NinjaSignalError(f"could not reach {url}: {e.reason}") from e
        stripped = raw.lstrip()
        if not stripped or stripped[0] not in "{[":
            # a feed is always JSON; anything else (an error page, a stale CDN
            # entry) is rejected rather than parsed into nonsense.
            raise NinjaSignalError(f"{url} did not return JSON (got {stripped[:40]!r}…)")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise NinjaSignalError(f"{url} returned invalid JSON: {e}") from e
        self._cache[path] = (now, data)
        return data

    def _feed(self, name: str) -> dict:
        return self._get(f"{_FEED}/{name}.js")

    # ── data feeds ───────────────────────────────────────────────────────────
    def groups(self) -> list[dict]:
        """Active ransomware groups: victim counts, top sector/country, origin."""
        return self._feed("groups").get("groups", [])

    def group(self, slug: str) -> dict:
        """Full dossier data for one group (victims, sectors, countries, recent)."""
        slug = slug.strip().lower().replace(" ", "")
        return self._feed(f"group-{slug}")

    def recent(self, limit: int | None = None, group: str | None = None,
               sector: str | None = None, country: str | None = None) -> list[dict]:
        """Recent claimed victims (date, group, victim, sector, country), newest first,
        optionally filtered."""
        vics = self._feed("victims-recent").get("victims", [])

        def keep(v: dict) -> bool:
            if group and (v.get("group") or "").lower() != group.lower():
                return False
            if sector and (v.get("sector") or "").lower() != sector.lower():
                return False
            if country and (v.get("country") or "").lower() != country.lower():
                return False
            return True

        out = [v for v in vics if keep(v)]
        return out[:limit] if limit is not None else out

    def monthly(self) -> list[dict]:
        """Per-month totals + top groups (the time series behind the trends)."""
        return self._feed("stats-monthly").get("months", [])

    # ── predictions (the differentiator) ─────────────────────────────────────
    def predictions(self, kind: str | None = None) -> list[dict]:
        """The lab's live predictions: {type, subject, statement, confidence, basis}.
        `kind` filters by type (rising_group | likely_target | momentum | watch)."""
        preds = self._feed("predictions").get("predictions", [])
        return [p for p in preds if (not kind or p.get("type") == kind)]

    def surging(self) -> list[dict]:
        """Groups the lab flags as accelerating right now (type=rising_group)."""
        return self.predictions(kind="rising_group")

    def predict(self, group: str) -> list[dict]:
        """Predictions whose subject matches a group (case-insensitive)."""
        g = group.strip().lower()
        return [p for p in self.predictions() if g in (p.get("subject") or "").lower()]

    # ── a small derived signal: exposure/risk ────────────────────────────────
    def risk(self, sector: str | None = None, country: str | None = None) -> dict:
        """A simple, transparent exposure score from the recent-victim mix.

        Score = this sector's (or country's) share of recent claims, scaled to the
        busiest sector/country = 100. It's a descriptive concentration measure, not a
        probabilistic forecast — see `predictions()` for the model's forward calls.
        """
        vics = self.recent()
        if not vics:
            return {"score": 0, "basis": "no recent data"}
        field = "sector" if sector else "country" if country else "sector"
        target = (sector or country or "").lower()
        counts: dict[str, int] = {}
        for v in vics:
            key = (v.get(field) or "unknown")
            counts[key] = counts.get(key, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
        top = ranked[0][1] if ranked else 1
        if not target:
            return {"field": field, "ranking": [{field: k, "recent_claims": n,
                     "score": round(100 * n / top)} for k, n in ranked[:15]],
                    "window_claims": len(vics)}
        n = next((c for k, c in counts.items() if k.lower() == target), 0)
        rank = next((i + 1 for i, (k, _) in enumerate(ranked) if k.lower() == target), None)
        return {field: sector or country, "recent_claims": n,
                "score": round(100 * n / top), "rank": rank,
                "of": len(ranked), "window_claims": len(vics)}

    # ── convenience ──────────────────────────────────────────────────────────
    def latest_month(self) -> dict:
        months = self.monthly()
        return months[0] if months else {}

    def frame(self, rows: list[dict]):
        """Return rows as a pandas DataFrame if pandas is installed, else the list.
        Keeps pandas an optional convenience, never a hard dependency."""
        try:
            import pandas as pd  # noqa: PLC0415
        except ImportError:
            return rows
        return pd.DataFrame(rows)
