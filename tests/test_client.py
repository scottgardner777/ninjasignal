"""Offline tests: feed access is monkeypatched so the suite never hits the network."""
import pytest

from ninjasignal import Client, NinjaSignalError

FEEDS = {
    "/feeds/ransomware/groups.js": {"groups": [
        {"slug": "lockbit", "name": "LockBit", "victims": 3315, "top_sector": "Manufacturing",
         "top_country": "US", "origin": "Russia", "sanctioned": True, "apt": False},
        {"slug": "qilin", "name": "Qilin", "victims": 700, "top_sector": "Healthcare",
         "top_country": "US", "origin": "Russia", "sanctioned": False, "apt": False}]},
    "/feeds/ransomware/victims-recent.js": {"victims": [
        {"date": "2026-10-07", "group": "Qilin", "victim": "Acme Health", "sector": "Healthcare", "country": "US"},
        {"date": "2026-10-06", "group": "LockBit", "victim": "Widgets Inc", "sector": "Manufacturing", "country": "DE"},
        {"date": "2026-10-06", "group": "Qilin", "victim": "Clinic Co", "sector": "Healthcare", "country": "GB"}]},
    "/feeds/ransomware/stats-monthly.js": {"months": [
        {"month": "2026-10", "total": 173, "top_groups": [{"name": "Qilin", "victims": 19}]}]},
    "/feeds/ransomware/predictions.js": {"month": "2026-10", "predictions": [
        {"type": "rising_group", "subject": "Qilin", "statement": "expanding in healthcare",
         "confidence": 0.9, "basis": "surge 3x"},
        {"type": "watch", "subject": "LockBit", "statement": "sanctioned, steady", "confidence": 0.7, "basis": ""}]},
    "/feeds/ransomware/group-qilin.js": {"slug": "qilin", "name": "Qilin", "victims": 700,
                                         "sectors": [["Healthcare", 120]], "recent": []},
}


@pytest.fixture
def nl(monkeypatch):
    c = Client(cache_ttl=0)
    monkeypatch.setattr(c, "_get", lambda path: FEEDS[path])
    return c


def test_groups(nl):
    g = nl.groups()
    assert len(g) == 2 and g[0]["name"] == "LockBit"


def test_recent_filters(nl):
    assert len(nl.recent(sector="Healthcare")) == 2
    assert len(nl.recent(group="LockBit")) == 1
    assert len(nl.recent(limit=1)) == 1


def test_predictions_and_surging(nl):
    assert len(nl.predictions()) == 2
    s = nl.surging()
    assert len(s) == 1 and s[0]["subject"] == "Qilin"


def test_predict(nl):
    assert nl.predict("qilin")[0]["type"] == "rising_group"
    assert nl.predict("nonexistent") == []


def test_risk(nl):
    r = nl.risk(sector="Healthcare")
    assert r["recent_claims"] == 2 and r["score"] == 100 and r["rank"] == 1


def test_group(nl):
    assert nl.group("Qilin")["name"] == "Qilin"


def test_non_json_rejected():
    """A stale CDN entry / error page must never be parsed as data."""
    c = Client()

    class FakeResp:
        def read(self): return b"<!doctype html><html>nope</html>"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    import urllib.request
    import pytest as _p
    orig = urllib.request.urlopen
    urllib.request.urlopen = lambda *a, **k: FakeResp()
    try:
        with _p.raises(NinjaSignalError):
            c._get("/feeds/ransomware/groups.js")
    finally:
        urllib.request.urlopen = orig
