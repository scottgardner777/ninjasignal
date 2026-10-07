"""ninjasignal — the Python client for Ninja Labz predictive threat intelligence.

Ninja Labz tracks the ransomware ecosystem on live data and publishes what it
predicts next. This library is a thin, dependency-free reader over the public
feeds — it talks only to https://ninjalabz.io and reads open CC-BY data.

    import ninjasignal as ns
    ns.surging()            # groups accelerating right now
    ns.predict("qilin")     # what the lab predicts for a group
    ns.groups()             # active groups + victim counts
    ns.recent(limit=20)     # latest claimed victims

IP boundary: this client embodies NONE of Ninja Labz's predictive methods. It
only consumes already-published outputs. The models and systems behind those
outputs are proprietary and patent-pending, and nothing here licenses them.
"""
from __future__ import annotations

from .client import Client, NinjaSignalError, DEFAULT_BASE

__all__ = ["Client", "NinjaSignalError", "DEFAULT_BASE", "__version__",
           "groups", "group", "recent", "monthly", "predictions", "surging",
           "predict", "risk", "latest_month"]

__version__ = "0.1.0"

_default: Client | None = None


def _client() -> Client:
    global _default
    if _default is None:
        _default = Client()
    return _default


# Module-level convenience wrappers over a shared default Client.
def groups():
    return _client().groups()


def group(slug: str):
    return _client().group(slug)


def recent(limit: int | None = None, group: str | None = None,
           sector: str | None = None, country: str | None = None):
    return _client().recent(limit=limit, group=group, sector=sector, country=country)


def monthly():
    return _client().monthly()


def predictions(kind: str | None = None):
    return _client().predictions(kind=kind)


def surging():
    return _client().surging()


def predict(group: str):
    return _client().predict(group)


def risk(sector: str | None = None, country: str | None = None):
    return _client().risk(sector=sector, country=country)


def latest_month():
    return _client().latest_month()
