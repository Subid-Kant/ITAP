# ITAP — time helpers.
from datetime import datetime, timezone


def utcnow() -> datetime:
    """Naive UTC now — the replacement for the deprecated ``datetime.utcnow()``.

    ``datetime.utcnow()`` has been deprecated since Python 3.12 (it returns a
    naive object while claiming to be UTC, which invites tz mix-ups). This keeps
    the *exact* previous semantics — a naive UTC timestamp — so existing
    ``DateTime`` columns, serialized strings and comparisons behave identically;
    the only difference is that no DeprecationWarning is raised.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)