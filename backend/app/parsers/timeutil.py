from datetime import datetime, timezone

# The database stores naive UTC timestamps (SQLite has no tz-aware column), so
# every "now" in the codebase funnels through this one helper instead of the
# deprecated datetime.utcnow(). To make the result timezone-aware, wrap it:
# value.replace(tzinfo=timezone.utc).
def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_from_timestamp(value: float) -> datetime:
    """Convert a Unix epoch timestamp to the naive-UTC form used by the database."""
    return datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
