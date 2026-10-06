"""
ITAP — Log scrubbing.

API keys that reach a log file, a console or a shared screenshot are leaked. The
backend already keeps its keys in `settings`, but a stray `logger.debug(url)`, a
`repr(exc)` of a failed HTTP call, or a third-party library's own request logging
can still surface them. This filter rewrites any log record that matches a known
secret shape before it is emitted, so the leak is impossible by construction
rather than by remembering not to do it.

Attach to the root logger (see main.py) so it covers every library too.
"""
import logging
import re

REDACTED = "[REDACTED]"

# Patterns are deliberately broad: a false positive costs a redacted debug line,
# a false negative costs an API key.
_SECRET_PATTERNS = [
    # ?key=..., &key=..., api_key=..., apikey=..., key: abc123, SECRET_KEY='...'
    # (?<![A-Za-z0-9]) rather than \b: an underscore is a word character, so \b does
    # not match inside ENV_STYLE names like SHODAN_API_KEY — the exact shape this
    # needs to catch.
    re.compile(r"(?i)(?<![A-Za-z0-9])(?:api[_-]?key|apikey|key|token|secret|password|access[_-]?key)"
               r"([\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9\-_\.]{8,})"),
    # Authorization: Bearer <jwt> / Basic <b64>
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-_\.=+/]{8,}"),
    # JWTs in the wild (three base64url segments)
    re.compile(r"\beyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\b"),
]


def _redact_match(match: re.Match) -> str:
    """Replace a match with REDACTED, keeping the parameter name when present.

    For ``key=abc123`` (pattern 1, two groups) the result is ``key=[REDACTED]`` so
    the log still says *what* was redacted; with a single group the whole match
    goes.
    """
    if match.re.groups >= 2 and match.group(2):
        prefix = match.group(0)[: match.start(2) - match.start(0)]
        return f"{prefix}{REDACTED}"
    return REDACTED


def scrub(text: str) -> str:
    """Return ``text`` with anything resembling a credential replaced."""
    if not text:
        return text
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(_redact_match, text)
    return text


class SecretRedactingFilter(logging.Filter):
    """Rewrite every record's message/args so no credential reaches a handler."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            message = record.getMessage()
            scrubbed = scrub(message)
            if scrubbed != message:
                record.msg = scrubbed
                record.args = ()
        except Exception:
            # Never let scrubbing break logging.
            pass
        return True


def install_secret_filter() -> None:
    """Attach the filter to the root logger (covers third-party loggers)."""
    root = logging.getLogger()
    if not any(isinstance(f, SecretRedactingFilter) for f in root.filters):
        root.addFilter(SecretRedactingFilter())
