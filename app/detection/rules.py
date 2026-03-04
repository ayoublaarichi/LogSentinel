"""
Detection rules definitions.

Each rule is a dataclass describing the detection logic parameters.
The actual evaluation happens in the engine module.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionRule:
    """Specification of a single detection rule."""

    name: str
    description: str
    severity: str          # low | medium | high | critical
    event_types: list[str] # which event_types to evaluate
    log_source: str        # "auth" or "nginx"
    threshold: int         # minimum events to trigger
    window_minutes: int    # time window in minutes


# ── Built-in rules ───────────────────────────────────────────────────────────

SSH_BRUTE_FORCE = DetectionRule(
    name="Brute Force Login",
    description=(
        "Detected {count} failed login attempts from {ip} "
        "within {window} minutes (threshold: {threshold})."
    ),
    severity="high",
    event_types=["ssh_failed_login", "ssh_invalid_user"],
    log_source="auth",
    threshold=5,
    window_minutes=2,
)

NGINX_REQUEST_FLOOD = DetectionRule(
    name="Nginx Request Flood",
    description=(
        "Detected {count} HTTP requests from {ip} "
        "within {window} minutes (threshold: {threshold})."
    ),
    severity="medium",
    event_types=["http_ok", "http_client_error", "http_server_error"],
    log_source="nginx",
    threshold=200,
    window_minutes=2,
)

# Registry of all active rules
ACTIVE_RULES: list[DetectionRule] = [SSH_BRUTE_FORCE, NGINX_REQUEST_FLOOD]
