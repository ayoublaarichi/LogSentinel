"""
LogSentinel — Multi-Tenant SOC Log Analyzer & Detection Dashboard.

A FastAPI-based security operations dashboard that ingests Linux auth.log
and nginx access logs, parses them into structured events, and runs
detection rules to surface actionable alerts.
"""

from app.config import APP_VERSION

__version__ = APP_VERSION
