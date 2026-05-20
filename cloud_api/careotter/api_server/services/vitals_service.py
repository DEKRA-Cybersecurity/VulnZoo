"""
vitals_service.py — DEPRECATED

This module previously provided direct HTTP polling to the bedside sensor.
In the push architecture the Pi sends vitals to POST /api/device/vitals,
so this service is no longer used by the Cloud API.

Kept as a stub to avoid breaking any legacy imports.
"""


class VitalsService:
    """Stub — all pull methods have been removed."""

    def __init__(self):
        pass
