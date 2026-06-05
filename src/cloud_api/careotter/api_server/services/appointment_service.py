"""
appointment_service.py — CareOtter teleconsultation booking.

Backs OWASP API6:2023 (Unrestricted Access to Sensitive Business Flows): patients book a
scarce set of cardiology appointment slots. The flow is intentionally reachable by any
authenticated patient (`@token_required`) — that is correct, not the bug.

The per-patient cap (`MAX_ACTIVE_APPOINTMENTS`) is ALWAYS enforced, and it is checked against
the denormalized `users.active_appointments` counter rather than a live COUNT over the slots.

Secure (`VULNERABLE=0`): cancellation validates the HTTP method first (POST only) and releases
the slot and decrements the counter together, atomically — the counter never drifts.

Vulnerable (`VULNERABLE=1`): the cancel flow decrements the counter BEFORE it checks the
method, and only POST actually releases the slot. A non-POST cancel (DELETE / GET) therefore
lowers the counter while leaving the booking in place — a counter desync that lets one patient
re-book and hoard every slot past the cap (denial of care). The slot claim stays atomic in both
modes, so two patients never double-book — this is a clean API6 business-flow flaw, not a race.
"""

import logging

from config import Config

logger = logging.getLogger(__name__)


class AppointmentService:
    """Booking rules. Holds the single toggle that exposes API6; raw persistence lives in
    DatabaseService."""

    MAX_ACTIVE_APPOINTMENTS = 2   # per-patient active-booking cap (secure mode)

    def __init__(self, db):
        self.db = db

    def get_slots(self):
        """All currently-open (bookable) slots."""
        return self.db.list_open_slots()

    def get_mine(self, username):
        """The caller's active bookings."""
        return self.db.slots_for_user(username)

    def book(self, username, slot_id):
        # The per-patient cap is ALWAYS enforced here, against users.active_appointments.
        # The API6 weakness is NOT cap removal — it is the cancel-flow counter desync (see
        # cancel()), which lets an attacker lower the counter without giving up a slot.
        return self.db.book_slot(username, slot_id, max_active=self.MAX_ACTIVE_APPOINTMENTS)

    def cancel(self, username, slot_id, http_method='POST'):
        # API6: in vulnerable mode the cancel flow decrements the per-patient counter BEFORE it
        # validates the HTTP method, so a non-POST request (DELETE / GET) lowers the counter
        # while leaving the slot booked — a desync that lets one patient hoard slots past the
        # cap. Secure mode validates the method first and releases slot + counter atomically.
        vulnerable = (Config.VULNERABLE == 1)
        return self.db.cancel_slot(username, slot_id,
                                   http_method=http_method, vulnerable=vulnerable)