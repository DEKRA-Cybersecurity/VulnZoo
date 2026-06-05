"""
store_service.py — CareOtter "Health Store" business logic.

Backs OWASP API6:2023 (Unrestricted Access to Sensitive Business Flows).

Each patient's wallet is pre-funded with a FIXED device-procurement budget; there is
intentionally NO way to add money (no top-up / salary payout). The sensitive flow is the
**purchase**, against a deliberately scarce catalog.

PHASE 2 (WIRED): with `Config.VULNERABLE == 1` the per-patient purchase quota is removed,
so a single authenticated patient can automate the checkout to buy out the entire scarce
inventory and deny every other patient. Stock and the wallet balance stay enforced in
both modes — the flaw is the missing per-patient quantity limit (the API6 boundary), not
overselling or unpaid purchases. With `VULNERABLE == 0` the quota holds and the abuse
fails.
"""

import logging

from config import Config

logger = logging.getLogger(__name__)


class StoreService:
    """Business rules for the Health Store. Holds the single toggle point that exposes
    API6; the raw persistence lives in DatabaseService."""

    MAX_PER_PRODUCT = 2   # per-patient per-SKU quota (secure mode)

    def __init__(self, db):
        self.db = db

    # ── Catalog ────────────────────────────────────────────────────────────────

    def get_products(self):
        return self.db.list_products(active_only=True)

    def get_product(self, product_id):
        return self.db.get_product(product_id)

    # ── Wallet (read-only — fixed budget, no top-up) ───────────────────────────

    def get_wallet(self, username):
        self.db.ensure_wallet(username)   # lazily seed the fixed-budget wallet on first access
        return self.db.get_wallet(username)

    # ── Purchase ───────────────────────────────────────────────────────────────

    def purchase(self, username, product_id, quantity):
        """Buy `quantity` of a product. Stock and wallet balance are always enforced."""
        self.db.ensure_wallet(username)
        return self.db.try_purchase(
            username, product_id, quantity,
            max_per_product=self.MAX_PER_PRODUCT, check_stock=True)

    def get_orders(self, username):
        return self.db.get_orders(username)
