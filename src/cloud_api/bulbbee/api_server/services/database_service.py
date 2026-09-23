"""database_service.py - SQLAlchemy persistence for the BulbBee cloud API.

Replaces the in-process dicts (users / bulbs / claims) with a SQLite database
through SQLAlchemy. Users are seeded (no signup). A bulb row holds both the
account binding (owner, device_id) and the last known lighting state.

The seeded passwords are only verified in secure mode (the default login ignores
them, API2). Nothing here changes the intentional weaknesses, it only moves the
state into a database.
"""

import json
import logging
import os
import time

from sqlalchemy import create_engine, Column, String, Boolean, Integer, Float
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bulbbee")

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True)
    role = Column(String, nullable=False, default="user")
    password = Column(String, nullable=False, default="")


class Bulb(Base):
    __tablename__ = "bulbs"
    bulb_id = Column(String, primary_key=True)
    owner = Column(String, nullable=False)
    device_id = Column(String, index=True)
    binding_token = Column(String, default="")
    power = Column(Boolean, default=False)
    brightness = Column(Integer, nullable=True)
    color = Column(String, default="[0,0,0]")     # JSON-encoded [r,g,b]
    scene = Column(String, nullable=True)


class Claim(Base):
    __tablename__ = "claims"
    token = Column(String, primary_key=True)
    user = Column(String, nullable=False)
    exp = Column(Float, nullable=False)
    used = Column(Boolean, default=False)


class Event(Base):
    """Temporal server event log: what happened and when."""
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(Float, nullable=False)
    kind = Column(String, nullable=False)
    message = Column(String, nullable=False)


class DatabaseService:
    """SQLite/SQLAlchemy store for users, bulb bindings + state, and claims."""

    def __init__(self, url):
        args = {}
        if url.startswith("sqlite"):
            args["connect_args"] = {"check_same_thread": False}
            if url in ("sqlite://", "sqlite:///:memory:"):
                args["poolclass"] = StaticPool     # keep one in-memory connection
            elif url.startswith("sqlite:///"):
                d = os.path.dirname(url[len("sqlite:///"):])
                if d:
                    os.makedirs(d, exist_ok=True)
        self.engine = create_engine(url, **args)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    # ── seed (pre-created accounts + the two demo bulbs) ────────────────────

    def seed(self):
        with self.Session() as s:
            if s.query(User).count() == 0:
                s.add_all([
                    User(username="alice", role="user", password="alice123"),
                    User(username="bob", role="user", password="bob123"),
                    User(username="admin", role="admin", password="admin123"),
                ])
            if s.query(Bulb).count() == 0:
                s.add_all([
                    Bulb(bulb_id="bulb-1", owner="alice", device_id="bee-0001", binding_token="seed"),
                    Bulb(bulb_id="bulb-2", owner="bob", device_id="bee-0002", binding_token="seed"),
                ])
            s.commit()

    # ── users ───────────────────────────────────────────────────────────────

    def get_user(self, username):
        with self.Session() as s:
            u = s.get(User, username)
            return {"username": u.username, "role": u.role, "password": u.password} if u else None

    # ── bulbs ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _dict(b):
        d = {"owner": b.owner, "device_id": b.device_id, "binding_token": b.binding_token,
             "power": b.power, "color": json.loads(b.color or "[0,0,0]")}
        if b.brightness is not None:
            d["brightness"] = b.brightness
        if b.scene is not None:
            d["scene"] = b.scene
        return d

    def get_bulb(self, bulb_id):
        with self.Session() as s:
            b = s.get(Bulb, bulb_id)
            return self._dict(b) if b else None

    def all_bulbs(self):
        with self.Session() as s:
            return {b.bulb_id: self._dict(b) for b in s.query(Bulb).all()}

    def bulbs_by_owner(self, owner):
        with self.Session() as s:
            return {b.bulb_id: self._dict(b) for b in s.query(Bulb).filter_by(owner=owner).all()}

    def bulb_for_device(self, device_id):
        with self.Session() as s:
            b = s.query(Bulb).filter_by(device_id=device_id).first()
            return b.bulb_id if b else None

    @staticmethod
    def _new_bulb_id(s):
        n = 1
        while s.get(Bulb, "bulb-%d" % n) is not None:
            n += 1
        return "bulb-%d" % n

    def bind(self, device_id, owner, token="", bulb_id=None):
        """Create or update the device -> owner binding, returning the bulb_id."""
        with self.Session() as s:
            if bulb_id is None:
                prior = s.query(Bulb).filter_by(device_id=device_id).first()
                bulb_id = prior.bulb_id if prior else self._new_bulb_id(s)
            b = s.get(Bulb, bulb_id)
            if b is None:
                b = Bulb(bulb_id=bulb_id, owner=owner, device_id=device_id,
                         binding_token=token, color="[0,0,0]")
                s.add(b)
            else:
                b.owner = owner
                b.device_id = device_id
                b.binding_token = token
            s.commit()
            return bulb_id

    def update_bulb(self, bulb_id, data):
        """Update the lighting fields present in `data` (power/brightness/color/scene)."""
        with self.Session() as s:
            b = s.get(Bulb, bulb_id)
            if b is None:
                return
            if "power" in data:
                b.power = bool(data["power"])
            if "brightness" in data:
                b.brightness = int(data["brightness"])
            if "color" in data:
                b.color = json.dumps(data["color"])
            if "scene" in data:
                b.scene = data["scene"]
            s.commit()

    # ── claims (BULB-R6) ─────────────────────────────────────────────────────

    def add_claim(self, token, user, exp):
        with self.Session() as s:
            s.add(Claim(token=token, user=user, exp=exp, used=False))
            s.commit()

    def get_claim(self, token):
        with self.Session() as s:
            c = s.get(Claim, token)
            return {"user": c.user, "exp": c.exp, "used": c.used} if c else None

    def mark_claim_used(self, token):
        with self.Session() as s:
            c = s.get(Claim, token)
            if c:
                c.used = True
                s.commit()

    # ── event log (temporal record of what the server does) ──────────────────

    def log_event(self, kind, message):
        """Record a server event: a timestamped row in the DB plus a stdout log
        line, so the server keeps a temporal record of what happens."""
        logger.info("[%s] %s", kind, message)
        try:
            with self.Session() as s:
                s.add(Event(ts=time.time(), kind=str(kind), message=str(message)[:500]))
                s.commit()
        except Exception:
            pass

    def recent_events(self, limit=100):
        with self.Session() as s:
            rows = s.query(Event).order_by(Event.id.desc()).limit(limit).all()
            return [{"id": e.id, "ts": e.ts, "kind": e.kind, "message": e.message}
                    for e in reversed(rows)]
