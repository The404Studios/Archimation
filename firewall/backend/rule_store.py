"""
SQLite persistent rule storage for the Windows-style firewall.

Stores firewall rules in a SQLite database so they survive restarts.
The database lives at ``/var/lib/pe-compat/firewall/rules.db`` by
default.  Provides full CRUD, filtering, and JSON import/export.
"""

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from .nft_manager import FirewallRule
except ImportError:
    # When imported outside a package context (e.g. nft_manager.py --daemon
    # inserts the backend directory into sys.path and does a bare
    # "import rule_store"), relative imports fail.  Fall back to absolute.
    from nft_manager import FirewallRule

logger = logging.getLogger("firewall.rule_store")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_DB_DIR = "/var/lib/pe-compat/firewall"
DEFAULT_DB_PATH = os.path.join(DEFAULT_DB_DIR, "rules.db")

_SCHEMA_VERSION = 1

_CREATE_RULES_TABLE = """\
CREATE TABLE IF NOT EXISTS rules (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    direction       TEXT NOT NULL DEFAULT 'inbound',
    action          TEXT NOT NULL DEFAULT 'block',
    protocol        TEXT NOT NULL DEFAULT 'any',
    port            INTEGER,
    port_range      TEXT,
    remote_address  TEXT,
    local_address   TEXT,
    application     TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    profile         TEXT NOT NULL DEFAULT 'public',
    priority        INTEGER NOT NULL DEFAULT 100,
    created_at      TEXT NOT NULL,
    modified_at     TEXT NOT NULL
);
"""

_CREATE_META_TABLE = """\
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class RuleStore:
    """SQLite-backed persistent storage for firewall rules.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  Parent directories are
        created automatically.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_directory()
        try:
            self._connect()
            self._migrate()
        except sqlite3.DatabaseError:
            # Database corrupted (e.g. unclean shutdown on persistent USB).
            # Back up the broken file and start fresh.
            logger.error("Database at %s is corrupted, resetting", db_path)
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
            backup = db_path + ".corrupt"
            try:
                os.replace(db_path, backup)
            except OSError:
                pass
            # Also remove WAL/SHM leftovers
            for suffix in ("-wal", "-shm"):
                try:
                    os.remove(db_path + suffix)
                except OSError:
                    pass
            self._connect()
            self._migrate()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            logger.debug("Database connection closed")

    def __del__(self) -> None:
        """Ensure the database connection is closed on garbage collection."""
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self) -> "RuleStore":
        """Support use as a context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Close the database connection when exiting the context."""
        self.close()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_rule(self, rule: FirewallRule) -> FirewallRule:
        """Insert a new rule into the database.

        Returns the rule (its ``id`` field is guaranteed to be set).
        """
        now = _utcnow_iso()
        self._conn.execute(
            """INSERT INTO rules
               (id, name, direction, action, protocol, port, port_range,
                remote_address, local_address, application, enabled,
                profile, priority, created_at, modified_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rule.id, rule.name, rule.direction, rule.action,
                rule.protocol, rule.port, rule.port_range,
                rule.remote_address, rule.local_address,
                rule.application, int(rule.enabled),
                rule.profile, rule.priority, now, now,
            ),
        )
        self._conn.commit()
        logger.info("Stored rule %s (%s)", rule.id, rule.name)
        return rule

    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        """Fetch a single rule by id.  Returns ``None`` if not found."""
        cursor = self._conn.execute(
            "SELECT * FROM rules WHERE id = ?", (rule_id,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_rule(row)

    def update_rule(self, rule: FirewallRule) -> bool:
        """Update an existing rule.  Returns True if the row existed."""
        now = _utcnow_iso()
        cursor = self._conn.execute(
            """UPDATE rules SET
                   name=?, direction=?, action=?, protocol=?, port=?,
                   port_range=?, remote_address=?, local_address=?,
                   application=?, enabled=?, profile=?, priority=?,
                   modified_at=?
               WHERE id=?""",
            (
                rule.name, rule.direction, rule.action, rule.protocol,
                rule.port, rule.port_range, rule.remote_address,
                rule.local_address, rule.application, int(rule.enabled),
                rule.profile, rule.priority, now, rule.id,
            ),
        )
        self._conn.commit()
        if cursor.rowcount == 0:
            logger.warning("Rule %s not found for update", rule.id)
            return False
        logger.info("Updated rule %s (%s)", rule.id, rule.name)
        return True

    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule by id.  Returns True if it existed."""
        cursor = self._conn.execute(
            "DELETE FROM rules WHERE id = ?", (rule_id,)
        )
        self._conn.commit()
        if cursor.rowcount == 0:
            logger.warning("Rule %s not found for deletion", rule_id)
            return False
        logger.info("Deleted rule %s", rule_id)
        return True

    # ------------------------------------------------------------------
    # Query / List
    # ------------------------------------------------------------------

    def list_rules(
        self,
        direction: Optional[str] = None,
        profile: Optional[str] = None,
        enabled: Optional[bool] = None,
        order_by: str = "priority",
    ) -> list[FirewallRule]:
        """List rules with optional filters.

        Parameters
        ----------
        direction:
            ``"inbound"`` or ``"outbound"``; ``None`` for both.
        profile:
            ``"public"``, ``"private"``, ``"domain"``; ``None`` for all.
        enabled:
            Filter by enabled state; ``None`` for all.
        order_by:
            Column to sort by (default ``"priority"``).
        """
        clauses: list[str] = []
        params: list = []

        if direction is not None:
            clauses.append("direction = ?")
            params.append(direction)
        if profile is not None:
            clauses.append("profile = ?")
            params.append(profile)
        if enabled is not None:
            clauses.append("enabled = ?")
            params.append(int(enabled))

        sql = "SELECT * FROM rules"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)

        # Whitelist allowed order columns
        allowed_order = {"priority", "name", "created_at", "modified_at", "direction"}
        if order_by not in allowed_order:
            order_by = "priority"
        sql += f" ORDER BY {order_by}"

        cursor = self._conn.execute(sql, params)
        return [self._row_to_rule(row) for row in cursor.fetchall()]

    def count_rules(
        self,
        direction: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> int:
        """Return the number of rules matching the filters."""
        clauses: list[str] = []
        params: list = []
        if direction:
            clauses.append("direction = ?")
            params.append(direction)
        if profile:
            clauses.append("profile = ?")
            params.append(profile)

        sql = "SELECT COUNT(*) FROM rules"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        cursor = self._conn.execute(sql, params)
        return cursor.fetchone()[0]

    # ------------------------------------------------------------------
    # Import / Export
    # ------------------------------------------------------------------

    def export_json(self, pretty: bool = True) -> str:
        """Export all rules as a JSON string."""
        rules = self.list_rules()
        data = [r.to_dict() for r in rules]
        return json.dumps(data, indent=2 if pretty else None)

    def import_json(self, data: str, replace: bool = False) -> int:
        """Import rules from a JSON string.

        Parameters
        ----------
        data:
            JSON array of rule dictionaries.
        replace:
            If True, delete all existing rules first.

        Returns the number of rules imported.
        """
        items = json.loads(data)
        if not isinstance(items, list):
            raise ValueError("Expected a JSON array of rule objects")

        if replace:
            self._conn.execute("DELETE FROM rules")
            # No commit yet -- rolled into the single batch commit below.
            logger.info("Cleared existing rules for import")

        # Batch inserts/updates into a single transaction.  The per-rule
        # add_rule()/update_rule() paths each commit after every rule, which
        # is O(N) fsyncs for an N-rule import.
        count = 0
        now = _utcnow_iso()
        for item in items:
            rule = FirewallRule.from_dict(item)
            try:
                self._conn.execute(
                    """INSERT INTO rules
                       (id, name, direction, action, protocol, port, port_range,
                        remote_address, local_address, application, enabled,
                        profile, priority, created_at, modified_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        rule.id, rule.name, rule.direction, rule.action,
                        rule.protocol, rule.port, rule.port_range,
                        rule.remote_address, rule.local_address,
                        rule.application, int(rule.enabled),
                        rule.profile, rule.priority, now, now,
                    ),
                )
                count += 1
            except sqlite3.IntegrityError:
                # Duplicate id -- update in place
                self._conn.execute(
                    """UPDATE rules SET
                           name=?, direction=?, action=?, protocol=?, port=?,
                           port_range=?, remote_address=?, local_address=?,
                           application=?, enabled=?, profile=?, priority=?,
                           modified_at=?
                       WHERE id=?""",
                    (
                        rule.name, rule.direction, rule.action, rule.protocol,
                        rule.port, rule.port_range, rule.remote_address,
                        rule.local_address, rule.application, int(rule.enabled),
                        rule.profile, rule.priority, now, rule.id,
                    ),
                )
                count += 1
        self._conn.commit()

        logger.info("Imported %d rules from JSON", count)
        return count

    def export_to_file(self, path: str) -> None:
        """Export rules as JSON to *path*."""
        content = self.export_json()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        logger.info("Exported rules to %s", path)

    def import_from_file(self, path: str, replace: bool = False) -> int:
        """Import rules from a JSON file at *path*."""
        with open(path, "r") as fh:
            data = fh.read()
        return self.import_json(data, replace=replace)

    # ------------------------------------------------------------------
    # Convenience wrappers expected by the GUI and CLI
    # ------------------------------------------------------------------

    def get_rules(self, direction: str = None) -> list[dict]:
        """Return rules as a list of dicts, optionally filtered by direction.

        This is a wrapper around :meth:`list_rules` that converts
        ``FirewallRule`` objects to plain dictionaries so that GUI and
        CLI code can use ``rule.get("field")`` style access.
        """
        rules = self.list_rules(direction=direction)
        return [r.to_dict() for r in rules]

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        """Update a rule's enabled status in the database."""
        rule = self.get_rule(str(rule_id))
        if rule is None:
            logger.warning("Rule %s not found for enable/disable", rule_id)
            return
        rule.enabled = enabled
        self.update_rule(rule)
        logger.info("Rule %s %s", rule_id, "enabled" if enabled else "disabled")

    def blocked_count_today(self) -> int:
        """Return the count of blocked connections today.

        This is a stub; a full implementation would query nftables
        counters or a log database.
        """
        return 0

    def import_rules(self, path: str) -> int:
        """Import rules from a JSON file.  Alias for :meth:`import_from_file`."""
        return self.import_from_file(path)

    def export_rules(self, path: str) -> None:
        """Export rules to a JSON file.  Alias for :meth:`export_to_file`."""
        self.export_to_file(path)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _ensure_directory(self) -> None:
        """Create the parent directory for the database file."""
        parent = os.path.dirname(self._db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _connect(self) -> None:
        """Open (or create) the SQLite database."""
        # isolation_level=None lets us control transaction boundaries
        # explicitly via BEGIN/COMMIT.  We intentionally keep the
        # default deferred behaviour, but setting busy_timeout below
        # means we get a clean retry under WAL when GUI + CLI hit the
        # DB concurrently instead of an SQLITE_BUSY exception.
        self._conn = sqlite3.connect(self._db_path, timeout=5.0)
        self._conn.row_factory = sqlite3.Row
        # Enable WAL for concurrent reads
        self._conn.execute("PRAGMA journal_mode=WAL")
        # On old/slow disks a full fsync per commit dominates latency;
        # NORMAL is still crash-safe under WAL (only a checkpoint failure
        # can lose a committed transaction).
        self._conn.execute("PRAGMA synchronous=NORMAL")
        # 2 MiB page cache -- default is 2000 pages (~8 MiB on 4k), but
        # the negative form pins memory in bytes and is cheaper on RAM
        # constrained old hardware while still covering the typical
        # rule table many times over.
        self._conn.execute("PRAGMA cache_size=-2000")
        # Keep temp state in memory rather than on disk.
        self._conn.execute("PRAGMA temp_store=MEMORY")
        self._conn.execute("PRAGMA foreign_keys=ON")
        # 5 s busy_timeout matches the Python-level connect timeout and
        # prevents spurious SQLITE_BUSY on systems where the GUI, CLI,
        # and daemon may open the DB concurrently.  WAL allows multi-
        # reader + single-writer; the busy timeout gives writers a
        # window to queue up instead of failing outright.
        self._conn.execute("PRAGMA busy_timeout=5000")
        # mmap lets SQLite skip page-copy syscalls for read-heavy
        # workloads like our list_rules() path.  32 MiB is far more
        # than we need for a typical rule set but is cheap when the
        # file is small (only actually-accessed pages get mapped).
        try:
            self._conn.execute("PRAGMA mmap_size=33554432")
        except sqlite3.OperationalError:
            # mmap unsupported on this platform (older SQLite) -- ignore
            pass
        logger.debug("Opened database at %s", self._db_path)

    def _migrate(self) -> None:
        """Create or migrate the schema.

        Reads the stored ``schema_version`` from the ``meta`` table before
        overwriting it so future version bumps can run migration steps.
        Previously this unconditionally ``INSERT OR REPLACE``d the version,
        which would silently mask the presence of an older on-disk schema.
        """
        self._conn.executescript(_CREATE_RULES_TABLE)
        self._conn.executescript(_CREATE_META_TABLE)

        # Indexes on columns commonly used in WHERE / ORDER BY clauses.
        # CREATE INDEX IF NOT EXISTS is idempotent so this is safe across
        # migrations without touching the schema_version.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rules_direction ON rules(direction)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rules_profile ON rules(profile)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rules_dir_prof ON rules(direction, profile)"
        )
        # GUI and daemon commonly filter by (direction, enabled) when
        # showing active rules only; add a covering index so we can
        # skip the full table scan on largish rule sets.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rules_dir_enabled "
            "ON rules(direction, enabled)"
        )
        # list_rules() sorts by priority after filtering on direction.
        # A composite index lets SQLite serve both the WHERE and the
        # ORDER BY from a single structure.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rules_dir_prio "
            "ON rules(direction, priority)"
        )
        # Application-path lookups are used by the AppTracker / dashboard
        # when cross-referencing the rule set against tracked exes.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rules_application "
            "ON rules(application) WHERE application IS NOT NULL"
        )

        # Read existing schema version so callers can key future migration
        # steps off of it.  An older DB (version < _SCHEMA_VERSION) is
        # upgraded in-place; a newer one (future _SCHEMA_VERSION) is
        # logged but left alone.
        cursor = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", ("schema_version",)
        )
        row = cursor.fetchone()
        try:
            current_version = int(row["value"]) if row else 0
        except (ValueError, TypeError):
            current_version = 0

        if current_version > _SCHEMA_VERSION:
            logger.warning(
                "DB schema version %d newer than code %d -- "
                "running code may not understand new columns",
                current_version, _SCHEMA_VERSION,
            )
        elif current_version < _SCHEMA_VERSION:
            logger.info(
                "Upgrading DB schema from v%d to v%d",
                current_version, _SCHEMA_VERSION,
            )
            # Future: add per-version migration steps here.

        # Record the resolved version.
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            ("schema_version", str(_SCHEMA_VERSION)),
        )
        self._conn.commit()
        logger.debug("Schema version %d ready", _SCHEMA_VERSION)

    def get_schema_version(self) -> int:
        """Return the on-disk schema version (0 if missing or malformed)."""
        cursor = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", ("schema_version",)
        )
        row = cursor.fetchone()
        try:
            return int(row["value"]) if row else 0
        except (ValueError, TypeError):
            return 0

    @staticmethod
    def _row_to_rule(row: sqlite3.Row) -> FirewallRule:
        """Convert a database row to a FirewallRule."""
        return FirewallRule(
            id=row["id"],
            name=row["name"],
            direction=row["direction"],
            action=row["action"],
            protocol=row["protocol"],
            port=row["port"],
            port_range=row["port_range"],
            remote_address=row["remote_address"],
            local_address=row["local_address"],
            application=row["application"],
            enabled=bool(row["enabled"]),
            profile=row["profile"],
            priority=row["priority"],
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()
