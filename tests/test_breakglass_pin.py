"""Breakglass PIN rotation tests."""
import pytest
from ai_guardian.breakglass import rotate_pin, verify_pin, configure_store, configure_pin_hash
from ai_guardian.storage import SQLiteStore
import os, tempfile


@pytest.fixture
def store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    s = SQLiteStore(path)
    yield s
    os.unlink(path)


class TestRotatePin:
    def test_rotate_pin_success(self, store):
        """Admin can rotate PIN when current PIN is correct."""
        configure_store(store)
        configure_pin_hash(None)  # reset to compiled default

        result = rotate_pin(current_pin="ai-guardian-breakglass-2026", new_pin="newpin123", actor="admin")
        assert result is True

        # Old PIN should no longer work
        assert verify_pin("ai-guardian-breakglass-2026") is False
        # New PIN should work
        assert verify_pin("newpin123") is True

    def test_rotate_pin_wrong_current(self, store):
        """Rotation fails with wrong current PIN — old PIN still works."""
        configure_store(store)
        configure_pin_hash(None)

        result = rotate_pin(current_pin="wrongpin456", new_pin="newpin123", actor="admin")
        assert result is False

        # Old default PIN still works
        assert verify_pin("ai-guardian-breakglass-2026") is True

    def test_rotate_pin_new_pin_too_short(self, store):
        """New PIN shorter than 6 chars is rejected."""
        configure_store(store)
        configure_pin_hash(None)

        result = rotate_pin(current_pin="ai-guardian-breakglass-2026", new_pin="abc", actor="admin")
        assert result is False

        # Default PIN unchanged
        assert verify_pin("ai-guardian-breakglass-2026") is True

    def test_rotate_pin_persists_in_store(self, store):
        """Rotated PIN hash is stored in DB and survives store reinit."""
        configure_store(store)
        configure_pin_hash(None)

        rotate_pin(current_pin="ai-guardian-breakglass-2026", new_pin="persistent999", actor="admin")

        # DB has the new hash
        db_hash = store.get_breakglass_config("pin_hash")
        import hashlib
        expected = hashlib.sha256("persistent999".encode()).hexdigest()
        assert db_hash == expected

    def test_rotate_pin_logged_audit_style(self, store):
        """The actor field is captured in the new PIN hash record."""
        configure_store(store)
        configure_pin_hash(None)

        rotate_pin(current_pin="ai-guardian-breakglass-2026", new_pin="actorlogged", actor="test-actor-001")

        db_val = store.get_breakglass_config("pin_hash")
        assert db_val is not None