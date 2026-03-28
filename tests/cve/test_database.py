"""Tests for CVE database."""

import pytest

from prithvi.cve.database import CVEDatabase


@pytest.fixture
def db(tmp_path):
    database = CVEDatabase(db_path=tmp_path / "test_cve.db")
    yield database
    database.close()


class TestCVEDatabase:
    def test_insert_and_lookup(self, db):
        db.insert_cve(
            cve_id="CVE-2024-0001",
            severity="HIGH",
            description="Test vulnerability",
            published="2024-01-01",
            affected=[{
                "name": "openssl",
                "version_start": "1.0.0",
                "version_end": "1.1.0",
                "ecosystem": "deb",
            }],
        )
        records = db.lookup("openssl", "deb")
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2024-0001"

    def test_lookup_no_match(self, db):
        records = db.lookup("nonexistent", "deb")
        assert len(records) == 0

    def test_cve_count(self, db):
        assert db.cve_count == 0
        db.insert_cve(
            "CVE-2024-0001", "HIGH", "test",
            "2024-01-01",
            [{"name": "pkg", "ecosystem": "deb"}],
        )
        assert db.cve_count == 1

    def test_upsert(self, db):
        db.insert_cve(
            "CVE-2024-0001", "HIGH", "v1",
            "2024-01-01",
            [{"name": "pkg", "ecosystem": "deb"}],
        )
        db.insert_cve(
            "CVE-2024-0001", "CRITICAL", "v2",
            "2024-01-01",
            [{"name": "pkg", "ecosystem": "deb"}],
        )
        records = db.lookup("pkg", "deb")
        # Should have 2 affected_packages entries (not deduped by design)
        assert len(records) == 2
