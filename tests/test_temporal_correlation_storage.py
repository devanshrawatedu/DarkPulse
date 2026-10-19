"""Unit tests for temporal spike detection, correlation and storage."""

from datetime import datetime, timedelta, timezone

from darkpulse.analysis.temporal import TemporalAnalyzer
from darkpulse.correlation import cluster_events
from darkpulse.models import NormalizedRecord, RawRecord, SourceKind, stable_id
from darkpulse.storage.base import InMemoryStore


def _rec(rid, title, text, days_ago=0, source=SourceKind.RSS):
    return NormalizedRecord(
        id=rid,
        source=source,
        source_record_id=rid,
        record_type="article",
        title=title,
        text=text,
        published_at=datetime.now(timezone.utc) - timedelta(days=days_ago),
    )


class TestTemporalSpikes:
    def test_spike_detected_on_burst(self):
        # CVE-QUIET: steady 1/day for 10 days. CVE-BURST: 0 for 9 days then 5.
        records, keys = [], {}
        for d in range(10):
            records.append(_rec(f"q-{d}", f"quiet {d}", "CVE-2024-1111 noise", days_ago=10 - d))
            keys[f"q-{d}"] = ["CVE-2024-1111"]
        for d in range(5):
            records.append(_rec(f"b-{d}", f"burst {d}", "CVE-2024-2222 spike", days_ago=0))
            keys[f"b-{d}"] = ["CVE-2024-2222"]

        spikes = TemporalAnalyzer(z_threshold=1.5, min_baseline=3).detect_spikes(records, keys)
        spike_entities = {s.entity for s in spikes}
        assert "CVE-2024-2222" in spike_entities

    def test_steady_series_has_no_spike(self):
        records, keys = [], {}
        for d in range(8):
            records.append(_rec(f"s-{d}", f"steady {d}", "CVE-2024-3333 steady", days_ago=8 - d))
            keys[f"s-{d}"] = ["CVE-2024-3333"]
        spikes = TemporalAnalyzer(z_threshold=2.0, min_baseline=3).detect_spikes(records, keys)
        assert all(s.entity != "CVE-2024-3333" for s in spikes)

    def test_spike_fields(self):
        records, keys = [], {}
        for d in range(10):
            records.append(_rec(f"q-{d}", f"quiet {d}", "x", days_ago=10 - d))
            keys[f"q-{d}"] = []
        # burst: 3 records today after 10 quiet days -> sharp single-day spike
        for d in (0, 1, 2):
            records.append(_rec(f"b-{d}", f"burst {d}", "CVE-2024-4444", days_ago=0))
            keys[f"b-{d}"] = ["CVE-2024-4444"]
        spikes = TemporalAnalyzer(z_threshold=1.5, min_baseline=3).detect_spikes(records, keys)
        assert spikes
        s = spikes[0]
        assert s.observed >= 1 and s.baseline_mean >= 0 and s.z_score >= 1.5
        assert s.window and len(s.window) == 10


class TestCorrelation:
    def test_shared_cve_merges_cross_source(self):
        a = _rec("a", "NVD entry", "Bug in product", source=SourceKind.NVD)
        b = _rec("b", "KEV entry", "Bug in product", source=SourceKind.CISA_KEV)
        # give both a shared CVE
        a.text = "CVE-2024-9999 exploited widely"
        b.text = "CISA adds CVE-2024-9999 to KEV"
        events = cluster_events([a, b], similarity_threshold=0.9)
        assert len(events) == 1
        assert set(events[0].sources) == {"nvd", "cisa_kev"}
        assert "CVE-2024-9999" in events[0].cves

    def test_dissimilar_records_stay_separate(self):
        a = _rec("a", "Ransomware hits hospitals", "Ryuk ransomware incident at hospital")
        b = _rec("b", "New phishing kit", "phishing kit sold on forum with MFA bypass")
        events = cluster_events([a, b], similarity_threshold=0.9)
        assert len(events) == 2

    def test_event_time_bounds(self):
        a = _rec("a", "t", "CVE-2024-8888 story", days_ago=5)
        b = _rec("b", "t again", "More on CVE-2024-8888", days_ago=1)
        events = cluster_events([a, b])
        assert len(events) == 1
        assert events[0].first_seen <= events[0].last_seen


class TestStorage:
    def test_dual_storage_separation(self):
        store = InMemoryStore()
        raw = RawRecord(
            id="r1", source=SourceKind.RSS, source_record_id="x", payload={"a": 1}
        )
        norm = _rec("n1", "title", "text")
        store.save_raw(raw)
        store.save_normalized(norm)
        assert store.count_raw() == 1
        assert store.count_normalized() == 1
        assert store.list_raw()[0].id == "r1"
        assert store.list_normalized()[0].id == "n1"

    def test_upsert_idempotent(self):
        store = InMemoryStore()
        raw = RawRecord(id="r1", source=SourceKind.RSS, source_record_id="x", payload={})
        store.save_raw(raw)
        store.save_raw(raw)
        assert store.count_raw() == 1

    def test_source_filter(self):
        store = InMemoryStore()
        store.save_raw(RawRecord(id="a", source=SourceKind.NVD, source_record_id="1", payload={}))
        store.save_raw(RawRecord(id="b", source=SourceKind.RSS, source_record_id="2", payload={}))
        assert len(store.list_raw(source="nvd")) == 1
        assert len(store.list_raw(source="rss")) == 1

    def test_snapshot_roundtrip(self, tmp_path):
        store = InMemoryStore()
        store.save_raw(RawRecord(id="a", source=SourceKind.NVD, source_record_id="1", payload={"k": "v"}))
        store.save_normalized(_rec("n1", "hello", "world"))
        path = str(tmp_path / "snap.json")
        store.save_snapshot(path)
        restored = InMemoryStore.load_snapshot(path)
        assert restored.count_raw() == 1
        assert restored.count_normalized() == 1
        assert restored.list_normalized()[0].title == "hello"
