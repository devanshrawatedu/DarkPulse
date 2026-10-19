"""Unit tests for indicator regex extraction and heuristic entity extraction."""

from darkpulse.extraction.indicators import (
    Extractor,
    extract_entities_heuristic,
    extract_indicators,
)
from darkpulse.models import EntityType, NormalizedRecord, SourceKind, stable_id


def _record(text: str) -> NormalizedRecord:
    return NormalizedRecord(
        id=stable_id("test", "1"),
        source=SourceKind.RSS,
        source_record_id="test-1",
        record_type="article",
        title="Test",
        text=text,
    )


class TestIndicatorRegex:
    def test_cve_extraction(self):
        text = "Exploits for cve-2024-3400 and CVE-2023-4966 were observed."
        inds = extract_indicators(text)
        cves = {i.value for i in inds if i.kind == "cve"}
        assert cves == {"CVE-2024-3400", "CVE-2023-4966"}

    def test_cve_requires_four_digit_sequence(self):
        inds = extract_indicators("CVE-2024-340 is not a valid CVE id")
        assert all(i.kind != "cve" for i in inds)

    def test_ipv4_extraction(self):
        text = "C2 at 192.168.1.1 and 8.8.8.8 but not 999.1.1.1"
        ips = {i.value for i in extract_indicators(text) if i.kind == "ip"}
        assert ips == {"192.168.1.1", "8.8.8.8"}

    def test_domain_extraction(self):
        text = "Phishing at cdn[.]example-bad[.]com and evil.xyz"
        domains = {i.value for i in extract_indicators(text) if i.kind == "domain"}
        assert "evil.xyz" in domains

    def test_hash_extraction_by_length(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha1 = "a9993e364706816aba3e25717850c26c9cd0d89d"
        sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        text = f"md5 {md5}, sha1 {sha1}, sha256 {sha256}"
        inds = extract_indicators(text)
        by_kind = {i.kind: i.value for i in inds}
        assert by_kind["md5"] == md5
        assert by_kind["sha1"] == sha1
        assert by_kind["sha256"] == sha256

    def test_no_hash_false_positive_from_long_words(self):
        # 40-char word with non-hex characters must not match SHA1
        inds = extract_indicators("the word " + "g" * 20 + "h" * 20 + " is not a hash")
        assert all(i.kind != "sha1" for i in inds)

    def test_defanged_bracket_notation(self):
        text = "C2 domain: mal[.]ware[.]xyz and IP 203[.]0[.]113[.]9"
        inds = extract_indicators(text)
        assert any(i.kind == "domain" for i in inds)


class TestHeuristicEntities:
    def test_malware_and_actor(self):
        ents = extract_entities_heuristic("LockBit affiliates abused CVE-2023-4966; APT28 spied.")
        names = {e.name for e in ents}
        assert "LockBit" in names
        assert "APT28" in names

    def test_alias_canonicalization_to_title_case(self):
        ents = extract_entities_heuristic("cobalt strike beacons spotted")
        assert any(e.name == "Cobalt Strike" and e.type == EntityType.MALWARE for e in ents)

    def test_dedupe(self):
        ents = extract_entities_heuristic("Emotet and emotet and EMOTET everywhere")
        assert len([e for e in ents if e.type == EntityType.MALWARE]) == 1

    def test_technology_and_org(self):
        ents = extract_entities_heuristic("FortiOS on FortiGate appliances used by CISA")
        types = {(e.type) for e in ents}
        assert EntityType.TECHNOLOGY in types
        assert EntityType.ORGANIZATION in types


class TestExtractorFacade:
    def test_extract_bundle(self):
        extractor = Extractor(use_nlp=False)
        rec = _record("CVE-2024-3400 hits PAN-OS; Scattered Spider claims; 8.8.8.8")
        bundle = extractor.extract(rec)
        kinds = {i.kind for i in bundle.indicators}
        assert "cve" in kinds and "ip" in kinds
        assert any(e.name == "PAN-OS" for e in bundle.entities)
