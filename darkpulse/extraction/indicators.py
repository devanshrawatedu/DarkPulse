"""Extraction layer: strict indicator regexes plus contextual entity extraction."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from ..graph.kb import canonical_entity
from ..models import (
    EntityType,
    ExtractedEntity,
    ExtractionResult,
    Indicator,
    IndicatorKind,
    NormalizedRecord,
)
from ..utils import utcnow

logger = logging.getLogger(__name__)

# CVE-YEAR-SEQUENCE per the MITRE spec: a 4-digit year and a sequence number of
# at least 4 digits. Years before 1999 or an all-zero sequence are not real ids.
CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b", re.IGNORECASE)
MIN_CVE_YEAR = 1999

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|online|site|link|su|cc|me|co|gov|edu)\b",
    re.IGNORECASE,
)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

_KNOWN_MALWARE = {
    "mirai", "wannacry", "notpetya", "petya", "ryuk", "revil", "sodinokibi",
    "emotet", "trickbot", "dridex", "cobalt strike", "cobaltstrike", "beacon",
    "lockbit", "blackcat", "alphv", "cl0p", "clop", "qakbot", "qbot",
    "icedid", "zettilim", "akira", "play", "maze", "megazord", "kryptina",
}
_KNOWN_ACTORS = {
    "apt28", "apt29", "fancy bear", "cozy bear", "lazarus group", "lazarus",
    "sandworm", "bitwise spider", "scattered spider",
    "ta505", "fin7", "fin11", "mustang panda", "volt typhoon",
    "salt typhoon", "winter vivern", "charm power", "darkside",
}
_TECH_KEYWORDS = {
    "windows", "linux", "apache", "nginx", "iis", "exchange", "sharepoint",
    "jenkins", "confluence", "gitlab", "fortinet", "fortigate", "fortios",
    "citrix", "netscaler", "vmware", "esxi", "vcenter", "vsphere",
    "cisco ios", "cisco asa", "cisco", "palo alto", "pan-os", "globalprotect",
    "ivanti", "pulse secure", "connect secure", "zoho", "manageengine",
    "atlassian", "bitbucket", "wordpress", "drupal", "joomla", "microsoft office",
    "outlook", "chrome", "firefox", "safari", "openssl", "log4j", "spring",
    "spring4shell", "goanywhere", "moveit", "ws_ftp", "papercut",
}
_ORG_KEYWORDS = {
    "cisa", "fbi", "nsa", "mandiant", "crowdstrike", "microsoft", "google",
    "cisco", "palo alto networks", "fortinet", "ivanti", "vmware",
    "sophos", "kaspersky", "check point", "bitdefender", "eset",
}


@dataclass(frozen=True)
class _GlossaryTerm:
    """One precompiled glossary entry with its canonical entity identity."""

    pattern: re.Pattern[str]
    name: str
    type: EntityType
    confidence: float


def _glossary_term(term: str, etype: EntityType, confidence: float) -> _GlossaryTerm:
    canonical = canonical_entity(term, etype)
    name = canonical[1] if canonical else term
    # Word-boundary match so "play" does not fire on "display" and "petya"
    # does not fire inside "notpetya".
    pattern = re.compile(
        rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", re.IGNORECASE
    )
    return _GlossaryTerm(pattern=pattern, name=name, type=etype, confidence=confidence)


_GLOSSARY: tuple[_GlossaryTerm, ...] = (
    *(_glossary_term(t, EntityType.MALWARE, 0.9) for t in sorted(_KNOWN_MALWARE)),
    *(_glossary_term(t, EntityType.THREAT_ACTOR, 0.9) for t in sorted(_KNOWN_ACTORS)),
    *(_glossary_term(t, EntityType.TECHNOLOGY, 0.7) for t in sorted(_TECH_KEYWORDS)),
    *(_glossary_term(t, EntityType.ORGANIZATION, 0.7) for t in sorted(_ORG_KEYWORDS)),
)


def _defang(text: str) -> str:
    """Normalize defanged IOC notation (hXXp, [.], (.), {.}, [at]) to plain text."""
    text = re.sub(r"h(?:xx|tt)p(s?)://", r"http\1://", text, flags=re.IGNORECASE)
    return (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[ at ]", "@")
        .replace("[at]", "@")
        .replace("(at)", "@")
    )


def _is_valid_cve(match: re.Match[str]) -> bool:
    year, sequence = int(match.group(1)), int(match.group(2))
    return MIN_CVE_YEAR <= year <= utcnow().year + 1 and sequence > 0


def looks_like_indicator(text: str) -> bool:
    """True when ``text`` is an IOC rather than a named entity.

    NER models regularly label CVE ids or IP addresses as organizations; those
    must not become graph entities of their own.
    """
    value = text.strip()
    if not value:
        return True
    return any(
        pattern.fullmatch(value)
        for pattern in (CVE_RE, IPV4_RE, MD5_RE, SHA1_RE, SHA256_RE, DOMAIN_RE)
    )


def extract_indicators(text: str) -> list[Indicator]:
    """Extract CVEs, IPv4 addresses, domains and file hashes.

    Defanged notation (``mal[.]ware[.]xyz``, ``203[.]0[.]113[.]9``) is
    normalized first, so spans refer to the normalized text.
    """
    if not text:
        return []

    text = _defang(text)
    found: list[Indicator] = []
    seen: set[tuple[str, str]] = set()

    def add(
        kind: IndicatorKind, value: str, span: tuple[int, int] | None = None
    ) -> None:
        key = (kind, value)
        if key not in seen:
            seen.add(key)
            found.append(Indicator(kind=kind, value=value, span=span))

    for match in CVE_RE.finditer(text):
        if _is_valid_cve(match):
            add("cve", match.group(0).upper(), (match.start(), match.end()))
    for match in SHA256_RE.finditer(text):
        add("sha256", match.group(0).lower())
    for match in SHA1_RE.finditer(text):
        add("sha1", match.group(0).lower())
    for match in MD5_RE.finditer(text):
        add("md5", match.group(0).lower())
    for match in IPV4_RE.finditer(text):
        add("ip", match.group(0))
    for match in DOMAIN_RE.finditer(text):
        value = match.group(0)
        if not IPV4_RE.fullmatch(value):
            add("domain", value.lower())
    return found


def _snippet(text: str, needle: str, width: int = 90) -> str | None:
    index = text.lower().find(needle.lower())
    if index < 0:
        return None
    start = max(0, index - width // 2)
    end = min(len(text), index + len(needle) + width // 2)
    prefix = "..." if start else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{text[start:end].strip()}{suffix}"


def _dedupe_entities(entities: list[ExtractedEntity]) -> list[ExtractedEntity]:
    best: dict[tuple[str, str], ExtractedEntity] = {}
    for entity in entities:
        key = (entity.type.value, entity.name.lower())
        if key not in best or entity.confidence > best[key].confidence:
            best[key] = entity
    return sorted(best.values(), key=lambda entity: (-entity.confidence, entity.name))


def extract_entities_heuristic(text: str) -> list[ExtractedEntity]:
    """Glossary-based entity extraction (zero-dependency fallback for NER)."""
    if not text:
        return []

    entities: list[ExtractedEntity] = []
    for term in _GLOSSARY:
        match = term.pattern.search(text)
        if match is None:
            continue
        entities.append(
            ExtractedEntity(
                name=term.name,
                type=term.type,
                confidence=term.confidence,
                extractor="glossary",
                evidence=_snippet(text, match.group(0)),
            )
        )
    return _dedupe_entities(entities)


class NlpEntityExtractor:
    """spaCy-backed extractor that degrades to no-ops when the model is absent."""

    def __init__(self, model: str = "en_core_web_sm") -> None:
        self.model_name = model
        self._nlp = None
        self._unavailable = False

    def _load(self):
        if self._nlp is not None or self._unavailable:
            return self._nlp
        try:
            import spacy
        except ImportError:
            logger.info("spaCy is not installed; using glossary extraction only")
            self._unavailable = True
            return None
        try:
            self._nlp = spacy.load(self.model_name, disable=["lemmatizer"])
        except (OSError, ValueError) as exc:
            logger.warning(
                "spaCy model %r unavailable (%s); using glossary extraction only",
                self.model_name,
                exc,
            )
            self._unavailable = True
        return self._nlp

    def extract(self, text: str) -> list[ExtractedEntity]:
        nlp = self._load()
        if nlp is None or not text:
            return []
        label_map = {"ORG": EntityType.ORGANIZATION, "PRODUCT": EntityType.TECHNOLOGY}
        entities: list[ExtractedEntity] = []
        doc = nlp(text[:20000])
        for ent in doc.ents:
            etype = label_map.get(ent.label_)
            name = ent.text.strip()
            if etype is None or len(name) < 3:
                continue
            entities.append(
                ExtractedEntity(
                    name=name,
                    type=etype,
                    confidence=0.55,
                    extractor="spacy",
                    evidence=doc[max(0, ent.start - 8) : ent.end + 8].text,
                )
            )
        return _dedupe_entities(entities)


class Extractor:
    """Combines indicator regexes, glossary heuristics and optional NLP."""

    def __init__(self, spacy_model: str = "en_core_web_sm", use_nlp: bool = True) -> None:
        self.nlp = NlpEntityExtractor(spacy_model) if use_nlp else None

    def extract(self, record: NormalizedRecord) -> ExtractionResult:
        text = "\n".join(part for part in (record.title, record.text) if part)
        entities = extract_entities_heuristic(text)
        if self.nlp is not None:
            entities = _dedupe_entities(
                entities + self.nlp.extract(record.text or record.title)
            )
        entities = [
            entity for entity in entities if not looks_like_indicator(entity.name)
        ]
        return ExtractionResult(
            record_id=record.id,
            indicators=extract_indicators(text),
            entities=entities,
        )
