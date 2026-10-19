"""DarkPulse settings, loaded from ``DARKPULSE_*`` environment variables."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
DEFAULT_FIXTURE_DIR = PACKAGE_ROOT / "fixtures"
DEFAULT_SNAPSHOT_DIR = PROJECT_ROOT / "data" / "snapshots"

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    return default if raw is None else raw.strip().lower() in _TRUTHY


def _env_list(name: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


class SourceConfig(BaseModel):
    """Endpoint, pacing and retry policy for one public data source."""

    name: str
    url: str
    enabled: bool = True
    timeout: float = Field(20.0, gt=0)
    max_retries: int = Field(4, ge=1, le=10)
    backoff_base: float = Field(1.6, gt=0)
    requests_per_minute: float = Field(6.0, ge=0.01)


class MongoConfig(BaseModel):
    enabled: bool = False
    uri: str = "mongodb://localhost:27017"
    database: str = "darkpulse"


class Neo4jConfig(BaseModel):
    enabled: bool = False
    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: str = ""


class RiskWeights(BaseModel):
    """Weights for the multi-factor risk score; they need not sum to 1."""

    activity_growth: float = Field(0.30, ge=0.0)
    relationship_density: float = Field(0.20, ge=0.0)
    severity: float = Field(0.25, ge=0.0)
    recency: float = Field(0.15, ge=0.0)
    asset_relevance: float = Field(0.10, ge=0.0)


class Settings(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    # Ingestion
    sources: list[SourceConfig] = Field(default_factory=lambda: default_sources())
    nvd_api_key: str = ""

    # Storage / fixtures (all paths are absolute, resolved from the package)
    mongo: MongoConfig = Field(default_factory=MongoConfig)
    neo4j: Neo4jConfig = Field(default_factory=Neo4jConfig)
    snapshot_dir: Path = DEFAULT_SNAPSHOT_DIR
    fixture_dir: Path = DEFAULT_FIXTURE_DIR

    # Extraction
    spacy_model: str = "en_core_web_sm"

    # Correlation / temporal analysis
    correlation_similarity_threshold: float = Field(0.60, ge=0.0, le=1.0)
    spike_z_threshold: float = Field(2.0, gt=0)
    min_baseline_observations: int = Field(3, ge=1)

    # Risk engine
    risk_weights: RiskWeights = Field(default_factory=RiskWeights)
    monitored_assets: list[str] = Field(default_factory=list)

    # Runtime
    log_level: str = "INFO"
    offline: bool = False

    def ensure_dirs(self) -> None:
        """Create the writable artifact directory (fixtures are read-only)."""
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    def source(self, name: str) -> SourceConfig | None:
        return next((src for src in self.sources if src.name == name), None)


def default_sources() -> list[SourceConfig]:
    return [
        SourceConfig(
            name="nvd",
            url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            requests_per_minute=6.0,
        ),
        SourceConfig(
            name="cisa_kev",
            url=(
                "https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json"
            ),
            requests_per_minute=30.0,
        ),
        SourceConfig(name="feeds", url="", requests_per_minute=30.0),
    ]


def get_settings() -> Settings:
    """Build settings from the environment (``DARKPULSE_*`` / ``NVD_API_KEY``)."""
    return Settings(
        offline=_env_flag("DARKPULSE_OFFLINE"),
        nvd_api_key=os.getenv("NVD_API_KEY", ""),
        monitored_assets=_env_list("DARKPULSE_MONITORED_ASSETS"),
        mongo=MongoConfig(enabled=_env_flag("DARKPULSE_MONGO")),
        neo4j=Neo4jConfig(
            enabled=_env_flag("DARKPULSE_NEO4J"),
            uri=os.getenv("DARKPULSE_NEO4J_URI", "bolt://localhost:7687"),
            user=os.getenv("DARKPULSE_NEO4J_USER", "neo4j"),
            password=os.getenv("DARKPULSE_NEO4J_PASSWORD", ""),
        ),
        log_level=os.getenv("DARKPULSE_LOG_LEVEL", "INFO"),
        snapshot_dir=Path(
            os.getenv("DARKPULSE_SNAPSHOT_DIR", str(DEFAULT_SNAPSHOT_DIR))
        ),
        fixture_dir=Path(
            os.getenv("DARKPULSE_FIXTURE_DIR", str(DEFAULT_FIXTURE_DIR))
        ),
    )
