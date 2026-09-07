from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_UNSAFE_DEFAULT_KEY = "change_me_in_production_please"

# Valid AI provider identifiers (OpenAI-compatible means Ollama, LM Studio, etc.)
_VALID_AI_PROVIDERS = {"mock", "openai", "anthropic", "ollama", "openai_compatible"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_name: str = "BugForge"
    version: str = "1.1.0"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    # Database
    database_url: str = "postgresql+asyncpg://bugforge:bugforge_dev@localhost:5432/bugforge"

    # Security — must be overridden in production
    secret_key: str = _UNSAFE_DEFAULT_KEY

    # CORS
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:3001"]

    # Analysis limits
    max_file_size_bytes: int = 5 * 1024 * 1024  # 5 MB
    max_repo_files: int = 10_000
    analysis_timeout_seconds: int = 300

    # AI provider: mock | openai | anthropic | ollama | openai_compatible
    ai_provider: str = "mock"
    ai_model: str = "gpt-4o-mini"
    # API key comes from environment only — never commit a real key
    ai_api_key: str = ""
    # Base URL override: for Ollama use http://localhost:11434/v1
    ai_base_url: str = ""
    ai_max_context_chars: int = 32_000
    ai_max_output_tokens: int = 2_000
    ai_temperature: float = 0.1
    ai_timeout_seconds: int = 60
    ai_max_retries: int = 2
    ai_max_hypotheses: int = 3

    # GitHub Integration — credentials come from environment only, never committed
    github_token: str = ""
    github_app_id: str = ""
    github_app_private_key: str = ""

    # -------------------------------------------------------------------
    # Autonomous Repository Discovery (v1.1.0)
    # -------------------------------------------------------------------
    # master switch: disabled | manual | scheduled
    discovery_mode: str = "disabled"
    # hours between scheduled discovery sweeps (0 = run once then stop)
    discovery_interval_hours: int = 24
    # minimum GitHub stars for a candidate to be considered
    discovery_min_stars: int = 1_000
    # maximum stars (0 = no upper bound)
    discovery_max_stars: int = 0
    # maximum repository disk size in KB (0 = no limit)
    discovery_max_size_kb: int = 50_000
    # maximum number of open files in the repository (0 = no limit)
    discovery_max_files: int = 5_000
    # comma-separated list of allowed primary languages (empty = all)
    discovery_languages: str = "Python,JavaScript,TypeScript,Go,Rust,Java"
    # require an OSI-recognised open-source license
    discovery_require_license: bool = True
    # skip forked repositories
    discovery_skip_forks: bool = True
    # skip archived repositories
    discovery_skip_archived: bool = True
    # require a commit within this many days (0 = no recency filter)
    discovery_max_staleness_days: int = 365
    # daily cap on new repository candidates (0 = unlimited)
    discovery_daily_repo_limit: int = 100
    # maximum simultaneous autonomous analyses
    discovery_max_concurrent: int = 2
    # daily cap on AI calls from the autonomous scanner (0 = unlimited)
    discovery_daily_ai_limit: int = 200
    # comma-separated topics to exclude
    discovery_excluded_topics: str = "exploit,hack,malware,pentest,ctf"
    # comma-separated owner logins to exclude
    discovery_excluded_owners: str = ""
    # permanent workspace root for cloned repositories (empty = auto-select)
    autonomous_workspace_dir: str = ""

    # -------------------------------------------------------------------
    # Eligibility / Safety Policy (v1.1.0)
    # -------------------------------------------------------------------
    # hard block repositories larger than this many KB
    safety_max_repo_size_kb: int = 100_000
    # hard block repositories with more than this many files
    safety_max_file_count: int = 20_000
    # hard block repositories with more than this many shell/CI scripts
    safety_max_script_count: int = 50
    # allow Docker execution of repository tests
    safety_allow_docker_exec: bool = True
    # allow network access inside sandbox containers
    safety_allow_sandbox_network: bool = False
    # allow dependency installation inside the sandbox
    safety_allow_dep_install: bool = False

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        v = v.upper()
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str, info: object) -> str:
        env = getattr(getattr(info, "data", {}), "get", lambda k, d=None: d)(
            "environment", "development"
        )
        if v == _UNSAFE_DEFAULT_KEY and env == "production":
            raise ValueError(
                "SECRET_KEY must be set to a secure random value in production. "
                'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
            )
        return v

    @field_validator("discovery_mode")
    @classmethod
    def validate_discovery_mode(cls, v: str) -> str:
        valid = {"disabled", "manual", "scheduled"}
        if v not in valid:
            raise ValueError(f"discovery_mode must be one of {valid}")
        return v

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, v: str) -> str:
        if v not in _VALID_AI_PROVIDERS:
            raise ValueError(f"ai_provider must be one of {_VALID_AI_PROVIDERS}")
        return v

    def get_discovery_languages(self) -> list[str]:
        """Return the allowed language list (empty = all languages permitted)."""
        if not self.discovery_languages.strip():
            return []
        return [lang.strip() for lang in self.discovery_languages.split(",") if lang.strip()]

    def get_excluded_topics(self) -> set[str]:
        if not self.discovery_excluded_topics.strip():
            return set()
        return {t.strip().lower() for t in self.discovery_excluded_topics.split(",") if t.strip()}

    def get_excluded_owners(self) -> set[str]:
        if not self.discovery_excluded_owners.strip():
            return set()
        return {o.strip().lower() for o in self.discovery_excluded_owners.split(",") if o.strip()}

    def is_local_ai(self) -> bool:
        """Return True when the AI provider runs locally (no cloud cost)."""
        return self.ai_provider in {"mock", "ollama", "openai_compatible"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
