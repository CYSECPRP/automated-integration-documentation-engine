"""The govflow.yaml configuration file."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from govflow.models import Severity
from govflow.util import canonical_json, format_validation_error, sha256_hex

_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}")


class ConfigError(ValueError):
    """The configuration file is missing or invalid."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GitHubTargets(_Strict):
    repositories: list[str] = Field(default_factory=list)
    api_url: str = Field(default="https://api.github.com", pattern=r"^https://")

    @field_validator("repositories")
    @classmethod
    def _valid_names(cls, value: list[str]) -> list[str]:
        for name in value:
            if not _REPOSITORY.fullmatch(name):
                raise ValueError(f"{name!r} is not an owner/repository name")
        return list(dict.fromkeys(value))


class Targets(_Strict):
    github: GitHubTargets = Field(default_factory=GitHubTargets)
    snapshots: list[Path] = Field(default_factory=list)


class PolicySettings(_Strict):
    include_builtin: bool = True
    paths: list[Path] = Field(default_factory=list)


class Governance(_Strict):
    separation_of_duties: bool = False
    allowed_actions: list[str] = Field(default_factory=list)
    allowed_targets: list[str] = Field(default_factory=list)
    fail_on: Severity | None = None


class Link(_Strict):
    label: str = Field(min_length=1, max_length=40)
    href: str

    @field_validator("href")
    @classmethod
    def _safe_href(cls, value: str) -> str:
        if value.startswith("https://"):
            return value
        if ":" in value or value.startswith(("/", "\\")):
            raise ValueError("links must be https:// URLs or relative paths")
        return value

    @property
    def external(self) -> bool:
        return self.href.startswith("https://")


class DocsSettings(_Strict):
    title: str = Field(default="Governance report", max_length=80)
    links: list[Link] = Field(default_factory=list)


class Config(_Strict):
    version: Literal[1] = 1
    name: str = Field(default="govflow run", max_length=80)
    targets: Targets = Field(default_factory=Targets)
    policies: PolicySettings = Field(default_factory=PolicySettings)
    governance: Governance = Field(default_factory=Governance)
    docs: DocsSettings = Field(default_factory=DocsSettings)

    @property
    def digest(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json")))

    def resolve_paths(self, base: Path) -> Config:
        def resolve(path: Path) -> Path:
            return path if path.is_absolute() else base / path

        targets = self.targets.model_copy(
            update={"snapshots": [resolve(path) for path in self.targets.snapshots]}
        )
        policies = self.policies.model_copy(
            update={"paths": [resolve(path) for path in self.policies.paths]}
        )
        return self.model_copy(update={"targets": targets, "policies": policies})


def parse_config_text(text: str, source: str) -> Config:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{source}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a mapping at the top level")
    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"{source}: {format_validation_error(exc)}") from exc


def load_config(path: Path) -> Config:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from exc
    return parse_config_text(text, str(path)).resolve_paths(path.parent)
