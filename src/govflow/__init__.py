"""govflow: Automated Integration & Documentation Engine."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("govflow")
except PackageNotFoundError:  # pragma: no cover - only when running from an unpacked source tree
    __version__ = "0.0.0"
