"""reality — read-only cloud infrastructure discovery and local simulation."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("reality")
except PackageNotFoundError:
    # Running from a source checkout that was never pip-installed. The version
    # is cosmetic everywhere it is used, so report it as unknown rather than
    # failing every command at import time.
    __version__ = "0.0.0+unknown"
