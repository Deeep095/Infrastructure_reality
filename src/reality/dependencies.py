"""What this tool depends on, why, and whether it is installed.

``reality`` keeps a deliberately small runtime surface — one required package,
and two optional extras that are imported lazily so a core install never needs
them. That claim is easy to make in a README and hard to verify, so
``reality doctor`` prints the real picture from installed metadata: every
declared dependency, the version actually present, which extra it belongs to,
and one line on what would stop working without it.

The transitive count is computed from each installed package's own declared
requirements, skipping their optional extras (a requirement guarded by an
``extra ==`` marker is not installed unless that extra was asked for). It is
therefore a close approximation rather than a resolver's answer, which is why
it is reported as a count of packages reached rather than as a dependency tree.
"""

from __future__ import annotations

import re
from importlib import metadata

from pydantic import BaseModel, ConfigDict

#: Requirement strings look like ``boto3>=1.34`` or
#: ``typing-extensions>=4.12; python_version < "3.13"``. Only the leading name
#: matters here.
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

#: Marks a requirement that only applies when an optional extra was requested,
#: so it is not part of the default install.
_EXTRA_MARKER = re.compile(r"\bextra\s*==")

#: The group a dependency belongs to, in the order a reader should see them:
#: what is always needed, then what each opt-in feature adds, then tooling.
REQUIRED = "required"
AWS_EXTRA = "aws"
TABLE_EXTRA = "table"
DEV_EXTRA = "dev"

_GROUP_ORDER = (REQUIRED, AWS_EXTRA, TABLE_EXTRA, DEV_EXTRA)

#: Every package this project declares, and what is lost without it. Hard-coded
#: because the *reason* is prose that no metadata carries; the version and the
#: installed/missing state are always read from the environment.
_DECLARED: tuple[tuple[str, str, str], ...] = (
    ("pydantic", REQUIRED, "frozen domain models, validation, stable JSON"),
    ("boto3", AWS_EXTRA, "read-only AWS API calls; imported only under --aws"),
    ("rich", TABLE_EXTRA, "--output table and the progress bar; other formats are stdlib"),
    ("pytest", DEV_EXTRA, "the test suite"),
    ("ruff", DEV_EXTRA, "linter and formatter"),
    ("mypy", DEV_EXTRA, "strict type checking"),
)


class Dependency(BaseModel):
    """One declared dependency, as found in this environment."""

    model_config = ConfigDict(frozen=True)

    name: str
    group: str
    purpose: str
    version: str | None = None  # None when the package is not installed

    @property
    def installed(self) -> bool:
        return self.version is not None


def _installed_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def direct_dependencies() -> tuple[Dependency, ...]:
    """Every declared dependency, grouped, with the version present here."""
    return tuple(
        Dependency(
            name=name,
            group=group,
            purpose=purpose,
            version=_installed_version(name),
        )
        for group in _GROUP_ORDER
        for name, dep_group, purpose in _DECLARED
        if dep_group == group
    )


def _normalize(name: str) -> str:
    """PEP 503 name normalization.

    ``typing_extensions`` and ``typing-extensions`` are one package, and
    different distributions spell their requirement either way. Without this
    the transitive list reports it twice.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_names(package: str) -> set[str]:
    """The non-optional requirement names one installed package declares."""
    try:
        requires = metadata.requires(package) or []
    except metadata.PackageNotFoundError:
        return set()
    names: set[str] = set()
    for raw in requires:
        if _EXTRA_MARKER.search(raw):
            continue  # belongs to one of that package's own extras
        match = _REQUIREMENT_NAME.match(raw)
        if match is not None:
            names.add(_normalize(match.group(1)))
    return names


def transitive_dependencies(roots: tuple[Dependency, ...] | None = None) -> tuple[str, ...]:
    """Installed packages reached from the declared ones, excluding the roots.

    A breadth-first walk over each installed package's own requirements. Only
    packages that are actually present are reported: a requirement nothing
    installed is not something this environment is carrying.
    """
    direct = roots if roots is not None else direct_dependencies()
    root_names = {_normalize(dependency.name) for dependency in direct if dependency.installed}
    seen: set[str] = set(root_names)
    queue = list(root_names)
    reached: set[str] = set()
    while queue:
        for name in _requirement_names(queue.pop()):
            if name in seen or _installed_version(name) is None:
                continue
            seen.add(name)
            reached.add(name)
            queue.append(name)
    return tuple(sorted(reached))


def render_dependencies() -> str:
    """The dependency section of ``reality doctor``."""
    direct = direct_dependencies()
    transitive = transitive_dependencies(direct)
    name_width = max(len(dependency.name) for dependency in direct)
    version_width = max(len(dependency.version or "-") for dependency in direct)

    lines = ["reality: dependencies"]
    for dependency in direct:
        version = dependency.version or "-"
        marker = " " if dependency.installed else "!"
        lines.append(
            f"  {marker} {dependency.name:<{name_width}}  {version:<{version_width}}  "
            f"{dependency.group:<8}  {dependency.purpose}"
        )
    if transitive:
        lines.append(f"    + {len(transitive)} transitive package(s): {', '.join(transitive)}")
    missing = [dependency for dependency in direct if not dependency.installed]
    if missing:
        lines.append(
            "    '!' marks a package this environment does not have; the extras are "
            "optional by design and the features that need them say so when used."
        )
    return "\n".join(lines) + "\n"
