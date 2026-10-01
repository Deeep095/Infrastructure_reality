"""Runtime configuration for reality.

A single configuration object is the only route runtime settings take into
the rest of the code base. It defaults to purely local behaviour (a SQLite
file next to the working directory) and treats AWS as strictly opt-in: no
adapter may run against AWS unless the user explicitly selected ``--aws``,
``--profile``, and ``--region`` on the command line. There is no default
region and no default profile anywhere in this code base.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field, field_validator


class ConfigError(Exception):
    """Raised when configuration violates the safety contract."""


class RealityConfig(BaseModel):
    """Runtime settings; every default is local and offline."""

    database_path: Path = Field(
        default=Path("reality.db"),
        description="Local SQLite database file. Never a network resource.",
    )
    aws_opt_in: bool = Field(
        default=False,
        description="Set only by the explicit --aws command-line flag.",
    )
    aws_profile: str | None = Field(
        default=None,
        description="Named AWS profile; must be explicit, never defaulted.",
    )
    aws_region: str | None = Field(
        default=None,
        description="AWS region; must be explicit, never defaulted.",
    )

    @field_validator("aws_profile", "aws_region")
    @classmethod
    def _empty_is_absent(cls, value: str | None) -> str | None:
        """An empty flag value is no selection at all, never an explicit one."""
        if value is None or not value.strip():
            return None
        return value

    @property
    def aws_ready(self) -> bool:
        """True only when the complete explicit opt-in triple is present."""
        return self.aws_opt_in and self.aws_profile is not None and self.aws_region is not None

    def validate_aws_flags(
        self, *, flag_profile: str | None = None, flag_region: str | None = None
    ) -> None:
        """Reject a partial AWS selection typed on the command line.

        ``--profile`` or ``--region`` without ``--aws`` implies implicit AWS
        usage, which the safety contract forbids, so reject it loudly.

        Only the *flags* are policed. A profile or region that came from the
        settings file or the environment is a saved preference, not a request
        to read AWS - erroring on those would make it impossible to keep a
        region configured while running purely local commands, which is the
        single most common way to use this tool. What matters is that nothing
        reaches AWS without ``--aws``, and that is enforced by ``--aws`` never
        being persisted.
        """
        if not self.aws_opt_in and (flag_profile is not None or flag_region is not None):
            raise ConfigError(
                "--profile and --region only make sense together with --aws; "
                "rerun with --aws --profile PROFILE --region REGION"
            )
        # A complete triple must also be complete, however it was assembled. A
        # command that reads no AWS still refuses `--aws` alone, so the opt-in
        # means the same thing everywhere instead of being quietly ignored by
        # some subcommands and enforced by others.
        if self.aws_opt_in:
            missing = [
                flag
                for flag, value in (
                    ("--profile", self.aws_profile),
                    ("--region", self.aws_region),
                )
                if value is None
            ]
            if missing:
                raise ConfigError(
                    f"--aws requires an explicit {' and '.join(missing)}; "
                    "no default profile or region is ever assumed"
                )

    def require_aws(self) -> None:
        """Validate the complete explicit opt-in triple before an AWS adapter runs.

        Call this at the entry point of any command that reads from AWS.
        Missing input must stop the command before a client is constructed.
        """
        if not self.aws_opt_in:
            raise ConfigError(
                "this command reads from AWS, which is opt-in; "
                "rerun with --aws --profile PROFILE --region REGION"
            )
        missing = [
            flag
            for flag, value in (("--profile", self.aws_profile), ("--region", self.aws_region))
            if value is None
        ]
        if missing:
            raise ConfigError(
                f"--aws requires an explicit {' and '.join(missing)}; "
                "no default profile or region is ever assumed"
            )
