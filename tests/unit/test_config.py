"""Unit tests for the configuration object and its AWS opt-in rules."""

from __future__ import annotations

import pytest

from reality.config import ConfigError, RealityConfig


def test_defaults_are_local_and_offline() -> None:
    config = RealityConfig()
    assert config.aws_opt_in is False
    assert config.aws_profile is None
    assert config.aws_region is None
    assert config.aws_ready is False
    assert config.database_path.suffix == ".db"


def test_default_database_is_local_relative_path() -> None:
    # The default must stay a plain local file, never a network resource.
    config = RealityConfig()
    assert not config.database_path.is_absolute()


def test_require_aws_rejects_when_not_opted_in() -> None:
    with pytest.raises(ConfigError, match="--aws"):
        RealityConfig().require_aws()


def test_require_aws_rejects_missing_profile() -> None:
    config = RealityConfig(aws_opt_in=True, aws_region="eu-west-1")
    with pytest.raises(ConfigError, match="--profile"):
        config.require_aws()


def test_require_aws_rejects_missing_region() -> None:
    config = RealityConfig(aws_opt_in=True, aws_profile="sandbox")
    with pytest.raises(ConfigError, match="--region"):
        config.require_aws()


def test_require_aws_accepts_the_full_explicit_triple() -> None:
    config = RealityConfig(aws_opt_in=True, aws_profile="sandbox", aws_region="eu-west-1")
    config.require_aws()  # must not raise
    assert config.aws_ready is True


@pytest.mark.parametrize(
    "kwargs",
    [
        {"aws_profile": "sandbox"},
        {"aws_region": "eu-west-1"},
        {"aws_profile": "sandbox", "aws_region": "eu-west-1"},
    ],
)
def test_partial_aws_flags_rejected_without_opt_in(kwargs: dict[str, str]) -> None:
    config = RealityConfig(**kwargs)
    with pytest.raises(ConfigError, match="--aws"):
        config.validate_aws_flags(
            flag_profile=kwargs.get("aws_profile"),
            flag_region=kwargs.get("aws_region"),
        )


def test_a_saved_profile_is_not_treated_as_an_opt_in_request() -> None:
    """A configured profile/region must not make a local command fail.

    Keeping a region configured is the normal way to use the tool, and the
    safety guarantee is about reaching AWS - which still needs ``--aws`` - not
    about refusing to remember a region name.
    """
    config = RealityConfig(aws_profile="sandbox", aws_region="eu-west-1")
    config.validate_aws_flags(flag_profile=None, flag_region=None)  # must not raise
    # ...and the config still is not AWS-ready, so no adapter would be built.
    assert config.aws_ready is False


def test_validate_aws_flags_passes_when_fully_offline() -> None:
    RealityConfig().validate_aws_flags()  # must not raise


def test_empty_profile_or_region_does_not_count_as_explicit() -> None:
    config = RealityConfig(aws_opt_in=True, aws_profile="sandbox", aws_region="")
    with pytest.raises(ConfigError, match="--region"):
        config.require_aws()
