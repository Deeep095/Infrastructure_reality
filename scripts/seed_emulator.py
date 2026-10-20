"""Seed a local AWS emulator, and write the Terraform state that declares part of it.

The offline demo replays recorded responses; this script is the next step up:
real boto3 calls, over HTTP, to an AWS-compatible emulator (``moto_server`` or
LocalStack) running on this machine. ``reality scan --endpoint-url`` then reads
that world through exactly the code path a real account would use.

This is the only script in the repository that *creates* cloud resources, so
it refuses any endpoint that is not on loopback, and it signs every request
with fixed dummy credentials rather than a profile: even a misrouted request
could not authenticate against a real account.

What it builds, and the conclusion each part should reconcile to:

* ``web-server`` attaches to ``web-sg`` (declared) and to ``legacy-ops-sg``
  (not declared) - one ``confirmed`` and one ``undocumented`` attachment.
* RDS ``primary`` attaches to ``web-sg``, declared - ``confirmed``.
* Lambda ``processor`` uses ``processor_role``, declared - ``confirmed``.
* Lambda ``cleanup`` uses ``cleanup_role``; neither is declared - ``undocumented``.
* ``aws_instance.web`` also declares ``depends_on`` its security group, which
  no API reports - ``declared_only``.
* Both roles carry an S3 policy - ``possible`` permissions. moto does not
  implement CloudTrail ``LookupEvents``, but that changes nothing here:
  management events never show data-plane usage, so a grant is ``possible``
  with or without CloudTrail.

Usage::

    moto_server -p 5000
    python scripts/seed_emulator.py --endpoint-url http://127.0.0.1:5000

It writes ``<out-dir>/state.json`` plus a throwaway AWS config/credentials pair
holding an ``emulator`` profile, and prints the commands to run next. Your own
``~/.aws`` files are never read or written.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROFILE = "emulator"
DUMMY_KEY = "test"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
BUCKET = "data-lake-emulator"

LAMBDA_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


@dataclass(frozen=True)
class SeededWorld:
    """Where the generated files landed, and the IDs the emulator assigned."""

    state_path: Path
    config_file: Path
    credentials_file: Path
    region: str
    account: str
    ids: dict[str, str]


def require_loopback(endpoint_url: str) -> None:
    """Refuse any endpoint that could be a real AWS region."""
    host = urlparse(endpoint_url).hostname
    if host not in LOOPBACK_HOSTS:
        raise SystemExit(
            f"seed_emulator: refusing endpoint {endpoint_url!r}: this script creates "
            "resources, so it only talks to an emulator on localhost / 127.0.0.1"
        )


def reset_moto(endpoint_url: str) -> bool:
    """Clear a moto server's state so reruns start clean; False on other emulators."""
    request = urllib.request.Request(
        endpoint_url.rstrip("/") + "/moto-api/reset", method="POST", data=b""
    )
    try:
        with urllib.request.urlopen(request, timeout=5):
            return True
    except (urllib.error.URLError, OSError):
        return False


def write_profile(out_dir: Path, region: str) -> tuple[Path, Path]:
    """A throwaway config/credentials pair holding only the dummy profile."""
    aws_dir = out_dir / "aws"
    aws_dir.mkdir(parents=True, exist_ok=True)
    config_file = aws_dir / "config"
    credentials_file = aws_dir / "credentials"
    config_file.write_text(f"[profile {PROFILE}]\nregion = {region}\n", encoding="utf-8")
    credentials_file.write_text(
        f"[{PROFILE}]\naws_access_key_id = {DUMMY_KEY}\naws_secret_access_key = {DUMMY_KEY}\n",
        encoding="utf-8",
    )
    return config_file, credentials_file


def _lambda_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("handler.py", "def handler(event, context):\n    return event\n")
    return buffer.getvalue()


def _resource(
    address: str, values: dict[str, Any], depends_on: list[str] | None = None
) -> dict[str, Any]:
    resource_type, name = address.split(".", 1)
    block: dict[str, Any] = {
        "address": address,
        "mode": "managed",
        "type": resource_type,
        "name": name,
        "values": values,
    }
    if depends_on:
        block["depends_on"] = depends_on
    return block


def seed(endpoint_url: str, region: str, out_dir: Path) -> SeededWorld:
    """Create the emulator world and write the state that declares part of it."""
    require_loopback(endpoint_url)
    import boto3
    from botocore.config import Config

    reset_moto(endpoint_url)
    session = boto3.Session(
        aws_access_key_id=DUMMY_KEY, aws_secret_access_key=DUMMY_KEY, region_name=region
    )
    # Path-style S3: "bucket.localhost" does not resolve, so virtual-hosted
    # bucket URLs would never reach the emulator.
    path_style = Config(s3={"addressing_style": "path"})

    def client(service: str) -> Any:
        return session.client(service, endpoint_url=endpoint_url, config=path_style)

    account = client("sts").get_caller_identity()["Account"]

    ec2 = client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
    vpc_kwargs = {"VpcId": vpcs[0]["VpcId"]} if vpcs else {}
    web_sg = ec2.create_security_group(
        GroupName="web-sg", Description="web tier", **vpc_kwargs
    )["GroupId"]
    legacy_sg = ec2.create_security_group(
        GroupName="legacy-ops-sg", Description="added by hand during an incident", **vpc_kwargs
    )["GroupId"]
    image_id = ec2.describe_images()["Images"][0]["ImageId"]
    instance_id = ec2.run_instances(
        ImageId=image_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[web_sg, legacy_sg],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web-server"}]}
        ],
    )["Instances"][0]["InstanceId"]

    db_arn = client("rds").create_db_instance(
        DBInstanceIdentifier="primary",
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername="app",
        MasterUserPassword="emulator-only-password",
        AllocatedStorage=20,
        VpcSecurityGroupIds=[web_sg],
    )["DBInstance"]["DBInstanceArn"]

    s3 = client("s3")
    if region == "us-east-1":
        s3.create_bucket(Bucket=BUCKET)
    else:
        s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": region})

    iam = client("iam")
    role_arns: dict[str, str] = {}
    roles = (("processor_role", "s3:GetObject"), ("cleanup_role", "s3:DeleteObject"))
    for role_name, action in roles:
        role_arns[role_name] = iam.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=LAMBDA_TRUST
        )["Role"]["Arn"]
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"{role_name}-s3",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": action,
                            "Resource": f"arn:aws:s3:::{BUCKET}/*",
                        }
                    ],
                }
            ),
        )

    lam = client("lambda")
    function_arns: dict[str, str] = {}
    for function_name, role_name in (("processor", "processor_role"), ("cleanup", "cleanup_role")):
        function_arns[function_name] = lam.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arns[role_name],
            Handler="handler.handler",
            Code={"ZipFile": _lambda_zip()},
        )["FunctionArn"]

    # The declared world: everything above except legacy-ops-sg, the cleanup
    # function and its role. Those are the drift the scan should surface.
    resources = [
        _resource(
            "aws_security_group.web_sg",
            {
                "id": web_sg,
                "arn": f"arn:aws:ec2:{region}:{account}:security-group/{web_sg}",
                "name": "web-sg",
            },
        ),
        _resource(
            "aws_instance.web",
            {
                "id": instance_id,
                "arn": f"arn:aws:ec2:{region}:{account}:instance/{instance_id}",
                "instance_type": "t3.micro",
                "vpc_security_group_ids": [web_sg],
            },
            depends_on=["aws_security_group.web_sg"],
        ),
        _resource(
            "aws_db_instance.primary",
            {
                "id": "primary",
                "arn": db_arn,
                "engine": "postgres",
                "vpc_security_group_ids": [web_sg],
            },
        ),
        _resource(
            "aws_iam_role.processor_role",
            {"id": "processor_role", "arn": role_arns["processor_role"], "name": "processor_role"},
        ),
        _resource(
            "aws_lambda_function.processor",
            {
                "id": "processor",
                "arn": function_arns["processor"],
                "role": role_arns["processor_role"],
            },
            depends_on=["aws_iam_role.processor_role"],
        ),
        _resource("aws_s3_bucket.data_lake", {"id": BUCKET, "arn": f"arn:aws:s3:::{BUCKET}"}),
    ]
    state = {
        "format_version": "1.0",
        "terraform_version": "1.9.5",
        "values": {"root_module": {"resources": resources}},
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    state_path = out_dir / "state.json"
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    config_file, credentials_file = write_profile(out_dir, region)
    return SeededWorld(
        state_path=state_path,
        config_file=config_file,
        credentials_file=credentials_file,
        region=region,
        account=account,
        ids={
            "web_sg": web_sg,
            "legacy_sg": legacy_sg,
            "instance": instance_id,
            "db_arn": db_arn,
            "processor_arn": function_arns["processor"],
            "cleanup_arn": function_arns["cleanup"],
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--endpoint-url", required=True, help="emulator URL on loopback")
    parser.add_argument("--region", default="eu-west-1", help="emulated region (default eu-west-1)")
    parser.add_argument(
        "--out-dir", type=Path, default=Path(".emulator"), help="where state.json goes"
    )
    args = parser.parse_args(argv)

    world = seed(args.endpoint_url, args.region, args.out_dir)

    def scan_command(db: str, state: str) -> str:
        return (
            f"reality --database {db} scan {state} --aws --profile {PROFILE} "
            f"--region {world.region} --endpoint-url {args.endpoint_url}"
        )

    db = args.out_dir / "emulator.db"
    print(f"seed_emulator: seeded account {world.account} in {world.region} at {args.endpoint_url}")
    for name, value in world.ids.items():
        print(f"  {name}: {value}")
    print(f"  declared world: {world.state_path}")
    print("\nNext, in PowerShell:")
    print(f'  $env:AWS_CONFIG_FILE = "{world.config_file.resolve()}"')
    print(f'  $env:AWS_SHARED_CREDENTIALS_FILE = "{world.credentials_file.resolve()}"')
    print(f"  {scan_command(str(db), str(world.state_path))}")
    print(f"  reality --database {db} reconcile --output table")
    print("\nOr in bash:")
    print(f'  export AWS_CONFIG_FILE="{world.config_file.resolve().as_posix()}"')
    print(f'  export AWS_SHARED_CREDENTIALS_FILE="{world.credentials_file.resolve().as_posix()}"')
    print(f"  {scan_command(db.as_posix(), world.state_path.as_posix())}")
    print(f"  reality --database {db.as_posix()} reconcile --output table")
    return 0


if __name__ == "__main__":
    sys.exit(main())
