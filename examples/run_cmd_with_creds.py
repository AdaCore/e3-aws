#!/usr/bin/env python
"""Run a command with credentials obtained from assuming a given AWS role."""
import argparse

from e3.aws import Session
from e3.main import Main


def main() -> None:
    """Provide entry point."""
    parser = argparse.ArgumentParser(description="Launch command with AWS credentials")

    parser.add_argument("--region", help="AWS region to use", default="eu-west-1")
    parser.add_argument(
        "--profile", help="AWS profile to use to run the command.", default=None
    )
    parser.add_argument(
        "--role-arn",
        help="ARN of the role to assume to run the command.",
        required=True,
    )
    parser.add_argument(
        "--session_duration",
        help="session duration in seconds or None for default",
        default=None,
    )
    parser.add_argument("command")

    main_parser = Main(argument_parser=parser)
    main_parser.parse_args()
    assert main_parser.args is not None

    session = Session(
        profile=main_parser.args.profile, regions=[main_parser.args.region]
    )

    session.run(
        main_parser.args.command.split(),
        role_arn=main_parser.args.role_arn,
        session_duration=main_parser.args.session_duration,
        output=None,
    )


if __name__ == "__main__":
    main()
