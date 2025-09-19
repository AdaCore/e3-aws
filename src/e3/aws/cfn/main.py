from __future__ import annotations
import abc
import logging
import os
import tempfile
import time
import json
from datetime import datetime
import re

import botocore.exceptions

from e3.os.process import PIPE
from e3.vcs.git import GitRepository
from e3.aws import AWSEnv, Session
from e3.aws.s3 import bucket
from e3.aws.cfn import Stack
from e3.env import Env
from e3.fs import find, sync_tree
from e3.main import Main


class CFNMain(Main, metaclass=abc.ABCMeta):
    """Main to handle CloudFormation stack from command line."""

    def __init__(
        self,
        regions: list[str],
        default_profile: str | None = None,
        assets_dir: str | None = None,
        data_dir: str | None = None,
        s3_bucket: str | None = None,
        s3_key: str = "",
        assume_read_role: tuple[str, str] | None = None,
        assume_role: tuple[str, str] | None = None,
        deploy_branch: str | None = None,
    ):
        """Initialize main.

        :param regions: list of regions on which we can operate
        :param default_profile: default AWS profile to use to create the stack
        :param assets_dir: directory containing assets of the stack
        :param data_dir: directory containing files used by cfn-init
        :param s3_bucket: if defined S3 will be used as a proxy for resources.
            Template body will be uploaded to S3 before calling operation on
            it. This change the body limit from 50Ko to 500Ko. Additionally if
            data_dir is defined, the directory will be uploaded to the
            specified S3 bucket.
        :param s3_key: if s3_bucket is defined, then all uploaded resources
            will be stored under a subkey of s3_key. If not defined the root
            of the bucket is used.
        :param assume_read_role: tuple containing the two values that are passed
            to Session.assume_role() for read-only
        :param assume_role: tuple containing the two values that are passed
            to Session.assume_role() for deploy
        :param deploy_branch: git branch the script is allowed to deploy from
        """
        super(CFNMain, self).__init__(platform_args=False)
        self.argument_parser.add_argument(
            "--profile",
            help="choose AWS profile{}".format(
                "" if default_profile is None else f", default is {default_profile}"
            ),
            default=default_profile,
        )

        if len(regions) > 1:
            self.argument_parser.add_argument(
                "--region",
                help="choose region (default: %s)" % regions[0],
                default=regions[0],
            )
        else:
            self.argument_parser.set_defaults(region=regions[0])

        subs = self.argument_parser.add_subparsers(
            title="commands", description="available commands", dest="command"
        )
        subs.required = True

        create_args = subs.add_parser("push", help="push a stack")
        create_args.add_argument(
            "--no-wait",
            action="store_false",
            default=True,
            dest="wait_stack_creation",
            help="do not wait for stack creation completion",
        )
        create_args.add_argument(
            "--dry-run", action="store_true", help="do not create the stack, log only"
        )
        create_args.set_defaults(command="push")

        update_args = subs.add_parser("update", help="update a stack")
        update_args.add_argument(
            "--no-apply",
            action="store_false",
            default=True,
            dest="apply_changeset",
            help="do not ask whether to apply the changeset",
        )
        update_args.add_argument(
            "--no-wait",
            action="store_false",
            default=True,
            dest="wait_stack_creation",
            help="do not wait for stack update completion",
        )
        update_args.add_argument(
            "-y",
            "--yes",
            action="store_true",
            dest="skip_prompts",
            help="automatic yes to prompts",
        )
        update_args.add_argument(
            "--dry-run", action="store_true", help="do not update the stack, log only"
        )
        update_args.set_defaults(command="update")

        show_args = subs.add_parser("show", help="show the changeset content")
        show_args.set_defaults(command="show")

        protect_args = subs.add_parser(
            "protect", help="protect the stack against deletion"
        )
        protect_args.set_defaults(command="protect")

        delete_args = subs.add_parser("delete", help="delete stack")
        delete_args.add_argument(
            "--no-wait",
            action="store_false",
            default=True,
            dest="wait_stack_creation",
            help="do not wait for stack deletion completion",
        )
        delete_args.set_defaults(command="delete")

        show_cfn_policy_args = subs.add_parser(
            "show-cfn-policy", help="show required policy for CFN"
        )
        show_cfn_policy_args.set_defaults(command="show-cfn-policy")

        self.regions = regions

        self.assets_dir = assets_dir
        self.data_dir = data_dir
        self.s3_bucket = s3_bucket
        self.s3_assets_key = None
        self.s3_assets_url = None
        self.s3_data_key = None
        self.s3_data_url = None
        self.s3_template_key = None
        self.s3_template_url = None
        self.assume_read_role = assume_read_role
        self.assume_role = assume_role
        self.aws_env: Session | AWSEnv | None = None
        self.deploy_branch = deploy_branch

        self.timestamp = datetime.utcnow().strftime("%Y-%m-%d/%H:%M:%S.%f")

        if s3_bucket is not None:
            s3_root_key = f"{s3_key.strip('/')}/"
            s3_root_url = f"https://{self.s3_bucket}.s3.amazonaws.com/"

            # Assets use a static key
            self.s3_assets_key = f"{s3_root_key}assets/"
            self.s3_assets_url = f"{s3_root_url}{self.s3_assets_key}"

            # Data and template use a dynamic key based on the timestamp
            s3_timestamp_key = (
                "/".join([s3_root_key.rstrip("/"), self.timestamp]).strip("/") + "/"
            )
            self.s3_data_key = f"{s3_timestamp_key}data/"
            self.s3_data_url = f"{s3_root_url}{self.s3_data_key}"

            self.s3_template_key = f"{s3_timestamp_key}template"
            self.s3_template_url = f"{s3_root_url}{self.s3_template_key}"

    @property
    def dry_run(self) -> bool:
        """Return True if CloudFormation stack is not to be deployed."""
        assert self.args is not None
        return self.args.command not in ("push", "update") or self.args.dry_run

    def create_data_dir(self, root_dir: str) -> None:
        """Sync into root_dir data uploaded to the s3 bucket used by the stack.

        By default the content of self.data_dir is copied into root_dir.
        self.s3_data_key and self.s3_bucket can be used to reference resources in
        the template. The method can be overriden to create dynamically the content
        to upload.

        :param root_dir: location in which data to upload should be placed.
        """
        if self.data_dir is not None:
            sync_tree(self.data_dir, root_dir)

    def _prompt_yes(self, msg: str) -> bool:
        """Prompt user for yes or no answer.

        :param msg: short question to ask user
        :return: if user answered yes
        """
        assert self.args is not None
        if self.args.skip_prompts:
            return True

        ask = input(f"{msg} (y/N): ")
        return ask[0] in "Yy"

    def _upload_dir(
        self,
        root_dir: str,
        s3_bucket: str,
        s3_key: str,
        s3_client: botocore.client.S3 | None = None,
        check_exists: bool = False,
    ) -> None:
        """Upload directory to S3 bucket.

        :param root_dir: directory
        :param s3_bucket: bucket where to upload files
        :param s3_key: key prefix for uploaded files
        :param s3_client: a client for the S3 API
        :param check_exists: check if an S3 object exists before uploading it
        """
        assert self.args is not None

        for f in find(root_dir):
            subkey = os.path.relpath(f, root_dir).replace("\\", "/")

            logging.info(
                "Upload %s to %s:%s%s",
                subkey,
                s3_bucket,
                s3_key,
                subkey,
            )

            if s3_client is None:
                continue

            with bucket(
                s3_bucket, client=s3_client, auto_create=False
            ) as upload_bucket:
                # Check already existing S3 objects.
                # Ignore the potential 403 error as CFN roles often only have the
                # s3:GetObject permission on the bucket
                s3_object_key = f"{s3_key}{subkey}"
                if check_exists and upload_bucket.object_exists(
                    s3_object_key, ignore_error_403=True
                ):
                    logging.info(
                        "Skip already existing %s",
                        subkey,
                    )
                    continue

                if not self.args.dry_run:
                    with open(f, "rb") as fd:
                        upload_bucket.push(key=s3_object_key, content=fd, exist_ok=True)

    def _upload_stack(self, stack: Stack) -> None:
        """Upload stack data and template to S3.

        :param stack: the stack to upload
        """
        # Nothing to upload if there is no S3 bucket set
        if self.s3_bucket is None:
            return

        assert self.args is not None

        s3 = self.aws_env.client("s3") if self.aws_env else None

        with tempfile.TemporaryDirectory() as tempd:
            # Push data associated with CFNMain and then all data
            # related to the stack
            self.create_data_dir(root_dir=tempd)
            stack.create_data_dir(root_dir=tempd)

            if self.s3_data_key is not None:
                # synchronize data to the bucket before creating the stack
                self._upload_dir(
                    root_dir=tempd,
                    s3_bucket=self.s3_bucket,
                    s3_key=self.s3_data_key,
                    s3_client=s3,
                )

        if self.s3_template_key is not None:
            logging.info(
                "Upload template to %s:%s",
                self.s3_bucket,
                self.s3_template_key,
            )
            if s3 is not None and not self.args.dry_run:
                s3.put_object(
                    Bucket=self.s3_bucket,
                    Body=stack.body.encode("utf-8"),
                    ServerSideEncryption="AES256",
                    Key=self.s3_template_key,
                )

    def _push_stack_changeset(self, stack: Stack, s3_template_url: str | None) -> int:
        """Push the changeset of a stack from an already uploaded S3 template.

        Create the stack if it doesn't exist.

        :param stack: the stack
        :param s3_template_url: URL of the template
        :return: an error code
        """
        assert self.args is not None

        if stack.exists():
            changeset_name = "changeset%s" % int(time.time())
            logging.info("Push changeset: %s" % changeset_name)
            stack.create_change_set(changeset_name, url=s3_template_url)
            result = stack.describe_change_set(changeset_name)
            while result["Status"] in (
                "CREATE_PENDING",
                "CREATE_IN_PROGRESS",
            ):
                time.sleep(1.0)
                result = stack.describe_change_set(changeset_name)

            if result["Status"] == "FAILED":
                change_executed = False
                if (
                    "The submitted information didn't contain changes"
                    in result["StatusReason"]
                ):
                    logging.warning(result["StatusReason"])
                    change_executed = True
                else:
                    logging.error(result["StatusReason"])

                stack.delete_change_set(changeset_name)
                if not change_executed:
                    return 1
            else:
                for el in result["Changes"]:
                    if "ResourceChange" not in el:
                        continue
                    logging.info(
                        "%-8s %-32s: (replacement:%s)",
                        el["ResourceChange"].get("Action"),
                        el["ResourceChange"].get("LogicalResourceId"),
                        el["ResourceChange"].get("Replacement", "n/a"),
                    )

                if self.args.apply_changeset and self._prompt_yes("Apply change"):
                    stack.execute_change_set(
                        changeset_name=changeset_name,
                        wait=self.args.wait_stack_creation,
                    )

                    if self.args.wait_stack_creation:
                        return (
                            0
                            if stack.state()["StackStatus"] == "UPDATE_COMPLETE"
                            else 1
                        )
        else:
            logging.info("Create new stack")
            stack.create(url=s3_template_url, wait=self.args.wait_stack_creation)

        return 0

    def execute_for_stack(self, stack: Stack, aws_env: Session | None = None) -> int:
        """Execute application for a given stack and return exit status.

        :param Stack: the stack on which the application executes
        :param aws_env: custom AWS session to use
        """
        assert self.args is not None
        try:
            self.start_session(
                profile=self.args.profile, region=self.args.region, aws_env=aws_env
            )

            if self.args.command in ("push", "update"):
                # Synchronize resources to the S3 bucket
                self._upload_stack(stack)

                logging.info("Validate template for stack %s" % stack.name)
                if not self.args.dry_run:
                    try:
                        stack.validate(url=self.s3_template_url)
                    except Exception:
                        logging.error("Invalid cloud formation template")
                        logging.error(stack.body)
                        raise

                    return self._push_stack_changeset(
                        stack=stack, s3_template_url=self.s3_template_url
                    )

            elif self.args.command == "show":
                print(stack.body)
            elif self.args.command == "protect":
                # Enable termination protection
                stack.enable_termination_protection()

                if self.stack_policy_body is not None:
                    stack.set_stack_policy(self.stack_policy_body)
                else:
                    print("No stack policy to set")
            elif self.args.command == "show-cfn-policy":
                try:
                    print(
                        json.dumps(
                            stack.cfn_policy_document().as_dict,  # type: ignore
                            indent=2,
                        )
                    )
                except AttributeError as attr_e:
                    print(f"command supported only with troposphere stacks: {attr_e}")
            elif self.args.command == "delete":
                stack.delete(wait=self.args.wait_stack_creation)

            return 0
        except botocore.exceptions.ClientError as e:
            logging.error(str(e))
            return 1

    def execute(
        self,
        args: list[str] | None = None,
        known_args_only: bool = False,
        aws_env: Session | None = None,
    ) -> int:
        """Execute application and return exit status.

        See parse_args arguments.
        """
        super(CFNMain, self).parse_args(args, known_args_only)
        assert self.args is not None

        # Some checks in case of deployment.
        # The CI variable is set by GitLab.
        # Don't run the checks when in dry-run mode as this is not a real deploy.
        if (
            os.environ.get("CI") != "true"
            and self.args.command in ("push", "update")
            and not self.args.dry_run
        ):
            repo = GitRepository(".")

            # Retrieve the current branch
            try:
                branch = repo.git_cmd(
                    ["branch", "--show-current"], output=PIPE
                ).out.strip()
            except Exception as e:
                logging.error(f"Failed to get the current branch: {e}")
                return 1

            # Check we are on the correct branch
            if self.deploy_branch is not None and self.deploy_branch != branch:
                print(f"Can only deploy from branch {self.deploy_branch}")
                return 1

            # Check there are no local changes
            try:
                changes = repo.git_cmd(["status", "-s"], output=PIPE).out.strip()
                if changes != "":
                    print(
                        "Can only deploy from a clean repository, ensure you have "
                        "no modified files"
                    )
                    return 1
            except Exception as e:
                logging.error(f"Failed to check local changes: {e}")
                return 1

            # Check the branch is up to date
            try:
                fetch_out = repo.git_cmd(
                    ["fetch", "origin", branch, "--dry-run"], output=PIPE
                ).out
                # Check if there is a line indicating a commit
                if re.search(r"{}\s*\-\>\s*origin\/".format(branch), fetch_out):
                    print(
                        "Can only deploy from up to date branch, please do a git pull"
                    )
                    return 1
            except Exception as e:
                logging.error(f"Failed to fetch {branch}: {e}")
                return 1

        return_val = 0
        stacks = self.create_stack()

        if isinstance(stacks, list):
            for stack in stacks:
                return_val = self.execute_for_stack(stack, aws_env=aws_env)
                # Stop at first failure
                if return_val:
                    return return_val
        else:
            return_val = self.execute_for_stack(stacks, aws_env=aws_env)

        return return_val

    @abc.abstractmethod
    def create_stack(self) -> Stack | list[Stack]:
        """Create a stack.

        :return: Stack on which the application will operate
        """
        pass

    @property
    def stack_policy_body(self) -> str | None:
        """Stack Policy that can be set by calling the command ``protect``.

        :return: the inline stack policy
        """
        return None

    def start_session(
        self,
        profile: str | None = None,
        region: str | None = None,
        aws_env: Session | None = None,
    ) -> None:
        """Start the AWS session.

        If an assume_role was passed in the constructor, then it will try
        to assume the role.

        :param profile: AWS profile for the session
        :param region: region for the session
        :param aws_env: custom AWS session to use
        """
        if aws_env is not None:
            self.aws_env = aws_env
        else:
            assert self.args is not None
            is_show = self.args.command == "show"
            assume_role = self.assume_read_role if is_show else self.assume_role
            if assume_role:
                try:
                    main_session = Session(regions=self.regions, profile=profile)
                    self.aws_env = main_session.assume_role(
                        assume_role[0], assume_role[1]
                    )
                    # ??? needed since we still use a global variable for AWSEnv
                    Env().aws_env = self.aws_env
                except botocore.exceptions.NoCredentialsError:
                    # Don't force assume the role for the show command. The stacks
                    # that require AWS API calls to generate the template can display
                    # dummy values. Same thing for the dry-run mode.
                    if not is_show and not self.args.dry_run:
                        raise
            else:
                self.aws_env = AWSEnv(regions=self.regions, profile=profile)

            if self.aws_env:
                self.aws_env.default_region = (
                    self.regions[0] if region is None else region
                )
