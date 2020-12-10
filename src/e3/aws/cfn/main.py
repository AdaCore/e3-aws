from __future__ import annotations
import abc
import logging
import os
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import List, Union

import botocore.exceptions

from e3.aws import AWSEnv, Session, Stack
from e3.env import Env
from e3.fs import find
from e3.main import Main


class CFNMain(Main, metaclass=abc.ABCMeta):
    """Main to handle CloudFormation stack from command line."""

    def __init__(
        self,
        regions,
        default_profile="default",
        data_dir=None,
        s3_bucket=None,
        s3_key="",
        assume_role=None,
    ):
        """Initialize main.

        :param regions: list of regions on which we can operate
        :type regions: list[str]
        :param default_profile: default AWS profile to use to create the stack
        :type default_region: str
        :param data_dir: directory containing files used by cfn-init
        :type data_dir: str | None
        :param s3_bucket: if defined S3 will be used as a proxy for resources.
            Template body will be uploaded to S3 before calling operation on
            it. This change the body limit from 50Ko to 500Ko. Additionally if
            data_dir is defined, the directory will be uploaded to the
            specified S3 bucket.
        :param s3_key: if s3_bucket is defined, then all uploaded resources
            will be stored under a subkey of s3_key. If not defined the root
            of the bucket is used.
        :type: str
        :param assume_role: tuple containing the two values that are passed
            to Session.assume_role()
        :type assume_role: str
        """
        super(CFNMain, self).__init__(platform_args=False)
        self.argument_parser.add_argument(
            "--profile",
            help="choose AWS profile, default is {}".format(default_profile),
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
        create_args.set_defaults(command="push")

        update_args = subs.add_parser("update", help="update a stack")
        update_args.add_argument(
            "--no-apply",
            action="store_false",
            default=True,
            dest="apply_changeset",
            help="do not ask whether to apply the changeset",
        )
        update_args.set_defaults(command="update")

        show_args = subs.add_parser("show", help="show the changeset content")
        show_args.set_defaults(command="show")

        protect_args = subs.add_parser(
            "protect", help="protect the stack against deletion"
        )
        protect_args.set_defaults(command="protect")

        self.regions = regions

        self.data_dir = data_dir
        self.s3_bucket = s3_bucket
        self.s3_data_key = None
        self.s3_data_url = None
        self.s3_template_key = None
        self.s3_template_url = None
        self.assume_role = assume_role

        self.timestamp = str(int(time.time()))

        if s3_bucket is not None:
            s3_root_key = (
                "/".join([s3_key.rstrip("/"), self.timestamp]).strip("/") + "/"
            )
            self.s3_data_key = s3_root_key + "data/"
            self.s3_data_url = "https://%s.s3.amazonaws.com/%s" % (
                self.s3_bucket,
                self.s3_data_key,
            )
            self.s3_template_key = s3_root_key + "template"
            self.s3_template_url = "https://%s.s3.amazonaws.com/%s" % (
                self.s3_bucket,
                self.s3_template_key,
            )

    def execute_for_stack(self, stack: Stack) -> int:
        """Execute application for a given stack and return exit status.

        :param Stack: the stack on which the application executes
        """
        try:
            if self.args.command in ("push", "update"):
                if self.data_dir is not None and self.s3_data_key is not None:
                    s3 = self.aws_env.client("s3")

                    # synchronize data to the bucket before creating the stack
                    for f in find(self.data_dir):
                        with open(f, "rb") as fd:
                            subkey = os.path.relpath(f, self.data_dir).replace(
                                "\\", "/"
                            )
                            logging.info(
                                "Upload %s to %s:%s%s",
                                subkey,
                                self.s3_bucket,
                                self.s3_data_key,
                                subkey,
                            )
                            s3.put_object(
                                Bucket=self.s3_bucket,
                                Body=fd,
                                ServerSideEncryption="AES256",
                                Key=self.s3_data_key + subkey,
                            )

                if self.s3_template_key is not None:
                    logging.info(
                        "Upload template to %s:%s", self.s3_bucket, self.s3_template_key
                    )
                    s3.put_object(
                        Bucket=self.s3_bucket,
                        Body=stack.body.encode("utf-8"),
                        ServerSideEncryption="AES256",
                        Key=self.s3_template_key,
                    )

                logging.info("Validate template for stack %s" % stack.name)
                try:
                    stack.validate(url=self.s3_template_url)
                except Exception:
                    logging.error("Invalid cloud formation template")
                    logging.error(stack.body)
                    raise

                if stack.exists():
                    changeset_name = "changeset%s" % int(time.time())
                    logging.info("Push changeset: %s" % changeset_name)
                    stack.create_change_set(changeset_name, url=self.s3_template_url)
                    result = stack.describe_change_set(changeset_name)
                    while result["Status"] in ("CREATE_PENDING", "CREATE_IN_PROGRESS"):
                        time.sleep(1.0)
                        result = stack.describe_change_set(changeset_name)

                    if result["Status"] == "FAILED":
                        logging.error(result["StatusReason"])
                        stack.delete_change_set(changeset_name)
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

                        if self.args.apply_changeset:
                            ask = input("Apply change (y/N): ")
                            if ask[0] in "Yy":
                                return stack.execute_change_set(
                                    changeset_name=changeset_name, wait=True
                                )
                        return 0
                else:
                    logging.info("Create new stack")
                    stack.create(url=self.s3_template_url)
                    state = stack.state()
                    if self.args.wait_stack_creation:
                        logging.info("waiting for stack creation...")
                        while "PROGRESS" in state["Stacks"][0]["StackStatus"]:
                            result = stack.resource_status(in_progress_only=False)
                            time.sleep(10.0)
                            state = stack.state()
                        logging.info("done")
            elif self.args.command == "show":
                print(stack.body)
            elif self.args.command == "protect":
                # Enable termination protection
                result = stack.enable_termination_protection()

                if self.stack_policy_body is not None:
                    stack.set_stack_policy(self.stack_policy_body)
                else:
                    print("No stack policy to set")

            return 0
        except botocore.exceptions.ClientError as e:
            logging.error(str(e))
            return 1

    def execute(self, args=None, known_args_only=False, aws_env=None):
        """Execute application and return exit status.

        See parse_args arguments.
        """
        super(CFNMain, self).parse_args(args, known_args_only)
        if aws_env is not None:
            self.aws_env = aws_env
        else:

            if self.assume_role:
                main_session = Session(regions=self.regions, profile=self.args.profile)
                self.aws_env = main_session.assume_role(
                    self.assume_role[0], self.assume_role[1]
                )
                # ??? needed since we still use a global variable for AWSEnv
                Env().aws_env = self.aws_env
            else:
                self.aws_env = AWSEnv(regions=self.regions, profile=self.args.profile)
            self.aws_env.default_region = self.args.region

        return_val = 0
        stacks = self.create_stack()

        if isinstance(stacks, list):
            for stack in stacks:
                return_val = self.execute_for_stack(stack)
                # Stop at first failure
                if return_val:
                    return return_val
        else:
            return_val = self.execute_for_stack(stacks)

        return return_val

    @abc.abstractmethod
    def create_stack(self) -> Union[Stack, List[Stack]]:
        """Create a stack.

        :return: Stack on which the application will operate
        :rtype: Stack
        """
        pass

    @property
    def stack_policy_body(self):
        """Stack Policy that can be set by calling the command ``protect``.

        :return: the inline stack policy
        :rtype: str
        """
        return None
