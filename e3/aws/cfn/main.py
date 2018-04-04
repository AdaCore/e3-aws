import abc
import logging
import time

import botocore.exceptions
import yaml
from e3.aws import AWSEnv
from e3.main import Main


class CFNMain(Main, metaclass=abc.ABCMeta):
    """Main to handle CloudFormation stack from command line."""

    def __init__(self, regions, force_profile=None):
        """Initialize main.

        :param regions: list of regions on which we can operate
        :type regions: list[str]
        :param force_profile: if None then add ability to select a credential
            profile to use. Otherwise profile is set
        :type force_profile: str | None
        """
        super(CFNMain, self).__init__(platform_args=False)
        self.argument_parser.add_argument(
            '--profile',
            help='choose AWS profile',
            default='default')

        if len(regions) > 1:
            self.argument_parser.add_argument(
                '--region',
                help='choose region (default: %s)' % regions[0],
                default=regions[0])
        else:
            self.argument_parser.set_defaults(region=regions[0])

        subs = self.argument_parser.add_subparsers(
            title='commands',
            description='available commands')

        create_args = subs.add_parser('push', help='push a stack')
        create_args.add_argument(
            '--wait',
            action='store_true',
            default=False,
            help='if used then wait for stack creation completion')
        create_args.set_defaults(command='push')

        self.regions = regions

    def execute(self, args=None, known_args_only=False):
        """Execute application and return exit status.

        See parse_args arguments.
        """
        super(CFNMain, self).parse_args(args, known_args_only)
        self.aws_env = AWSEnv(regions=self.regions,
                              profile=self.args.profile)
        self.aws_env.default_region = self.args.region

        try:
            if self.args.command == 'push':
                s = self.create_stack()

                logging.info('Validate template for stack %s' % s.name)
                s.validate()

                if s.exists():
                    changeset_name = 'changeset%s' % int(time.time())
                    logging.info('Push changeset: %s' % changeset_name)
                    s.create_change_set(changeset_name)
                    result = s.describe_change_set(changeset_name)
                    while result['Status'] in ('CREATE_PENDING',
                                               'CREATE_IN_PROGRESS'):
                        time.sleep(1.0)
                        result = s.describe_change_set(changeset_name)

                    if result['Status'] == 'FAILED':
                        logging.error(result['StatusReason'])
                        s.delete_change_set(changeset_name)
                        return 1
                    else:
                        print(yaml.safe_dump(result['Changes']))
                        return 0
                else:
                    logging.info('Create new stack')
                    s.create()
                    state = s.state()
                    if self.args.wait:
                        while 'PROGRESS' in state['Stacks'][0]['StackStatus']:
                            result = s.resource_status(in_progress_only=False)
                            print(result)
                            time.sleep(10.0)
                            state = s.state()
            else:
                return 1
            return 0
        except botocore.exceptions.ClientError as e:
            logging.error(str(e))
            return 1

    @abc.abstractmethod
    def create_stack(self):
        """Create a stack.

        :return: Stack on which the application will operate
        :rtype: Stack
        """
