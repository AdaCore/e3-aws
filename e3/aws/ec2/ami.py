from __future__ import absolute_import, division, print_function

from e3.env import Env


class AMI(object):
    """Represent an AMI."""

    def __init__(self, ami_id, region=None, data=None):
        """Inialize an AMI description object.

        :param ami_id: the id of the AMI
        :type ami_id: str
        :param region: region in which the AMI is present. If None then
            use default region
        :type region: None | str
        :param data: a dict representing the metadata of the AMI. If None then
            download AMI description using EC2 api
        :type data: dict | None
        """
        self.ami_id = ami_id
        self.region = region
        if self.region is None:
            self.region = Env().aws_env.default_region

        if data is None:
            aws_env = Env().aws_env
            self.data = aws_env.client('ec2', self.region).describe_images(
                ImageIds=[self.ami_id])['Images'][0]
        else:
            self.data = data

    @property
    def id(self):
        return self.data['ImageId']

    @property
    def root_device(self):
        return self.data['RootDeviceName']

    def __str__(self):
        return '%-12s %-24s: %s' % (self.region,
                                    self.data['ImageId'],
                                    self.data.get('Description', ''))

    @classmethod
    def ls(cls):
        """List user AMIs."""
        aws_env = Env().aws_env

        result = []
        for r in aws_env.regions:
            c = aws_env.client('ec2', r)
            region_result = c.describe_images(Owners=['self'])
            for ami in region_result['Images']:
                result.append(AMI(ami['ImageId'], r, data=ami))
        return result
