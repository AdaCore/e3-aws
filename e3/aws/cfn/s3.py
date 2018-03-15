from enum import Enum

from e3.aws.cfn import AWSType, Resource


class AccessControl(Enum):
    """Canned ACLs for buckets."""

    AUTHENTICATED_READ = 'AuthenticatedRead'
    AWS_EXEC_READ = 'AwsExecRead'
    BUCKET_OWNER_READ = 'BucketOwnerRead'
    BUCKET_OWNER_FULL_CONTROL = 'BucketOwnerFullControl'
    LOG_DELIVERY_WRITE = 'LogDeliveryWrite'
    PRIVATE = 'Private'
    PUBLIC_READ = 'PublicRead'
    PUBLIC_WRITE = 'PublicReadWrite'


class Bucket(Resource):
    """S3 Bucket."""

    ATTRIBUTES = ('Arn', 'DomainName')

    def __init__(self, name, access_control=None, bucket_name=None):
        """Initialize a S3 bucket.

        :param name: logical name of the resource in the stack
        :type name: str
        :param acccess_control: A canned access control list (ACL) that grants
            predefined permissions to the bucket. if None default is PRIVATE
        :type access_control: None | AccessControl
        :param bucket_name: the bucket name in AWS. If set cloud formation will
            not be able to update settings of the buckets automatically.
        :type bucket_name: str | None
        """
        super(Bucket, self).__init__(name, kind=AWSType.S3_BUCKET)
        if access_control is None:
            self.access_control = AccessControl.PRIVATE
        else:
            assert isinstance(access_control, AccessControl)
            self.access_control = access_control
        self.bucket_name = bucket_name

    @property
    def arn(self):
        return self.getatt('Arn')

    @property
    def properties(self):
        result = {'AccessControl': self.access_control.value}
        if self.bucket_name is not None:
            result['BucketName'] = self.bucket_name
        return result
