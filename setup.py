from setuptools import setup, find_packages
import os

# Get e3 version from the VERSION file.
version_file = os.path.join(os.path.dirname(__file__), "VERSION")
with open(version_file) as f:
    e3_version = f.read().strip()

setup(
    name="e3-aws",
    version=e3_version,
    description="E3 Cloud Formation Extension",
    author="AdaCore's Production Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=(
        "boto3",
        "botocore",
        # Only require docker for linux as there is a known dependency issue
        # with pywin32 on windows
        "docker; platform_system=='Linux'",
        "pyyaml",
        "troposphere",
        "e3-core",
    ),
    namespace_packages=["e3"],
    entry_points={
        "e3.event.handler": ["s3-boto3 = e3.aws.handler.s3:S3Handler"],
        "console_scripts": ["e3-aws-assume-role = e3.aws:assume_role_main"],
    },
)
