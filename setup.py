from setuptools import setup, find_packages
from datetime import datetime

version = '20.08.' + datetime.utcnow().strftime('%Y%m%d')

setup(
    name='e3-aws',
    version=version,
    description="E3 Cloud Formation Extension",
    author="AdaCore's Production Team",
    packages=find_packages(),
    install_requires=('botocore', 'pyyaml', 'e3-core'),
    namespace_packages=['e3'],
    entry_points={
        'console_scripts': [
            'e3-aws-assume-role = e3.aws:assume_role_main'
        ]})
