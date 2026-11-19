# e3-aws
High level interface for CloudFormation



## e3-aws troposphere

e3-aws troposphere module provides helper class to build a AWS CloudFormation stack with
troposphere and deploy it.
It defines high level Troposphere resources structured in the form of **constucts**.
Constructs can consist of one or multiple AWS troposphere objects that in most cases
are interdependent.

This module also provide a **Stack** stack abstraction that handles the addition
of constructs or raw AWSObject to a stack and its deployement.

See examples directory for examples of how to build and deploy stacks.

### Packaging Python Lambda dependencies

Dependency packaging supports Python 3.12 and 3.13 on Amazon Linux 2023. When a
Python Lambda specifies a `requirement_file`, e3-aws uses `uv` to install its
dependencies into the deployment ZIP. Install [uv][uv-install] and make it
available on `PATH` in the environment that builds the Lambda asset.

[uv-install]: https://docs.astral.sh/uv/getting-started/installation/
