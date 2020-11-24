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