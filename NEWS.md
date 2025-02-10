# Version 22.4.0 (2024-??-??) *NOT RELEASED YET*

* Add VPCv2 construct supporting private subnets over multiple AZ.
* S3WebsiteDistribution can now define the python runtime for the lambda invalidating cloudfront cache.

# Version 22.3.0 (2024-24-01)

* Add support for stages and lambda aliases to RestApi
* Python packages are now downloaded according to the targeted runtime instead
  of host platform
* BucketWithRoles now supports different trusted accounts for read and write
  roles
* Retain is now the default DeletionPolicy for Buckets
* Add a method to add outputs to a Stack
* Add an option to prefix VPC endpoint IDs to allow multiple VPCs with the same
  endpoints in the same stack

# Version 22.2.0 (2023-04-03)

* Improve HTTP API support
  * Update flask wrapper to accept requests from REST API
  * Allow configuring multiple HTTP API stages
* Improve VPC support
  * Enable HTTPS more broadly
  * Support SES endpoints
* New additions:
  * Allow a list of roles in troposphere.iam.Trust
  * Add Construct for cloudwatch.Alarm
  * Add Construct for dynamodb.Table
* Enhance CD/CI support
  * CFNMain now supports a dry run mode for CI
  * Add support for blue/green deployment

# Version 22.1.0 (2022-09-02)

* First version published on pypi
