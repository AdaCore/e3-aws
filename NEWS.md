# Version 22.6.0 (2025-??-??) *NOT RELEASED YET*

* nothing yet

# Version 22.5.0 (2025-04-01)

* Add VPCv2 construct supporting private subnets over multiple AZ.
* S3WebsiteDistribution can now define the python runtime for the lambda invalidating cloudfront cache.
* Fix tests using moto following moto v5 release
* Add an helper for the Pricing API
* Add support for keyword arguments to Bucket Construct
* Add a method to subscribe SQS queue to SNS topic
* Stop requiring --sse=AES256 when uploading to S3
* Add LoggingConfiguration parameter for lambda function
* Fix S3 VPC Gateway endpoint route table IDs
* Make S3 interface endpoints depend on Gateway endpoint
* Add platforms for AWS Lambda Runtime configurations
* Add a default LifeCycle rule when creating a bucket

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
