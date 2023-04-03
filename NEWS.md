# Version 22.3.0 (2022-??-??) *NOT RELEASED YET*

* Nothing

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
