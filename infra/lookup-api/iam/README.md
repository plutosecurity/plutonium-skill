# AWS permission handoff

There are two identities with different permissions. Do not give the public Lambda deployment permissions.

## Lambda runtime role

An administrator should run [`../bootstrap_execution_role.sh`](../bootstrap_execution_role.sh), which deploys [`execution-role.yaml`](execution-role.yaml), or create the equivalent role named `plutonium-catalog-lookup-execution-prod` in `eu-central-1`.

The role trusts only `lambda.amazonaws.com` and has:

- `s3:GetObject` and `s3:GetObjectVersion` only under `plutonium-catalog-lookup-<account>-eu-central-1-prod/*`;
- `s3:GetBucketLocation` on that bucket;
- the AWS-managed `AWSLambdaBasicExecutionRole` policy for CloudWatch logs.

It does not have S3 write access and cannot create or modify AWS infrastructure.

## Human deployment permission set

The existing `Plutonium` Identity Center permission set needs scoped management access for:

- Lambda function `plutonium-catalog-lookup-*`, including code/configuration updates, reserved concurrency, tags, and API Gateway invoke permissions;
- API Gateway v2 API/stage/route/integration resources for `plutonium-catalog-lookup-*`;
- the dedicated S3 bucket `plutonium-catalog-lookup-*-eu-central-1-*`, including bucket configuration and object upload;
- CloudWatch log groups `/aws/lambda/plutonium-catalog-lookup-*` and `/aws/apigateway/plutonium-catalog-lookup-*`. Enabling HTTP API access logging also requires the CloudWatch Logs delivery actions AWS documents on `Resource: *`: `CreateLogDelivery`, `PutResourcePolicy`, `UpdateLogDelivery`, `DeleteLogDelivery`, `DescribeResourcePolicies`, `GetLogDelivery`, and `ListLogDeliveries`;
- `iam:PassRole` only for `plutonium-catalog-lookup-execution-*`, with `iam:PassedToService` restricted to `lambda.amazonaws.com`;
- CloudFormation stack `plutonium-catalog-lookup-*` and the SAM packaging bucket used by `sam deploy`.

If Gil deploys the first stack on your behalf, the ongoing human permissions can be narrower: publish new catalog objects, update the function/configuration, read logs/metrics, and read the stack outputs.

The Policy Simulator checks performed earlier covered the four direct creation actions. A SAM deployment additionally uses CloudFormation and CloudWatch Logs, so those must either be added to the permission set or handled by Gil during the initial deployment.
