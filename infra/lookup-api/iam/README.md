# AWS permissions for the Plutonium lookup service

This deployment uses two separate identities. The human deployer manages the
infrastructure; the Lambda runtime role can only read the private catalog and
write its own logs.

## Plutonium Identity Center permission set

Attach [`plutonium-deployer-policy.json`](plutonium-deployer-policy.json) as an
inline policy to the existing `Plutonium` permission set. It is scoped to AWS
account `391458701307`, Region `eu-central-1`, and resources used by this
service. The policy covers both first-time commands:

```bash
AWS_PROFILE=plutonium-prod AWS_REGION=eu-central-1 \
  ./infra/lookup-api/bootstrap_execution_role.sh

AWS_PROFILE=plutonium-prod AWS_REGION=eu-central-1 \
  ./infra/lookup-api/deploy.sh /path/to/catalog.json /path/to/manifest.json
```

The policy grants the exact actions required to:

- deploy the two `plutonium-catalog-lookup-*` CloudFormation stacks;
- create and manage the lookup Lambda function and HTTP API;
- create and manage the dedicated private catalog bucket;
- package Lambda code in the SAM-managed deployment bucket;
- create the dedicated Lambda execution role and pass only that role to
  Lambda;
- create and configure the service's CloudWatch log groups and API access-log
  delivery.

It does not grant access to unrelated Lambda functions, IAM roles, S3 buckets,
or CloudFormation stacks. API Gateway does not provide a resource ARN before
an HTTP API is created, so API Gateway management is limited by Region and API
resource path rather than by the generated API ID.

Organization service-control policies, permission boundaries, or session
policies can still deny an action allowed by this policy.

## Lambda runtime role

The bootstrap command deploys [`execution-role.yaml`](execution-role.yaml) and
creates `plutonium-catalog-lookup-execution-prod`. It trusts only
`lambda.amazonaws.com` and grants:

- `s3:GetObject` and `s3:GetObjectVersion` under the dedicated catalog bucket;
- `s3:GetBucketLocation` on that bucket;
- the AWS-managed `AWSLambdaBasicExecutionRole` policy for Lambda logs.

The runtime role cannot upload catalog data or create, update, or delete AWS
infrastructure. Do not attach the human deployment policy to this role.
