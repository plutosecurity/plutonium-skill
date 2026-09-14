#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$script_dir/../.." && pwd)"
region="${AWS_REGION:-eu-central-1}"
environment="${PLUTONIUM_ENVIRONMENT:-prod}"
expected_account_id="${PLUTONIUM_AWS_ACCOUNT_ID:-391458701307}"
stack_name="plutonium-catalog-lookup-${environment}"
role_name="plutonium-catalog-lookup-execution-${environment}"

cd "$repo_dir"

if [[ "$#" -ne 2 ]]; then
  echo "Usage: $0 /path/to/catalog.json /path/to/manifest.json" >&2
  exit 2
fi
catalog_path="$1"
manifest_path="$2"

command -v sam >/dev/null || { echo "AWS SAM CLI is required" >&2; exit 1; }
command -v aws >/dev/null || { echo "AWS CLI is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "Python 3 is required" >&2; exit 1; }
test -f "$catalog_path" || { echo "Catalog not found: $catalog_path" >&2; exit 1; }
test -f "$manifest_path" || { echo "Manifest not found: $manifest_path" >&2; exit 1; }
[[ "$region" == "eu-central-1" ]] || {
  echo "Refusing deployment outside eu-central-1: $region" >&2
  exit 1
}
[[ "$environment" == "dev" || "$environment" == "prod" ]] || {
  echo "PLUTONIUM_ENVIRONMENT must be dev or prod" >&2
  exit 1
}
[[ "$expected_account_id" =~ ^[0-9]{12}$ ]] || {
  echo "PLUTONIUM_AWS_ACCOUNT_ID must be a 12-digit AWS account ID" >&2
  exit 1
}

# Reject stale or malformed input before making any AWS infrastructure changes.
python3 "$script_dir/scripts/publish_catalog.py" \
  --region "$region" \
  --bucket preflight-only \
  --catalog "$catalog_path" \
  --manifest "$manifest_path" \
  --dry-run >/dev/null

actual_account_id="$(aws --region "$region" sts get-caller-identity \
  --query Account --output text)"
[[ "$actual_account_id" == "$expected_account_id" ]] || {
  echo "Refusing deployment to AWS account $actual_account_id; expected $expected_account_id" >&2
  exit 1
}

aws --region "$region" iam get-role --role-name "$role_name" >/dev/null || {
  echo "Execution role $role_name does not exist. Run bootstrap_execution_role.sh first." >&2
  exit 1
}

export SAM_CLI_TELEMETRY=0

sam validate --lint --template-file "$script_dir/template.yaml"
sam build --template-file "$script_dir/template.yaml"
sam deploy \
  --stack-name "$stack_name" \
  --region "$region" \
  --resolve-s3 \
  --no-confirm-changeset \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "Environment=$environment" \
    "ExecutionRoleName=$role_name"

bucket_name="$(aws --region "$region" cloudformation describe-stacks \
  --stack-name "$stack_name" \
  --query "Stacks[0].Outputs[?OutputKey=='CatalogBucketName'].OutputValue | [0]" \
  --output text)"
lookup_endpoint="$(aws --region "$region" cloudformation describe-stacks \
  --stack-name "$stack_name" \
  --query "Stacks[0].Outputs[?OutputKey=='LookupEndpoint'].OutputValue | [0]" \
  --output text)"

[[ -n "$bucket_name" && "$bucket_name" != "None" ]] || {
  echo "CloudFormation did not return CatalogBucketName" >&2
  exit 1
}
[[ -n "$lookup_endpoint" && "$lookup_endpoint" != "None" ]] || {
  echo "CloudFormation did not return LookupEndpoint" >&2
  exit 1
}

python3 "$script_dir/scripts/publish_catalog.py" \
  --region "$region" \
  --bucket "$bucket_name" \
  --catalog "$catalog_path" \
  --manifest "$manifest_path"

python3 "$repo_dir/tools/configure_api.py" --endpoint "$lookup_endpoint"

echo "Lookup endpoint: $lookup_endpoint"
echo "Private catalog bucket: $bucket_name"
echo "Skill endpoint configured. Run the tests and package the v0.2.0 release."
