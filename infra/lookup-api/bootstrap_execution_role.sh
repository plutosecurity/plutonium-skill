#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
region="${AWS_REGION:-eu-central-1}"
environment="${PLUTONIUM_ENVIRONMENT:-prod}"
expected_account_id="${PLUTONIUM_AWS_ACCOUNT_ID:-391458701307}"
stack_name="plutonium-catalog-lookup-execution-role-${environment}"

command -v aws >/dev/null || { echo "AWS CLI is required" >&2; exit 1; }
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

actual_account_id="$(aws --region "$region" sts get-caller-identity \
  --query Account --output text)"
[[ "$actual_account_id" == "$expected_account_id" ]] || {
  echo "Refusing deployment to AWS account $actual_account_id; expected $expected_account_id" >&2
  exit 1
}

aws --region "$region" cloudformation deploy \
  --template-file "$script_dir/iam/execution-role.yaml" \
  --stack-name "$stack_name" \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides "Environment=$environment" \
  --no-fail-on-empty-changeset

role_arn="$(aws --region "$region" cloudformation describe-stacks \
  --stack-name "$stack_name" \
  --query "Stacks[0].Outputs[?OutputKey=='ExecutionRoleArn'].OutputValue | [0]" \
  --output text)"
[[ -n "$role_arn" && "$role_arn" != "None" ]] || {
  echo "CloudFormation did not return ExecutionRoleArn" >&2
  exit 1
}

echo "Execution role: $role_arn"
