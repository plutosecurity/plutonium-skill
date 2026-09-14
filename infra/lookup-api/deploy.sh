#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$script_dir/../.." && pwd)"
region="${AWS_REGION:-eu-central-1}"
environment="${PLUTONIUM_ENVIRONMENT:-prod}"
stack_name="plutonium-catalog-lookup-${environment}"
role_name="plutonium-catalog-lookup-execution-${environment}"
catalog_path="${1:-$repo_dir/../plutonium-catalog-data/release/catalog.json}"
manifest_path="${2:-$repo_dir/../plutonium-catalog-data/release/manifest.json}"

cd "$repo_dir"

command -v sam >/dev/null || { echo "AWS SAM CLI is required" >&2; exit 1; }
command -v aws >/dev/null || { echo "AWS CLI is required" >&2; exit 1; }
test -f "$catalog_path" || { echo "Catalog not found: $catalog_path" >&2; exit 1; }
test -f "$manifest_path" || { echo "Manifest not found: $manifest_path" >&2; exit 1; }

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

python3 "$script_dir/scripts/publish_catalog.py" \
  --region "$region" \
  --bucket "$bucket_name" \
  --catalog "$catalog_path" \
  --manifest "$manifest_path"

python3 "$repo_dir/tools/configure_api.py" --endpoint "$lookup_endpoint"

echo "Lookup endpoint: $lookup_endpoint"
echo "Private catalog bucket: $bucket_name"
echo "Skill endpoint configured. Run the tests and package the v0.2.0 release."
