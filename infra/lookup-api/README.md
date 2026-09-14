# Plutonium catalog lookup API

This serverless application replaces the public bulk catalog transport used by Plutonium Skill. It exposes only two routes:

- `POST /v1/lookup` accepts `{"query":"Trello","details":false}` and returns one bounded result, ambiguity candidates, or suggestions.
- `GET /v1/health` is a shallow health check.

There is deliberately no list, export, pagination, or raw-record route.

## Architecture

```text
Public Skill helper
        |
        | one HTTPS POST per user lookup
        v
API Gateway HTTP API
  stage throttling: 2 requests/second, burst 5
        |
        v
Lambda (reserved concurrency: 5)
        |
        | GetObject using one least-privilege execution role
        v
Private versioned S3 bucket
  current.json -> releases/<sha256>/catalog.json
```

The stage throttle is a service-wide safety limit, not authentication and not a secrecy boundary. A determined caller can still collect public assessment data over time. The design removes the one-request bulk download and makes automated collection slower and observable.

Catalog pointers older than 45 days fail closed so a forgotten deployment cannot silently present an indefinitely stale assessment.

## Before the first deployment

An AWS administrator runs [`bootstrap_execution_role.sh`](bootstrap_execution_role.sh) once in `eu-central-1`, or creates an equivalent role named `plutonium-catalog-lookup-execution-prod` from [`iam/execution-role.yaml`](iam/execution-role.yaml). The role can read only objects in the dedicated bucket prefix and write Lambda logs.

The deployment identity needs permission to manage the scoped Lambda, HTTP API, S3 bucket and log groups, to pass that execution role, and to deploy the CloudFormation stack. `sam deploy --resolve-s3` also needs access to its SAM artifact bucket.

## Deploy and publish

Requirements: AWS CLI, AWS SAM CLI, Python 3.9+, and an authenticated AWS session.

From the repository root:

```bash
AWS_PROFILE=YOUR_PROFILE AWS_REGION=eu-central-1 \
  ./infra/lookup-api/bootstrap_execution_role.sh

AWS_PROFILE=YOUR_PROFILE AWS_REGION=eu-central-1 \
  ./infra/lookup-api/deploy.sh \
  ../plutonium-catalog-data/release/catalog.json \
  ../plutonium-catalog-data/release/manifest.json
```

The scripts refuse to deploy outside AWS account `391458701307` and `eu-central-1` by default. Override the account guard only for an intentional alternate account by setting `PLUTONIUM_AWS_ACCOUNT_ID`. `deploy.sh` requires explicit catalog and manifest paths, validates them before changing infrastructure, validates and deploys the stack, publishes the immutable catalog object, atomically updates `current.json`, reads the generated API endpoint, and writes that endpoint into the Skill's `references/api.json`. The catalog files are deployment inputs and must not be committed to this public repository.

For a catalog-only update after the stack exists:

```bash
python3 infra/lookup-api/scripts/publish_catalog.py \
  --region eu-central-1 \
  --bucket YOUR_STACK_CATALOG_BUCKET_OUTPUT \
  --catalog ../plutonium-catalog-data/release/catalog.json \
  --manifest ../plutonium-catalog-data/release/manifest.json
```

## Verify before removing public data

```bash
python3 -m unittest discover -s infra/lookup-api/tests -v
python3 -m unittest discover -s tests -v
python3 tools/package_skill.py
curl -fsS "YOUR_API_BASE/v1/health"
python3 skills/plutonium-skill/scripts/plutonium_lookup.py -- "Claude Trello connector"
```

Publish the new Skill release and verify the installed release against the live API before making `plutonium-catalog-data` private or deleting it. Removing the bulk repository is an explicit final migration step; this deployment never deletes GitHub data.

Use the ordered checklist in [`MIGRATION.md`](MIGRATION.md) for production rollout and rollback.
