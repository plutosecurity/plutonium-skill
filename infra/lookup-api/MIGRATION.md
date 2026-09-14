# Migration runbook

Follow this order so existing Skill installations fail closed rather than receiving unverified data.

1. Have an administrator create the Lambda execution role from `iam/execution-role.yaml`.
2. Obtain the scoped deployment permissions documented in `iam/README.md`.
3. Install AWS CLI and AWS SAM CLI locally and authenticate to the production AWS account in `eu-central-1`.
4. Check out or generate the newest catalog release, confirm its manifest has not expired, and run `deploy.sh` with its `release/catalog.json` and `release/manifest.json` paths. The publisher rejects expired releases.
5. Verify `/v1/health`, one exact match, one ambiguous match, one no-match query, one detailed lookup, and visible throttling under a short controlled burst.
6. Run the full test suite and `python3 tools/package_skill.py --release`.
7. Update the README installation version and checksum, publish the v0.2.0 Skill release, and test a clean installation from the release asset.
8. Watch API Gateway 4xx/5xx, Lambda errors/throttles/duration, and S3 access for at least one normal validation window.
9. Make `plutonium-catalog-data` private or remove it, including its public release assets. Confirm unauthenticated Git and release downloads no longer work.
10. Re-test the v0.2.0 Skill. Older Skill versions will fail closed and must be upgraded.

Previously downloaded copies of the public catalog cannot be revoked. This migration prevents new one-request downloads from the Pluto-controlled repository; it does not make information already shown on the public Plutonium website confidential.

## Rollback

If the API fails before the public repository is removed, restore the previous Skill release while investigating. If it fails after removal, keep the public repository private, restore the last known-good immutable S3 release by repointing `current.json`, or roll back the Lambda stack. Do not republish the bulk catalog as a shortcut.
