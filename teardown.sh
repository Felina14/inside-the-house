#!/usr/bin/env bash
# Mandatory last step. Assumes `python -m harness.collect` has already exported the needed log records to results/.
set -euo pipefail
: "${AWS_REGION:=us-east-1}"; export AWS_REGION  # credentials: standard AWS chain (e.g. AWS_PROFILE)
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
SUFFIX="ith-$ACCOUNT"
cd "$(dirname "$0")"

echo "== remove network defences"
.venv/bin/python -m harness.defences reset || true
.venv/bin/python -m harness.defences scoped-iam-off || true

empty_bucket() {  # deletes every object version and delete marker
  local b=$1
  aws s3api head-bucket --bucket "$b" 2>/dev/null || return 0
  echo "== empty $b"
  .venv/bin/python - "$b" <<'PY'
import sys, boto3
b = boto3.Session().resource("s3").Bucket(sys.argv[1])
b.object_versions.delete()
b.objects.all().delete()
PY
}
for b in docs reports stranger build; do empty_bucket "$b-$SUFFIX"; done

echo "== cdk destroy"
(cd infra && JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1 npx -y aws-cdk@latest destroy ith-main ith-build --force)

echo "== log groups created outside the stacks"
for g in /aws/codebuild/ith-strands-layer /aws/lambda/ith-agent /ith/vpc-flow-logs /ith/resolver-query-logs; do
  aws logs delete-log-group --log-group-name "$g" 2>/dev/null && echo "deleted $g" || true
done

echo "== CDK bootstrap (created for this project, tagged)"
BOOT="cdk-hnb659fds-assets-$ACCOUNT-$AWS_REGION"
empty_bucket "$BOOT"
aws cloudformation delete-stack --stack-name CDKToolkit
aws cloudformation wait stack-delete-complete --stack-name CDKToolkit
aws s3api delete-bucket --bucket "$BOOT" 2>/dev/null || true
aws ecr delete-repository --repository-name "cdk-hnb659fds-container-assets-$ACCOUNT-$AWS_REGION" --force 2>/dev/null || true

echo "== remaining resources tagged project=inside-the-house"
aws resourcegroupstaggingapi get-resources --tag-filters Key=project,Values=inside-the-house \
  --query 'ResourceTagMappingList[].ResourceARN' --output json
