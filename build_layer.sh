#!/usr/bin/env bash
# Build the Strands Agents Lambda layer on CodeBuild (arm64, Python 3.12). No local Docker needed.
set -euo pipefail
: "${AWS_REGION:=us-east-1}"; export AWS_REGION  # credentials: standard AWS chain (e.g. AWS_PROFILE)
id=$(aws codebuild start-build --project-name ith-strands-layer --query build.id --output text)
echo "build $id"
while s=$(aws codebuild batch-get-builds --ids "$id" --query 'builds[0].buildStatus' --output text); [ "$s" = IN_PROGRESS ]; do sleep 15; done
echo "status $s"; [ "$s" = SUCCEEDED ]
