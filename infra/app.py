#!/usr/bin/env python3
import os

import aws_cdk as cdk

from stack import BuildStack, InsideTheHouseStack

# Account comes from your current AWS credentials (set by the CDK CLI); nothing is hard-coded.
ACCOUNT = os.environ["CDK_DEFAULT_ACCOUNT"]
REGION = os.environ.get("CDK_DEFAULT_REGION", "us-east-1")
SUFFIX = f"ith-{ACCOUNT}"

app = cdk.App()
env = cdk.Environment(account=ACCOUNT, region=REGION)
build = BuildStack(app, "ith-build", suffix=SUFFIX, env=env)
InsideTheHouseStack(app, "ith-main", suffix=SUFFIX, artifacts_bucket=f"build-{SUFFIX}", env=env)
cdk.Tags.of(app).add("project", "inside-the-house")
app.synth()
