import json
from pathlib import Path

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_bedrock as bedrock
from aws_cdk import aws_codebuild as codebuild
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_route53resolver as r53r
from aws_cdk import aws_s3 as s3
from constructs import Construct

ROOT = Path(__file__).resolve().parent.parent
STRANDS_VERSION = "1.62.0"


def _bucket(scope, cid, name, versioned=False):
    return s3.Bucket(
        scope, cid, bucket_name=name, versioned=versioned,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        enforce_ssl=True, removal_policy=RemovalPolicy.DESTROY,
    )


class BuildStack(Stack):
    """CodeBuild project that builds the Strands Agents Lambda layer (arm64, Python 3.12). No local Docker."""

    def __init__(self, scope: Construct, cid: str, suffix: str, **kw):
        super().__init__(scope, cid, **kw)
        self.artifacts = _bucket(self, "Artifacts", f"build-{suffix}")
        project = codebuild.Project(
            self, "LayerBuild", project_name="ith-strands-layer",
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxArmBuildImage.AMAZON_LINUX_2023_STANDARD_3_0,
                compute_type=codebuild.ComputeType.SMALL,
            ),
            build_spec=codebuild.BuildSpec.from_object({
                "version": "0.2",
                "phases": {
                    "install": {"runtime-versions": {"python": "3.12"}},
                    "build": {"commands": [
                        f"pip install --no-cache-dir strands-agents=={STRANDS_VERSION} -t python/",
                        "find python -name '__pycache__' -type d -prune -exec rm -rf {} +",
                        "zip -qr layer.zip python",
                        f"aws s3 cp layer.zip s3://{self.artifacts.bucket_name}/layers/strands-{STRANDS_VERSION}.zip",
                    ]},
                },
            }),
            timeout=Duration.minutes(15),
        )
        self.artifacts.grant_put(project)
        CfnOutput(self, "ArtifactsBucket", value=self.artifacts.bucket_name)
        CfnOutput(self, "ProjectName", value=project.project_name)
        CfnOutput(self, "LayerKey", value=f"layers/strands-{STRANDS_VERSION}.zip")


class InsideTheHouseStack(Stack):
    def __init__(self, scope: Construct, cid: str, suffix: str, artifacts_bucket: str, **kw):
        super().__init__(scope, cid, **kw)

        # --- Network: one isolated subnet, no IGW, no NAT -------------------------------------------
        vpc = ec2.Vpc(
            self, "Vpc", ip_addresses=ec2.IpAddresses.cidr("10.40.0.0/24"), max_azs=1, nat_gateways=0,
            subnet_configuration=[ec2.SubnetConfiguration(
                name="isolated", subnet_type=ec2.SubnetType.PRIVATE_ISOLATED, cidr_mask=26)],
            restrict_default_security_group=False,
        )
        for svc in ("BEDROCK_RUNTIME", "STS", "CLOUDWATCH_LOGS"):
            vpc.add_interface_endpoint(svc, service=getattr(ec2.InterfaceVpcEndpointAwsService, svc))
        # Default policy (full access) at deploy time; the scoped policy is a defence applied later.
        s3_endpoint = vpc.add_gateway_endpoint("S3", service=ec2.GatewayVpcEndpointAwsService.S3)

        # --- Logging -------------------------------------------------------------------------------
        flow_group = logs.LogGroup(self, "FlowLogs", log_group_name="/ith/vpc-flow-logs",
                                   retention=logs.RetentionDays.ONE_WEEK, removal_policy=RemovalPolicy.DESTROY)
        ec2.FlowLog(
            self, "VpcFlowLog", resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(flow_group),
            traffic_type=ec2.FlowLogTrafficType.ALL,
            max_aggregation_interval=ec2.FlowLogMaxAggregationInterval.ONE_MINUTE,
        )
        query_group = logs.LogGroup(self, "ResolverQueryLogs", log_group_name="/ith/resolver-query-logs",
                                    retention=logs.RetentionDays.ONE_WEEK, removal_policy=RemovalPolicy.DESTROY)
        logs.CfnResourcePolicy(
            self, "ResolverLogsPolicy", policy_name="ith-resolver-query-logs",
            policy_document=json.dumps({"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": f"{query_group.log_group_arn}",
                "Condition": {"StringEquals": {"aws:SourceAccount": self.account}},
            }]}),
        )
        qlc = r53r.CfnResolverQueryLoggingConfig(self, "QueryLogConfig", name="ith-query-logs",
                                                 destination_arn=query_group.log_group_arn)
        r53r.CfnResolverQueryLoggingConfigAssociation(self, "QueryLogAssoc",
                                                      resolver_query_log_config_id=qlc.attr_id, resource_id=vpc.vpc_id)

        # --- DNS Firewall: rule group created, NOT associated (harness associates it as a defence) --
        allow = json.loads((ROOT / "infra" / "allowlist.json").read_text())
        allow_list = r53r.CfnFirewallDomainList(self, "AllowList", name="ith-allow", domains=allow)
        block_list = r53r.CfnFirewallDomainList(self, "BlockAll", name="ith-block-all", domains=["*"])
        rule_group = r53r.CfnFirewallRuleGroup(
            self, "FirewallRules", name="ith-egress",
            firewall_rules=[
                r53r.CfnFirewallRuleGroup.FirewallRuleProperty(
                    firewall_domain_list_id=allow_list.attr_id, priority=1, action="ALLOW",
                    # S3 bucket names resolve via a CNAME chain (s3-1-w..., s3-w.us-east-1...). The default
                    # INSPECT_REDIRECTION_DOMAIN checks every hop against the rules, so the BLOCK * rule would
                    # stop an allowed bucket. Trust redirects from allowed names only.
                    firewall_domain_redirection_action="TRUST_REDIRECTION_DOMAIN"),
                r53r.CfnFirewallRuleGroup.FirewallRuleProperty(
                    firewall_domain_list_id=block_list.attr_id, priority=2, action="BLOCK", block_response="NODATA"),
            ],
        )

        # --- Buckets -------------------------------------------------------------------------------
        docs = _bucket(self, "Docs", f"docs-{suffix}")
        reports = _bucket(self, "Reports", f"reports-{suffix}")
        # Versioned so a later run writing the same key can't overwrite an earlier run's evidence.
        stranger = _bucket(self, "Stranger", f"stranger-{suffix}", versioned=True)

        # --- Guardrail: prompt-attack HIGH, attached only for the guardrails defence ---------------
        guardrail = bedrock.CfnGuardrail(
            self, "Guardrail", name="ith-prompt-attack",
            blocked_input_messaging="This content was blocked by a guardrail (prompt attack).",
            blocked_outputs_messaging="This response was blocked by a guardrail.",
            content_policy_config=bedrock.CfnGuardrail.ContentPolicyConfigProperty(filters_config=[
                bedrock.CfnGuardrail.ContentFilterConfigProperty(
                    type="PROMPT_ATTACK", input_strength="HIGH", output_strength="NONE")]),
        )
        guardrail_version = bedrock.CfnGuardrailVersion(self, "GuardrailV1",
                                                        guardrail_identifier=guardrail.attr_guardrail_id)

        # --- Agent Lambda --------------------------------------------------------------------------
        role = iam.Role(self, "AgentRole", assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                        managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                            "service-role/AWSLambdaVPCAccessExecutionRole")])
        role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
            resources=[f"arn:aws:bedrock:{self.region}:{self.account}:inference-profile/us.amazon.nova-*",
                       "arn:aws:bedrock:*::foundation-model/amazon.nova-*"]))
        role.add_to_policy(iam.PolicyStatement(actions=["bedrock:ApplyGuardrail"],
                                               resources=[guardrail.attr_guardrail_arn]))
        docs.grant_read(role)
        # DELIBERATELY over-broad, mirroring a common real-world role. This identity-layer mistake is
        # what makes the S3 exit possible. See README "The role".
        role.add_to_policy(iam.PolicyStatement(actions=["s3:PutObject"], resources=["arn:aws:s3:::*/*"]))

        layer = lambda_.LayerVersion(
            self, "StrandsLayer",
            code=lambda_.Code.from_bucket(s3.Bucket.from_bucket_name(self, "ArtifactsRef", artifacts_bucket),
                                          f"layers/strands-{STRANDS_VERSION}.zip"),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_12],
            compatible_architectures=[lambda_.Architecture.ARM_64],
        )
        fn = lambda_.Function(
            self, "Agent", function_name="ith-agent",
            runtime=lambda_.Runtime.PYTHON_3_12, architecture=lambda_.Architecture.ARM_64,
            handler="handler.handler", code=lambda_.Code.from_asset(str(ROOT / "agent")),
            layers=[layer], role=role, memory_size=1024, timeout=Duration.seconds(240),
            vpc=vpc, vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
            environment={
                "DOCS_BUCKET": docs.bucket_name, "REPORTS_BUCKET": reports.bucket_name,
                "GUARDRAIL_ID": guardrail.attr_guardrail_id, "GUARDRAIL_VERSION": guardrail_version.attr_version,
            },
        )
        logs.LogGroup(self, "AgentLogs", log_group_name=f"/aws/lambda/{fn.function_name}",
                      retention=logs.RetentionDays.ONE_WEEK, removal_policy=RemovalPolicy.DESTROY)

        for k, v in {
            "VpcId": vpc.vpc_id, "VpcCidr": vpc.vpc_cidr_block, "S3EndpointId": s3_endpoint.vpc_endpoint_id,
            "FirewallRuleGroupId": rule_group.attr_id, "AllowListId": allow_list.attr_id,
            "DocsBucket": docs.bucket_name, "ReportsBucket": reports.bucket_name,
            "StrangerBucket": stranger.bucket_name, "FunctionName": fn.function_name,
            "RoleName": role.role_name, "GuardrailId": guardrail.attr_guardrail_id,
            "GuardrailVersion": guardrail_version.attr_version,
            "FlowLogGroup": flow_group.log_group_name, "QueryLogGroup": query_group.log_group_name,
        }.items():
            CfnOutput(self, k, value=v)
