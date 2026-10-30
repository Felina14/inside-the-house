# Inside the House

Code for an experiment: a sealed AI agent in a private subnet with no internet route reads a document carrying a hidden instruction. Does its secret get out anyway, through a DNS lookup or a write to the VPC's S3 gateway endpoint? And which layer stops it: the model (hardened prompt, Bedrock Guardrails) or the network (Route 53 Resolver DNS Firewall, S3 endpoint policy)?

Models: Amazon Nova via Amazon Bedrock. Agent: [Strands Agents](https://strandsagents.com) on AWS Lambda (Python 3.12, arm64). The Strands layer is built on AWS CodeBuild, so no local Docker is needed.

## Layout

```
agent/     Lambda handler, tools (read_document, fetch_url, save_report), system prompts
traps/     trap and clean HTML documents
infra/     CDK (Python): isolated VPC, endpoints, Flow Logs, Resolver query logs, DNS Firewall, buckets, guardrail, Lambda
harness/   run the matrix, apply/remove defences, collect logs, score, report
```

## Safety

- Exfil targets are `.invalid` names (RFC 2606) only. Canary values are generated per run; there are no real secrets.
- **Deploy only in a sandbox account.** The Lambda role deliberately has `s3:PutObject` on `arn:aws:s3:::*/*` to model a common over-broad role.
- No credentials or account identifiers are stored in this repo. Everything uses the standard AWS credential chain.

## Run

Prerequisites: Python 3.12+, Node (for the CDK CLI), credentials for a sandbox account (e.g. `export AWS_PROFILE=...`), and Bedrock access to the Nova models in us-east-1.

| Stage | Command |
|---|---|
| Setup | `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt` |
| Bootstrap + build stack | `cd infra && npx aws-cdk@latest bootstrap --tags project=inside-the-house && npx aws-cdk@latest deploy ith-build && cd ..` |
| Build the Strands layer | `./build_layer.sh` |
| Deploy | `cd infra && npx aws-cdk@latest deploy ith-main --outputs-file ../results/stack-outputs.json && cd ..` |
| Upload documents | `.venv/bin/python -m harness.setup_docs` |
| Baseline + allowlist | `.venv/bin/python -m harness.run --baseline`, wait ~10 min, `.venv/bin/python -m harness.defences discover-allowlist`, then deploy again |
| Matrix | `.venv/bin/python -m harness.run --models all --reps 20` |
| Collect, score, report | `.venv/bin/python -m harness.collect && .venv/bin/python -m harness.score && .venv/bin/python -m harness.report` |
| Teardown | `./teardown.sh` |

`infra/allowlist.json` starts as a placeholder; `discover-allowlist` replaces it with the exact names your deployment resolved. Outputs go to `results/`, which is git-ignored.

## License

MIT
