# Cloud configuration auditor

A local Python CLI for reviewing saved AWS (IAM, S3, security groups) and GCP (VPC firewall rules) configurations. It evaluates six checks mapped to CIS Benchmarks, preserves the configuration evidence, and simulates an S3 repair followed by a rescan. The security-group check is also packaged as an AWS Config custom rule. Python 3.10+; standard library only for the CLI.

**Current status:** offline scanner plus read-only AWS CLI v2 collection. Live collection ran in us-east-1: one security group, no regional S3 buckets, and IAM inventory denied by the current profile. Both security-group checks passed. IAM and S3 rules have not been validated on live resources. GCP checks run on supplied `gcloud` output only; no live GCP project has been scanned. No Security Hub ingestion or comparison, live remediation, or LLM component.

## Collect real configurations

Requires AWS CLI v2 on PATH and an authenticated profile. No additional Python packages.

```bash
python collect.py --profile default --region us-east-1 --output live-snapshot.json
python cspm.py scan live-snapshot.json
python cspm.py scan live-snapshot.json --format markdown
```

AWS CLI automatically paginates lists. IAM collects global customer-managed permissions policies; S3 general-purpose buckets and EC2 security groups are limited to the selected region. Inventory failures are saved in `collection_errors`; the collector exits with status 1 after saving a partial snapshot. Resource read failures become UNKNOWN. Explicitly absent S3 Block Public Access configuration becomes FAILED.

`read-only-policy.json` lists the required permissions; replace `<ACCOUNT_ID>` before use. This policy has not been attached to any user or role.

Actual account snapshots and reports (`live-*.json`, `live-*.md`) stay local and are ignored by Git. The published examples use synthetic resources. All unit tests pass, including 39 labeled regression cases (27 AWS, 12 GCP). Pagination has not been exercised against a large live inventory.

## Run the demo

Run from this folder with Python, or substitute `/opt/homebrew/bin/conda run -n dev python` on this computer.

```bash
python cspm.py scan fixtures/example.json
python cspm.py scan fixtures/example.json --format markdown
python cspm.py plan-s3 fixtures/example.json --bucket cspm-demo-bucket
python cspm.py simulate-s3 fixtures/example.json --bucket cspm-demo-bucket > repaired.json
python cspm.py scan repaired.json
python cspm.py scan fixtures/gcp-example.json --format markdown
python cspm.py evaluate fixtures/cases.json
python -m unittest discover -s tests -v
```

The demo starts with three failed checks and one passed check. The S3 simulation produces two failed and two passed checks. IAM and network findings remain open. The input file is not changed. Saved examples of these outputs are in `examples/`.

## Checks and scope

| Check | Implemented behavior | Important limit |
|---|---|---|
| IAM.1 | Finds explicit `Allow` statements containing `Action: "*"` and `Resource: "*"` in supplied customer-managed policies; supports string and list forms | No effective-permissions or privilege-escalation analysis. Conditions and denies are preserved as context, not resolved. AWS-managed policies and explicitly marked permission boundaries are excluded. Inline policies are not an input type. |
| S3.8 | Requires all four bucket-level Block Public Access flags to be true | Does not establish actual public access. Account controls, bucket policies, access points and ACLs are not evaluated. |
| EC2.13 | Finds direct world-open TCP ingress covering port 22, including port ranges and all-protocol rules | No network reachability analysis; UDP is outside this implementation's scope. |
| EC2.14 | Same check for port 3389 | Prefix-list references covering the port produce UNKNOWN unless another rule already proves a violation. |
| GCP.FW.1 | Finds enabled ingress firewall rules with `0.0.0.0/0` or `::/0` in `sourceRanges` that allow TCP or all protocols on port 22 (single ports, ranges, or no port list) | Higher-priority deny rules, hierarchical/network firewall policies and instance external IPs are not evaluated. |
| GCP.FW.2 | Same check for port 3389 | Rules that match only by `sourceTags` or service accounts are not world-open and pass. |

Each finding carries a `standards` list (for example `CIS AWS v1.2.0/4.1`, `CIS GCP 3.6`). Full per-control requirements, edge cases and remediation steps are in [`docs/controls.md`](docs/controls.md).

The AWS control IDs identify the Security Hub checks this project targets; `GCP.FW.*` IDs are this project's own. This is an educational subset, not an AWS-certified implementation or full Security Hub replacement. `PASSED` means only that this particular check did not find its targeted pattern in the supplied configuration.

## GCP firewall rules

```bash
gcloud compute firewall-rules list --project PROJECT_ID --format=json > rules.json
```

Place that list under `gcp_firewall_rules` in a snapshot (see `fixtures/gcp-example.json`). AWS and GCP resources can live in the same snapshot and are scanned together. Required permission: `compute.firewalls.list`.

## AWS Config custom rule (not deployed)

`config_rule/` packages the security-group check (EC2.13 SSH / EC2.14 RDP, selected by the `port` rule parameter) as an AWS Config custom Lambda rule. It is triggered by configuration changes, including oversized configuration items, and reports COMPLIANT / NON_COMPLIANT / NOT_APPLICABLE through `PutEvaluations`. AWS Config does not accept INSUFFICIENT_DATA from custom rules, so an unresolved prefix list is reported as NON_COMPLIANT with an "UNVERIFIED" annotation for manual review.

```bash
zip -j cspm-config-rule.zip config_rule/lambda_function.py cspm.py
aws s3 cp cspm-config-rule.zip s3://<bucket>/cspm-config-rule.zip
aws cloudformation deploy --template-file config_rule/template.yaml --stack-name cspm-config-rule \
  --parameter-overrides CodeBucket=<bucket> CodeKey=cspm-config-rule.zip --capabilities CAPABILITY_IAM
```

An AWS Config recorder must already be enabled. The rule has been tested locally against sample events in `config_rule/events/` with a fake client; it has not been deployed to an AWS account.

## Snapshot contract

The top-level JSON object has `iam_policies`, `s3_buckets`, and `security_groups` lists, plus an optional `gcp_firewall_rules` list. See `fixtures/example.json` for the full format.

- IAM entries contain `Arn` and a decoded default-version `PolicyDocument`. Set `IsPermissionsBoundary: true` when relevant. The caller must provide customer-managed policies rather than inline policy documents.
- S3 entries contain `Name` and `PublicAccessBlockConfiguration`. Use JSON `null` only when collection established that there is no bucket-level configuration. An incomplete object produces UNKNOWN; flag values must be JSON booleans.
- Security groups contain `GroupId` and AWS-shaped `IpPermissions`, with IPv4/IPv6 ranges, protocol and port intervals.
- GCP firewall rules use the `gcloud compute firewall-rules list --format=json` shape: `name`, `direction`, `disabled`, `sourceRanges`, `allowed[].IPProtocol` and `allowed[].ports`.
- A resource with a `CollectionError` object produces UNKNOWN rather than silently passing. Empty resource lists represent only the supplied snapshot, not proof of a complete account inventory.
- Each labeled regression case contains exactly one resource, with expected status keyed by control ID.

## Local verification

`fixtures/cases.json` contains 39 hand-authored synthetic cases: broad and scoped IAM statements, conditional policies, permission boundaries, inaccessible resources, each S3 flag, absent/incomplete configuration, IPv4/IPv6 ingress, port ranges, all protocols, numeric TCP, private sources and unresolved prefix lists; for GCP, port ranges, missing port lists, all protocols, IPv6, UDP, egress, disabled, deny and tag-only rules.

The tests also verify that repair changes only the chosen bucket, preserves the input, is idempotent, refuses unknown configuration, and that CLI scan and repair outputs work together. These are regression checks, not a held-out benchmark; matching all cases does not establish real-world detection accuracy.

## AWS phase still to do

1. Complete IAM read permissions and validate IAM/S3 rules against controlled test resources. Regional security-group collection has run successfully.
2. Compare representative findings with the corresponding AWS controls, accounting for this project's explicit scope differences.
3. Add a real S3 repair path with an explicit target and inspect its effect in the test account; verify state through a fresh API read. The current `simulate-s3` command does none of this.
4. Only after those checks, update the resume to describe AWS validation. Optional later work: evaluate LLM-generated finding explanations against the saved evidence.

## References

- [AWS IAM.1](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1)
- [AWS S3.8](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-8)
- [AWS EC2 controls](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html)
- [GCP VPC firewall rules](https://cloud.google.com/firewall/docs/firewalls)
