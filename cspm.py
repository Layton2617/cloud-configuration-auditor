"""Evaluate saved AWS configuration snapshots; no AWS calls or credentials."""

import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path


BPA_FLAGS = (
    "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
)
CONTROLS = {
    "IAM.1": ("High", "IAM policies should not allow full administrative privileges"),
    "S3.8": ("High", "S3 buckets should block public access at the bucket level"),
    "EC2.13": ("High", "Security groups should not allow unrestricted SSH ingress"),
    "EC2.14": ("High", "Security groups should not allow unrestricted RDP ingress"),
}


def result(control, resource, status, evidence, explanation, remediation):
    severity, title = CONTROLS[control]
    return {
        "control_id": control, "resource": resource, "status": status,
        "control_severity": severity, "title": title, "evidence": evidence,
        "explanation": explanation, "remediation": remediation,
    }


def check_policy(policy):
    arn = policy["Arn"]
    if ":iam::aws:policy/" in arn or policy.get("IsPermissionsBoundary", False):
        return result("IAM.1", arn, "NOT_APPLICABLE", {},
                      "AWS-managed policies and permission boundaries are outside this check.", "")
    if "CollectionError" in policy:
        return result("IAM.1", arn, "UNKNOWN", policy["CollectionError"],
                      "Policy collection failed; no pass or fail can be assigned.", "")
    statements = policy["PolicyDocument"]["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    matches = []
    for statement in statements:
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if statement["Effect"] == "Allow" and "*" in actions and "*" in resources:
            matches.append(statement)
    return result(
        "IAM.1", arn, "FAILED" if matches else "PASSED", {"statements": matches},
        "Checks explicit Allow Action=* Resource=* statements in a customer-managed policy. "
        "This is not an effective-permissions or privilege-escalation analysis; "
        "conditions, denies, attachments and organization policies can affect actual access.",
        "Review required operations and replace broad permissions with a reviewed policy. "
        "This tool does not generate or apply IAM policy replacements.",
    )


def check_bucket(bucket):
    name = bucket["Name"]
    if "CollectionError" in bucket:
        return result("S3.8", name, "UNKNOWN", bucket["CollectionError"],
                      "Bucket configuration collection failed; this is not a passing result.", "")
    configuration = bucket["PublicAccessBlockConfiguration"]
    missing = list(BPA_FLAGS) if configuration is None else [
        flag for flag in BPA_FLAGS if flag not in configuration
    ]
    # A null configuration means AWS explicitly reported no bucket-level configuration.
    if configuration is not None and missing:
        return result("S3.8", name, "UNKNOWN", {"missing_fields": missing},
                      "The snapshot is incomplete; collect all four flags before evaluating.", "")
    disabled = list(BPA_FLAGS) if configuration is None else [
        flag for flag in BPA_FLAGS if configuration[flag] is False
    ]
    if configuration is not None and any(type(configuration[f]) is not bool for f in BPA_FLAGS):
        raise ValueError(f"{name}: public-access-block flags must be JSON booleans")
    return result(
        "S3.8", name, "FAILED" if disabled else "PASSED",
        {"PublicAccessBlockConfiguration": configuration, "disabled_flags": disabled},
        "Checks bucket-level Block Public Access only. Missing flags do not establish "
        "public access or data exposure; account settings, policies and ACLs also matter.",
        "Review the bucket's intended use, then enable all four bucket-level flags. "
        "The repair command only changes a local snapshot.",
    )


def check_group(group, port):
    control = "EC2.13" if port == 22 else "EC2.14"
    if "CollectionError" in group:
        return result(control, group["GroupId"], "UNKNOWN", group["CollectionError"],
                      "Security-group collection failed; no pass or fail can be assigned.", "")
    matches = []
    unresolved = []
    for permission in group["IpPermissions"]:
        protocol = str(permission["IpProtocol"])
        covers_port = protocol == "-1" or (
            protocol in ("tcp", "6") and permission["FromPort"] <= port <= permission["ToPort"]
        )
        if not covers_port:
            continue
        unresolved += permission.get("PrefixListIds", [])
        sources = [entry["CidrIp"] for entry in permission.get("IpRanges", [])]
        sources += [entry["CidrIpv6"] for entry in permission.get("Ipv6Ranges", [])]
        if any(source in ("0.0.0.0/0", "::/0") for source in sources):
            matches.append(permission)
    status = "FAILED" if matches else "UNKNOWN" if unresolved else "PASSED"
    return result(
        control, group["GroupId"], status, {"rules": matches, "unresolved_prefix_lists": unresolved},
        f"Checks direct world-open TCP ingress covering port {port}, including all-protocol rules. "
        "A match alone does not prove internet reachability; routes, addresses, NACLs and "
        "resource attachments are not evaluated. Prefix lists are outside this check.",
        "Remove the world-open ingress rule or restrict it to the required source network "
        "after reviewing legitimate access requirements.",
    )


def scan(snapshot):
    checks = [check_policy(policy) for policy in snapshot["iam_policies"]]
    checks += [check_bucket(bucket) for bucket in snapshot["s3_buckets"]]
    checks += [check_group(group, port) for group in snapshot["security_groups"] for port in (22, 3389)]
    return {
        "mode": "offline_snapshot", "source": snapshot.get("source", "user-supplied snapshot"),
        "collection_errors": snapshot.get("collection_errors", []),
        "collection_scope": snapshot.get("scope", "user-supplied resources only"),
        "collected_at": snapshot.get("collected_at"),
        "summary": dict(Counter(check["status"] for check in checks)), "checks": checks,
        "scope": "Four configuration checks across supplied resources, not an account-wide security assessment. "
                 "Control IDs indicate the targeted AWS rule semantics; this tool is not Security Hub.",
    }


def plan_s3(snapshot, name):
    bucket = next(bucket for bucket in snapshot["s3_buckets"] if bucket["Name"] == name)
    check = check_bucket(bucket)
    if check["status"] == "UNKNOWN":
        raise ValueError("Cannot plan a change from an unknown bucket configuration")
    before = bucket["PublicAccessBlockConfiguration"]
    after = dict.fromkeys(BPA_FLAGS, True)
    return {
        "mode": "local_simulation_only", "resource": name, "control_id": "S3.8",
        "before": before, "after": after, "change_required": before != after,
        "impact": "Blocking public access can break intentional public access. "
                  "This command makes no AWS API calls.",
    }


def simulate_s3(snapshot, name):
    plan = plan_s3(snapshot, name)
    updated = deepcopy(snapshot)
    bucket = next(bucket for bucket in updated["s3_buckets"] if bucket["Name"] == name)
    bucket["PublicAccessBlockConfiguration"] = plan["after"].copy()
    updated["source"] = "local repair simulation; not AWS state"
    return updated


def evaluate(cases):
    outcomes = []
    for case in cases:
        actual = {check["control_id"]: check["status"] for check in scan(case["snapshot"])["checks"]}
        outcomes.append({"id": case["id"], "expected": case["expected"], "actual": actual,
                         "matched": actual == case["expected"]})
    return {"scope": "Hand-authored synthetic regression cases, not a held-out accuracy benchmark.",
            "cases": len(outcomes), "matched": sum(row["matched"] for row in outcomes),
            "outcomes": outcomes}


def markdown(report):
    lines = ["# CSPM snapshot report", "", f"Source: {report['source']}", "",
             report["scope"], "", f"Summary: `{json.dumps(report['summary'])}`", ""]
    lines += [f"Collection scope: {report['collection_scope']}", "",
              f"Collected at: {report['collected_at']}", "",
              "Inventory failures (empty inventory is not a passing result):", "",
              "```json", json.dumps(report['collection_errors'], indent=2), "```", ""]
    for check in report["checks"]:
        lines += [f"## {check['control_id']} {check['status']} {check['resource']}", "",
                  check["explanation"], "", "```json",
                  json.dumps(check["evidence"], indent=2), "```", ""]
        if check["status"] == "FAILED":
            lines += [f"Remediation: {check['remediation']}", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("snapshot", type=Path)
    scan_parser.add_argument("--format", choices=("json", "markdown"), default="json")
    for command in ("plan-s3", "simulate-s3"):
        command_parser = sub.add_parser(command)
        command_parser.add_argument("snapshot", type=Path)
        command_parser.add_argument("--bucket", required=True)
    evaluate_parser = sub.add_parser("evaluate")
    evaluate_parser.add_argument("cases", type=Path)
    args = parser.parse_args()
    if args.command == "evaluate":
        output = evaluate(json.loads(args.cases.read_text()))
    else:
        snapshot = json.loads(args.snapshot.read_text())
        if args.command == "scan":
            output = scan(snapshot)
        elif args.command == "plan-s3":
            output = plan_s3(snapshot, args.bucket)
        else:
            output = simulate_s3(snapshot, args.bucket)
    if args.command == "scan" and args.format == "markdown":
        print(markdown(output))
    else:
        print(json.dumps(output, indent=2))
    if args.command == "evaluate" and output["matched"] != output["cases"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
