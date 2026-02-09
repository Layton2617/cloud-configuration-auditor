"""Read AWS configurations with AWS CLI v2 and save a cspm.py snapshot."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote


class CollectionError(Exception):
    def __init__(self, message):
        super().__init__(message)
        match = re.search(r"An error occurred \(([^)]+)\)", message)
        self.detail = {"Code": match[1] if match else "CLIError", "Message": message.strip()}


def collect(profile, region):
    def aws(*arguments):
        process = subprocess.run(
            ["aws", *arguments, "--profile", profile, "--region", region,
             "--output", "json", "--no-cli-pager", "--no-cli-auto-prompt"],
            capture_output=True, text=True,
        )
        if process.returncode:
            raise CollectionError(process.stderr)
        return json.loads(process.stdout)

    identity = aws("sts", "get-caller-identity")
    snapshot = {
        "source": f"AWS read-only collection: account {identity['Account']}, region {region}",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "identity": identity, "region": region,
        "scope": "IAM customer-managed permissions policies (global), general-purpose S3 buckets and security groups in the selected region. No inline policies, AWS-managed policies, or other regions.",
        "collection_errors": [], "iam_policies": [], "s3_buckets": [], "security_groups": [],
    }

    def inventory(service, operation, key, *arguments):
        try:
            return aws(service, operation, *arguments)[key]
        except CollectionError as error:
            snapshot["collection_errors"].append({"operation": f"{service}:{operation}", **error.detail})
            return []

    policies = inventory("iam", "list-policies", "Policies", "--scope", "Local",
                         "--policy-usage-filter", "PermissionsPolicy")
    for policy in policies:
        entry = {"Arn": policy["Arn"], "DefaultVersionId": policy["DefaultVersionId"]}
        try:
            version = aws("iam", "get-policy-version", "--policy-arn", policy["Arn"],
                          "--version-id", policy["DefaultVersionId"])["PolicyVersion"]
            document = version["Document"]
            entry["PolicyDocument"] = json.loads(unquote(document)) if isinstance(document, str) else document
        except CollectionError as error:
            entry["CollectionError"] = error.detail
        snapshot["iam_policies"].append(entry)

    buckets = inventory("s3api", "list-buckets", "Buckets", "--bucket-region", region,
                        "--page-size", "1000")
    for bucket in buckets:
        entry = {"Name": bucket["Name"]}
        try:
            entry.update(aws("s3api", "get-public-access-block", "--bucket", bucket["Name"],
                             "--expected-bucket-owner", identity["Account"]))
        except CollectionError as error:
            if error.detail["Code"] == "NoSuchPublicAccessBlockConfiguration":
                entry["PublicAccessBlockConfiguration"] = None
            else:
                entry["CollectionError"] = error.detail
        snapshot["s3_buckets"].append(entry)

    snapshot["security_groups"] = inventory("ec2", "describe-security-groups", "SecurityGroups")
    return snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshot = collect(args.profile, args.region)
    args.output.write_text(json.dumps(snapshot, indent=2) + "\n")
    print(json.dumps({"resources": {key: len(snapshot[key]) for key in
                      ("iam_policies", "s3_buckets", "security_groups")},
                      "collection_errors": snapshot["collection_errors"]}, indent=2))
    if snapshot["collection_errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
