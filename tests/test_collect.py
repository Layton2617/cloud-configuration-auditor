import json
import subprocess
import unittest
from unittest.mock import patch

import collect
import cspm


class CollectionTests(unittest.TestCase):
    def run_collection(self, missing_code):
        calls = []

        def cli(command, **kwargs):
            calls.append(command)
            operation = tuple(command[1:3])
            responses = {
                ("sts", "get-caller-identity"): {"Account": "123456789012"},
                ("s3api", "list-buckets"): {"Buckets": [{"Name": "example"}]},
                ("ec2", "describe-security-groups"): {"SecurityGroups": []},
            }
            if operation == ("iam", "list-policies"):
                return subprocess.CompletedProcess(command, 1, "", "An error occurred (AccessDenied) when calling ListPolicies")
            if operation == ("s3api", "get-public-access-block"):
                return subprocess.CompletedProcess(command, 1, "", f"An error occurred ({missing_code}) when calling GetPublicAccessBlock")
            return subprocess.CompletedProcess(command, 0, json.dumps(responses[operation]), "")

        with patch("collect.subprocess.run", side_effect=cli):
            snapshot = collect.collect("test", "us-east-1")
        for command in calls:
            self.assertIn("--profile", command)
            self.assertIn("--region", command)
            self.assertNotIn("--no-paginate", command)
        return snapshot

    def test_absent_bucket_configuration_is_failed(self):
        snapshot = self.run_collection("NoSuchPublicAccessBlockConfiguration")
        self.assertIsNone(snapshot["s3_buckets"][0]["PublicAccessBlockConfiguration"])
        report = cspm.scan(snapshot)
        self.assertEqual(report["summary"], {"FAILED": 1})
        self.assertEqual(report["collection_errors"][0]["Code"], "AccessDenied")
        self.assertIn("AccessDenied", cspm.markdown(report))

    def test_bucket_access_denied_is_unknown(self):
        snapshot = self.run_collection("AccessDenied")
        self.assertEqual(cspm.scan(snapshot)["summary"], {"UNKNOWN": 1})


if __name__ == "__main__":
    unittest.main()
