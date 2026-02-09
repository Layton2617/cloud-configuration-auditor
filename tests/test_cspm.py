from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import unittest

import cspm


ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / 'fixtures/cases.json').read_text())
EXAMPLE = json.loads((ROOT / 'fixtures/example.json').read_text())


class CSPMTests(unittest.TestCase):
    def test_labeled_cases(self):
        for case in CASES:
            with self.subTest(case=case['id']):
                actual = {check['control_id']: check['status'] for check in cspm.scan(case['snapshot'])['checks']}
                self.assertEqual(actual, case['expected'])

    def test_repair_changes_only_selected_bucket(self):
        snapshot = deepcopy(EXAMPLE)
        snapshot['s3_buckets'].append({'Name': 'untouched', 'PublicAccessBlockConfiguration': None})
        original = deepcopy(snapshot)
        updated = cspm.simulate_s3(snapshot, 'cspm-demo-bucket')
        self.assertEqual(snapshot, original)
        self.assertEqual(updated['iam_policies'], snapshot['iam_policies'])
        self.assertEqual(updated['security_groups'], snapshot['security_groups'])
        self.assertEqual(updated['s3_buckets'][1], snapshot['s3_buckets'][1])
        self.assertEqual(cspm.check_bucket(updated['s3_buckets'][0])['status'], 'PASSED')

    def test_repair_is_idempotent(self):
        once = cspm.simulate_s3(EXAMPLE, 'cspm-demo-bucket')
        self.assertEqual(once, cspm.simulate_s3(once, 'cspm-demo-bucket'))
        self.assertFalse(cspm.plan_s3(once, 'cspm-demo-bucket')['change_required'])

    def test_unknown_configuration_cannot_be_repaired(self):
        snapshot = deepcopy(EXAMPLE)
        snapshot['s3_buckets'][0] = {'Name': 'cspm-demo-bucket', 'CollectionError': {'Code': 'AccessDenied'}}
        with self.assertRaisesRegex(ValueError, 'unknown'):
            cspm.simulate_s3(snapshot, 'cspm-demo-bucket')

    def test_string_false_is_not_silently_passed(self):
        bucket = deepcopy(EXAMPLE['s3_buckets'][0])
        bucket['PublicAccessBlockConfiguration']['BlockPublicPolicy'] = 'false'
        with self.assertRaises(ValueError):
            cspm.check_bucket(bucket)

    def test_known_failure_takes_precedence_over_unresolved_source(self):
        group = deepcopy(EXAMPLE['security_groups'][0])
        group['IpPermissions'][0]['PrefixListIds'] = [{'PrefixListId': 'pl-example'}]
        self.assertEqual(cspm.check_group(group, 22)['status'], 'FAILED')

    def test_cli_scan_and_repair(self):
        scan = subprocess.run([sys.executable, str(ROOT / 'cspm.py'), 'scan', str(ROOT / 'fixtures/example.json')], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(scan.stdout)['summary'], {'FAILED': 3, 'PASSED': 1})
        repair = subprocess.run([sys.executable, str(ROOT / 'cspm.py'), 'simulate-s3', str(ROOT / 'fixtures/example.json'), '--bucket', 'cspm-demo-bucket'], capture_output=True, text=True, check=True)
        self.assertEqual(cspm.scan(json.loads(repair.stdout))['summary'], {'FAILED': 2, 'PASSED': 2})

    def test_gcp_and_aws_resources_scan_together(self):
        snapshot = deepcopy(EXAMPLE)
        snapshot['gcp_firewall_rules'] = json.loads((ROOT / 'fixtures/gcp-example.json').read_text())['gcp_firewall_rules']
        report = cspm.scan(snapshot)
        self.assertEqual(report['summary'], {'FAILED': 4, 'PASSED': 4})
        failed = {(c['control_id'], c['resource']) for c in report['checks'] if c['status'] == 'FAILED'}
        self.assertIn(('GCP.FW.1', 'allow-ssh-from-anywhere'), failed)

    def test_evaluation_reports_mismatches(self):
        case = deepcopy(CASES[0])
        case['expected']['IAM.1'] = 'PASSED'
        self.assertEqual(cspm.evaluate([case])['matched'], 0)


if __name__ == '__main__':
    unittest.main()
