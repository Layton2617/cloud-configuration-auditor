from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'config_rule')]

import lambda_function


EVENTS = ROOT / 'config_rule/events'


class FakeConfig:
    def __init__(self, history=None):
        self.calls = []
        self.history = history

    def put_evaluations(self, **kwargs):
        self.calls.append(kwargs)

    def get_resource_config_history(self, **kwargs):
        return {'configurationItems': [self.history]}


def load(name, port=None, mutate=None):
    event = json.loads((EVENTS / name).read_text())
    if port:
        event['ruleParameters'] = json.dumps({'port': port})
    if mutate:
        invoking = json.loads(event['invokingEvent'])
        mutate(invoking['configurationItem']['configuration'])
        event['invokingEvent'] = json.dumps(invoking)
    return event


def run(event, client=None):
    client = client or FakeConfig()
    lambda_function.lambda_handler(event, None, client)
    [call] = client.calls
    [evaluation] = call['Evaluations']
    return call['ResultToken'], evaluation


class ConfigRuleTests(unittest.TestCase):
    def test_world_open_ssh_is_non_compliant(self):
        token, evaluation = run(load('open-ssh.json'))
        self.assertEqual(token, 'example-result-token')
        self.assertEqual(evaluation['ComplianceType'], 'NON_COMPLIANT')
        self.assertEqual(evaluation['ComplianceResourceId'], 'sg-0open22')
        self.assertEqual(evaluation['OrderingTimestamp'], '2026-10-01T12:00:00.000Z')
        self.assertTrue(evaluation['Annotation'].startswith('EC2.13 FAILED'))

    def test_restricted_ssh_is_compliant(self):
        self.assertEqual(run(load('restricted-ssh.json'))[1]['ComplianceType'], 'COMPLIANT')

    def test_deleted_resource_is_not_applicable(self):
        self.assertEqual(run(load('deleted.json'))[1]['ComplianceType'], 'NOT_APPLICABLE')

    def test_port_parameter_selects_rdp(self):
        _, evaluation = run(load('open-ssh.json', port='3389'))
        self.assertEqual(evaluation['ComplianceType'], 'COMPLIANT')
        self.assertTrue(evaluation['Annotation'].startswith('EC2.14 PASSED'))

    def test_legacy_ip_ranges_strings(self):
        def legacy(configuration):
            del configuration['ipPermissions'][0]['ipv4Ranges']
        self.assertEqual(run(load('open-ssh.json', mutate=legacy))[1]['ComplianceType'], 'NON_COMPLIANT')

    def test_prefix_list_is_flagged_unverified(self):
        def prefix_list(configuration):
            rule = configuration['ipPermissions'][0]
            rule['ipv4Ranges'], rule['ipRanges'] = [], []
            rule['prefixListIds'] = [{'prefixListId': 'pl-0abc'}]
        _, evaluation = run(load('restricted-ssh.json', mutate=prefix_list))
        self.assertEqual(evaluation['ComplianceType'], 'NON_COMPLIANT')
        self.assertIn('UNVERIFIED', evaluation['Annotation'])
        self.assertLessEqual(len(evaluation['Annotation']), 256)

    def test_oversized_item_is_fetched_from_history(self):
        item = json.loads(load('open-ssh.json')['invokingEvent'])['configurationItem']
        summary = {k: v for k, v in item.items() if k != 'configuration'}
        history = {**summary, 'configuration': json.dumps(item['configuration']),
                   'configurationItemCaptureTime': datetime(2026, 10, 1, 12, tzinfo=timezone.utc)}
        event = load('open-ssh.json')
        event['invokingEvent'] = json.dumps({'configurationItemSummary': summary,
                                             'messageType': 'OversizedConfigurationItemChangeNotification'})
        self.assertEqual(run(event, FakeConfig(history))[1]['ComplianceType'], 'NON_COMPLIANT')

    def test_scheduled_notification_is_ignored(self):
        client = FakeConfig()
        event = load('open-ssh.json')
        event['invokingEvent'] = json.dumps({'messageType': 'ScheduledNotification'})
        lambda_function.lambda_handler(event, None, client)
        self.assertEqual(client.calls, [])


if __name__ == '__main__':
    unittest.main()
