# CSPM snapshot report

Source: synthetic GCP demo; no real GCP resources

Configuration checks across supplied resources, not an account-wide security assessment. AWS control IDs indicate the targeted Security Hub rule semantics; GCP.FW IDs are this project's own. This tool is not Security Hub.

Summary: `{"FAILED": 1, "PASSED": 3}`

Collection scope: user-supplied resources only

Collected at: None

Inventory failures (empty inventory is not a passing result):

```json
[]
```

## GCP.FW.1 FAILED allow-ssh-from-anywhere

Standards: CIS GCP 3.6

Checks one enabled ingress rule for world-open TCP access covering port 22. Higher-priority deny rules, hierarchical and network firewall policies, and instance external IPs are not evaluated.

```json
{
  "network": "global/networks/default",
  "priority": 1000,
  "sourceRanges": [
    "0.0.0.0/0"
  ],
  "allowed": [
    {
      "IPProtocol": "tcp",
      "ports": [
        "22"
      ]
    }
  ],
  "targetTags": [
    "web"
  ]
}
```

Remediation: Restrict sourceRanges to trusted networks (for example the IAP TCP forwarding range 35.235.240.0/20) or delete the rule after reviewing legitimate access requirements.

## GCP.FW.2 PASSED allow-ssh-from-anywhere

Standards: CIS GCP 3.7

Checks one enabled ingress rule for world-open TCP access covering port 3389. Higher-priority deny rules, hierarchical and network firewall policies, and instance external IPs are not evaluated.

```json
{
  "network": "global/networks/default",
  "priority": 1000,
  "sourceRanges": [
    "0.0.0.0/0"
  ],
  "allowed": [],
  "targetTags": [
    "web"
  ]
}
```

## GCP.FW.1 PASSED allow-rdp-from-iap

Standards: CIS GCP 3.6

Checks one enabled ingress rule for world-open TCP access covering port 22. Higher-priority deny rules, hierarchical and network firewall policies, and instance external IPs are not evaluated.

```json
{
  "network": "global/networks/default",
  "priority": 1000,
  "sourceRanges": [],
  "allowed": [],
  "targetTags": []
}
```

## GCP.FW.2 PASSED allow-rdp-from-iap

Standards: CIS GCP 3.7

Checks one enabled ingress rule for world-open TCP access covering port 3389. Higher-priority deny rules, hierarchical and network firewall policies, and instance external IPs are not evaluated.

```json
{
  "network": "global/networks/default",
  "priority": 1000,
  "sourceRanges": [],
  "allowed": [],
  "targetTags": []
}
```

