# CSPM snapshot report

Source: local repair simulation; not AWS state

Four configuration checks across supplied resources, not an account-wide security assessment. Control IDs indicate the targeted AWS rule semantics; this tool is not Security Hub.

Summary: `{"FAILED": 2, "PASSED": 2}`

Collection scope: user-supplied resources only

Collected at: None

Inventory failures (empty inventory is not a passing result):

```json
[]
```

## IAM.1 FAILED arn:aws:iam::123456789012:policy/admin-string

Checks explicit Allow Action=* Resource=* statements in a customer-managed policy. This is not an effective-permissions or privilege-escalation analysis; conditions, denies, attachments and organization policies can affect actual access.

```json
{
  "statements": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

Remediation: Review required operations and replace broad permissions with a reviewed policy. This tool does not generate or apply IAM policy replacements.

## S3.8 PASSED cspm-demo-bucket

Checks bucket-level Block Public Access only. Missing flags do not establish public access or data exposure; account settings, policies and ACLs also matter.

```json
{
  "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  },
  "disabled_flags": []
}
```

## EC2.13 FAILED sg-demo

Checks direct world-open TCP ingress covering port 22, including all-protocol rules. A match alone does not prove internet reachability; routes, addresses, NACLs and resource attachments are not evaluated. Prefix lists are outside this check.

```json
{
  "rules": [
    {
      "IpProtocol": "tcp",
      "FromPort": 22,
      "ToPort": 22,
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0"
        }
      ],
      "Ipv6Ranges": []
    }
  ],
  "unresolved_prefix_lists": []
}
```

Remediation: Remove the world-open ingress rule or restrict it to the required source network after reviewing legitimate access requirements.

## EC2.14 PASSED sg-demo

Checks direct world-open TCP ingress covering port 3389, including all-protocol rules. A match alone does not prove internet reachability; routes, addresses, NACLs and resource attachments are not evaluated. Prefix lists are outside this check.

```json
{
  "rules": [],
  "unresolved_prefix_lists": []
}
```

