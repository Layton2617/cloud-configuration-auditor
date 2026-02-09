# Control requirements

Per-control specification for the checks in `cspm.py`. Each section states what the control evaluates, the exact rule, what each status means, which regression cases in `fixtures/cases.json` cover it, and where it differs from the real AWS control.

AWS control IDs, titles, severities and standards mappings are taken from the AWS Security Hub documentation. `GCP.FW.*` IDs belong to this project; they are not Security Hub controls.

## Control index

| ID | Title | Severity | Resource type | Reference rule | Standards |
|---|---|---|---|---|---|
| IAM.1 | IAM policies should not allow full "\*" administrative privileges | High | `AWS::IAM::Policy` | Config `iam-policy-no-statements-with-admin-access` (`excludePermissionBoundaryPolicy: true`) | CIS AWS v1.2.0/1.22, v1.4.0/1.16; NIST 800-53 r5 AC-6; PCI DSS v3.2.1/7.2.1 |
| S3.8 | S3 general purpose buckets should block public access | High | `AWS::S3::Bucket` | Config `s3-bucket-level-public-access-prohibited` | CIS AWS v5.0.0/2.1.4, v3.0.0/2.1.4, v1.4.0/2.1.5; PCI DSS v4.0.1/1.4.4; NIST 800-53 r5 AC-3, SC-7 |
| EC2.13 | Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22 | High | `AWS::EC2::SecurityGroup` | Config `restricted-ssh` | CIS AWS v1.2.0/4.1; PCI DSS v4.0.1/1.3.1; NIST 800-53 r5 SC-7 |
| EC2.14 | Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 3389 | High | `AWS::EC2::SecurityGroup` | Config `restricted-common-ports` (created rule `restricted-rdp`) | CIS AWS v1.2.0/4.2; PCI DSS v4.0.1/1.3.1 |
| GCP.FW.1 | VPC firewall rules should not allow ingress from 0.0.0.0/0 or ::/0 to port 22 | High | GCP Compute firewall rule | none (project-defined) | CIS Google Cloud Platform Foundation Benchmark 3.6 |
| GCP.FW.2 | VPC firewall rules should not allow ingress from 0.0.0.0/0 or ::/0 to port 3389 | High | GCP Compute firewall rule | none (project-defined) | CIS Google Cloud Platform Foundation Benchmark 3.7 |

Note: the `title` strings emitted by `cspm.py` are shortened paraphrases of the titles above.

CIS AWS v3.0.0 and v5.0.0 no longer map to EC2.13/EC2.14. The remote-admin-port requirement moved to EC2.53 (IPv4; CIS v3.0.0/5.2, v5.0.0/5.3) and EC2.54 (IPv6; CIS v3.0.0/5.3, v5.0.0/5.4), Config rule `vpc-sg-port-restriction-check`. Those controls cover 22 and 3389 together and consider TCP, UDP and all-protocol rules. This project implements EC2.13/EC2.14 semantics only, for TCP and all-protocol rules.

CIS GCP section numbers 3.6 and 3.7 are stable across benchmark v1.3–v4.0 according to third-party mirrors. The CIS PDF was not checked.

## Shared status semantics

| Status | Meaning |
|---|---|
| `PASSED` | The targeted pattern was not found in the supplied resource. It does not mean the resource is secure. |
| `FAILED` | The targeted pattern was found. Evidence contains the matching statements, flags or rules. |
| `UNKNOWN` | The resource could not be read (`CollectionError` present), or the snapshot lacks data needed to decide. Never counted as passing. |
| `NOT_APPLICABLE` | The resource is outside the control's scope by definition (IAM.1 only). |

The rules below apply to every control:

- A resource object containing a `CollectionError` key yields `UNKNOWN`. The exception is IAM.1, where the scope exclusion is checked first.
- An inventory call failure (for example `iam:ListPolicies` denied) is recorded in top-level `collection_errors`. It produces no per-resource result. An empty resource list is not evidence of compliance.
- Evaluation is offline and per resource. No control resolves cross-resource effects such as attachments, routes, account settings or organization policies.

---

## IAM.1: IAM policies should not allow full "\*" administrative privileges

**Severity:** High · **Resource:** `AWS::IAM::Policy` (customer-managed) · **Snapshot list:** `iam_policies`

### Data required

| Field | Source |
|---|---|
| `Arn` | `iam list-policies --scope Local --policy-usage-filter PermissionsPolicy` |
| `PolicyDocument` | `iam get-policy-version --policy-arn ARN --version-id <DefaultVersionId>`. The document is URL-decoded and then JSON-parsed. |
| `IsPermissionsBoundary` (optional bool) | Supplied by the caller. The collector excludes boundary-only policies through the usage filter. |
| `CollectionError` (optional) | Set when `get-policy-version` fails |

### Evaluation

```
if Arn contains ":iam::aws:policy/" or IsPermissionsBoundary == true:
    NOT_APPLICABLE
elif CollectionError present:
    UNKNOWN
else:
    stmts = Statement if list else [Statement]
    match(s) := s.Effect == "Allow"
                and "*" in as_list(s.Action)
                and "*" in as_list(s.Resource)
    FAILED if any(match(s) for s in stmts) else PASSED
```

- `as_list` wraps a string in a one-element list.
- The wildcard must be exactly `"*"`. Service wildcards such as `s3:*` do not match.
- `Condition` is not evaluated. A conditional admin statement still fails.
- `NotAction` and `NotResource` are not evaluated.

### Edge cases

| Case | Expected | Case ID |
|---|---|---|
| Single statement object, `Action`/`Resource` as strings | FAILED | `admin-string` |
| Statement list, `"*"` among other actions | FAILED | `admin-list` |
| `Effect: Deny` with `*`/`*` | PASSED | `deny-star` |
| Specific action on `Resource: *` | PASSED | `specific-action-star-resource` |
| Service wildcard `s3:*` | PASSED | `service-wildcard` |
| Admin statement gated by `Condition` (MFA) | FAILED | `conditional-admin` |
| `IsPermissionsBoundary: true` | NOT_APPLICABLE | `permissions-boundary` |
| AWS-managed ARN (`arn:aws:iam::aws:policy/...`) | NOT_APPLICABLE | `aws-managed-out-of-scope` |
| `CollectionError` (AccessDenied) | UNKNOWN | `iam-collection-error` |

### Scope gaps vs AWS IAM.1

- Inline policies (user, group, role) are not an input type. The AWS control also checks only customer-managed policies.
- No effective-permissions analysis. Explicit denies in other statements, SCPs, permission boundaries and session policies are not combined.
- `NotAction: <x>` with `Resource: *` grants near-admin access and is not flagged.
- Only the default version is evaluated. Non-default versions can be promoted later, and the check does not see them.

### Remediation

- **Console:** IAM → Policies → *policy* → Edit. Replace `Action: "*"` with the specific actions required, then save as the new default version. Delete the old versions so that nobody can revert to them.
- **CLI:**
  ```
  aws iam create-policy-version --policy-arn ARN --policy-document file://scoped.json --set-as-default
  aws iam delete-policy-version --policy-arn ARN --version-id v<old>
  ```
- If an administrative principal is genuinely required, attach the AWS-managed `AdministratorAccess` policy to a dedicated, MFA-protected role. The AWS-managed policy is out of scope for this control.

### False positives / negatives

- **FP:** a break-glass policy that is admin by design. The finding is correct per the control; suppress it with a recorded justification. Also, a statement with a `Condition` that makes it unusable in practice.
- **FN:** `NotAction`-based grants; wide grants assembled from many service wildcards; admin access through inline policies.

---

## S3.8: S3 general purpose buckets should block public access

**Severity:** High · **Resource:** `AWS::S3::Bucket` · **Snapshot list:** `s3_buckets`

### Data required

| Field | Source |
|---|---|
| `Name` | `s3api list-buckets --bucket-region REGION` |
| `PublicAccessBlockConfiguration` | `s3api get-public-access-block --bucket NAME --expected-bucket-owner ACCOUNT` |
| `null` configuration | Set when the call returns `NoSuchPublicAccessBlockConfiguration` |
| `CollectionError` | Set for any other read error |

### Evaluation

```
FLAGS = BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets

if CollectionError present:                UNKNOWN
cfg = PublicAccessBlockConfiguration
if cfg is null:                            FAILED (all four flags reported disabled)
if any flag key missing from cfg:          UNKNOWN (evidence: missing_fields)
if any flag value is not a JSON boolean:   error (input rejected, no result)
if any flag == false:                      FAILED (evidence: disabled_flags)
else:                                      PASSED
```

A `null` configuration is different from a partially populated object. `null` means AWS confirmed that no bucket-level configuration exists, so the result is `FAILED`. A partially populated object means the snapshot is incomplete, so the result is `UNKNOWN`.

### Edge cases

| Case | Expected | Case ID |
|---|---|---|
| All four flags true | PASSED | `s3-all-blocked` |
| `BlockPublicAcls` false | FAILED | `s3-disabled-BlockPublicAcls` |
| `IgnorePublicAcls` false | FAILED | `s3-disabled-IgnorePublicAcls` |
| `BlockPublicPolicy` false | FAILED | `s3-disabled-BlockPublicPolicy` |
| `RestrictPublicBuckets` false | FAILED | `s3-disabled-RestrictPublicBuckets` |
| Configuration `null` (none set) | FAILED | `s3-absent-configuration` |
| Only one flag present | UNKNOWN | `s3-incomplete-snapshot` |
| `CollectionError` | UNKNOWN | `s3-collection-error` |
| Non-boolean flag value (for example `"true"`) | input error | not covered by a case |

### Scope gaps vs AWS S3.8

- Only bucket-level settings are evaluated. Account-level Block Public Access (S3.1) can still block public access when bucket-level flags are off. This check does not consider it.
- Bucket policies, ACLs, access points and Object Ownership are not evaluated, so a FAILED result does not prove exposure.
- Directory buckets are excluded. Only buckets in the collection region are listed.

### Remediation

- **Console:** S3 → *bucket* → Permissions → Block public access (bucket settings) → Edit → enable all four → Save.
- **CLI:**
  ```
  aws s3api put-public-access-block --bucket NAME \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  ```
- Before applying, confirm the bucket is not intentionally public, for example a static website not served through CloudFront OAC. `cspm.py plan-s3` / `simulate-s3` only modify a local snapshot.

### False positives / negatives

- **FP:** account-level Block Public Access is fully on, so the bucket is effectively protected while its bucket-level flags are off. Also, buckets that are intentionally public.
- **FN:** none for the flag check itself. All four flags true can still coexist with cross-account access granted to specific principals, which is not public but may be unwanted.

---

## EC2.13 / EC2.14: Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22 / 3389

**Severity:** High · **Resource:** `AWS::EC2::SecurityGroup` · **Snapshot list:** `security_groups`

Both controls run on every group. EC2.13 uses `port = 22` and EC2.14 uses `port = 3389`. Otherwise the logic is identical.

### Data required

`ec2 describe-security-groups` → `SecurityGroups[]`, using `GroupId` and `IpPermissions[]` with the following fields:

- `IpProtocol`
- `FromPort`, `ToPort`
- `IpRanges[].CidrIp`, `Ipv6Ranges[].CidrIpv6`
- `PrefixListIds[]`

### Evaluation

```
if CollectionError present: UNKNOWN
matches, unresolved = [], []
for p in IpPermissions:
    proto = str(p.IpProtocol)
    covers = proto == "-1"
             or (proto in {"tcp", "6"} and p.FromPort <= port <= p.ToPort)
    if not covers: continue
    unresolved += p.PrefixListIds
    sources = [r.CidrIp for r in p.IpRanges] + [r.CidrIpv6 for r in p.Ipv6Ranges]
    if "0.0.0.0/0" in sources or "::/0" in sources: matches.append(p)

FAILED  if matches
UNKNOWN if not matches and unresolved
PASSED  otherwise
```

- The CIDR comparison is an exact string match. `0.0.0.0/1` plus `128.0.0.0/1` is world-open in effect but does not match.
- Security-group references (`UserIdGroupPairs`) are not considered world-open.
- `udp`, `icmp` and other protocols never cover the port.

### Edge cases

| Case | EC2.13 | EC2.14 | Case ID |
|---|---|---|---|
| TCP 22 from `0.0.0.0/0` | FAILED | PASSED | `ssh-ipv4` |
| TCP 3389 from `::/0` | PASSED | FAILED | `rdp-ipv6` |
| TCP 20–3400 from `0.0.0.0/0` | FAILED | FAILED | `port-range` |
| Protocol `-1` from `::/0` | FAILED | FAILED | `all-protocols` |
| Numeric protocol `"6"` | FAILED | PASSED | `numeric-tcp` |
| TCP 22 from `10.0.0.0/8` | PASSED | PASSED | `private-source` |
| TCP 443 only | PASSED | PASSED | `web-only` |
| UDP 22 from `0.0.0.0/0` | PASSED | PASSED | `udp-only` |
| TCP 22 from a prefix list only | UNKNOWN | PASSED | `unresolved-prefix-list` |
| `CollectionError` | UNKNOWN | UNKNOWN | `sg-collection-error` |

### Scope gaps vs AWS EC2.13 / EC2.14

- UDP is out of scope here. The newer EC2.53/EC2.54 controls cover TCP, UDP and ALL, and they map to CIS v3.0.0/v5.0.0.
- Managed prefix list contents are not resolved. A prefix list that contains `0.0.0.0/0` yields UNKNOWN, not FAILED.
- The check does not consider whether the group is attached to anything, whether the instance has a public IP, routes or IGW, NACLs, or default-group semantics.

### Remediation

- **Console:** EC2 → Security Groups → *group* → Inbound rules → Edit. Remove the `0.0.0.0/0` / `::/0` rule for the port, or change the source to a trusted CIDR.
- **CLI:**
  ```
  aws ec2 describe-security-group-rules --filters Name=group-id,Values=sg-...
  aws ec2 revoke-security-group-ingress --group-id sg-... --security-group-rule-ids sgr-...
  aws ec2 authorize-security-group-ingress --group-id sg-... \
    --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=<trusted CIDR>}]'
  ```
- A wide range such as 20–3400 must be revoked as a whole and then re-added as narrower ranges that exclude 22 and 3389.
- For administrative access, prefer SSM Session Manager or EC2 Instance Connect Endpoint, which need no inbound admin port.

### False positives / negatives

- **FP:** an unattached group; a group on instances with no public path; an all-protocol rule intended for non-admin traffic.
- **FN:** world-open UDP; prefix lists containing `0.0.0.0/0` (these yield UNKNOWN); split CIDRs that cover the whole address space; SSH/RDP on non-standard ports.

---

## GCP.FW.1 / GCP.FW.2: VPC firewall rules should not allow ingress from 0.0.0.0/0 or ::/0 to port 22 / 3389

**Severity:** High · **Resource:** GCP Compute firewall rule · **Snapshot list:** `gcp_firewall_rules` (optional key) · **Standards:** CIS Google Cloud Platform Foundation Benchmark 3.6 (SSH) / 3.7 (RDP)

Both controls run on every rule. GCP.FW.1 uses `port = 22` and GCP.FW.2 uses `port = 3389`.

### Data required

The rules come from `gcloud compute firewall-rules list --format=json`, one object per rule, with these fields:

- `name`
- `direction` (`INGRESS` / `EGRESS`)
- `disabled`
- `sourceRanges[]`
- `allowed[{IPProtocol, ports[]}]`
- `denied[]`
- `priority`
- `targetTags[]`
- `sourceTags[]`
- `network`

The evidence contains these fields:

- `network`
- `priority`
- the world-open `sourceRanges`
- the matching `allowed` entries
- `targetTags`

### Evaluation

```
if CollectionError present: UNKNOWN
world = [s for s in sourceRanges if s in {"0.0.0.0/0", "::/0"}]
if direction (default "INGRESS") != "INGRESS" or disabled == true or not world:
    PASSED
covered(ports) := ports empty/absent
                  or any(lo <= port <= hi for "lo[-hi]" in ports)
matches = [a for a in allowed
           if a.IPProtocol in {"tcp", "6", "all"} and covered(a.ports)]
FAILED if matches else PASSED
```

- A rule that uses only `sourceTags` or `sourceServiceAccounts`, with no world-open `sourceRanges`, is not world-open.
- `denied` entries on the same rule are not evaluated against `allowed` entries.
- This control has no `NOT_APPLICABLE` result. Egress and disabled rules are `PASSED`.

### Edge cases

| Case | FW.1 | FW.2 | Case ID |
|---|---|---|---|
| tcp `["22"]` from `0.0.0.0/0` | FAILED | PASSED | `gcp-ssh-open` |
| tcp `["20-30"]` from `0.0.0.0/0` | FAILED | PASSED | `gcp-ssh-range` |
| tcp `["3389"]` from `::/0` | PASSED | FAILED | `gcp-rdp-ipv6` |
| tcp with no `ports` (all ports) | FAILED | FAILED | `gcp-tcp-no-ports` |
| `IPProtocol: "all"` | FAILED | FAILED | `gcp-all-protocols` |
| udp 22 only | PASSED | PASSED | `gcp-udp-22` |
| private `sourceRanges` | PASSED | PASSED | `gcp-private-source` |
| `sourceTags` only, no `sourceRanges` | PASSED | PASSED | `gcp-source-tags-only` |
| `direction: EGRESS` | PASSED | PASSED | `gcp-egress` |
| `disabled: true` | PASSED | PASSED | `gcp-disabled` |
| `denied` tcp 22 only (deny rule) | PASSED | PASSED | `gcp-deny-rule` |
| `CollectionError` | UNKNOWN | UNKNOWN | `gcp-collection-error` |
| `IPProtocol: "6"` | FAILED | PASSED | not covered by a case |
| `direction` absent (defaults to INGRESS) | FAILED | per ports | not covered by a case |

### Scope gaps

- A higher-priority (lower number) `denied` rule that shadows the allow is not evaluated, so the result can be FAILED although traffic is blocked.
- Hierarchical firewall policies (organization or folder) and global or regional network firewall policies are not collected or evaluated.
- UDP is out of scope.
- The check does not consider whether target instances exist or have external IPs. `targetTags` is reported but not resolved.
- Implied rules and default-network rules such as `default-allow-ssh` are evaluated only if they are present in the input.

### Remediation

- **Console:** VPC network → Firewall → *rule* → Edit → Source IPv4/IPv6 ranges → trusted CIDRs, or delete the rule.
- **CLI:**
  ```
  gcloud compute firewall-rules update NAME --source-ranges=<trusted CIDR>
  gcloud compute firewall-rules delete NAME
  ```
  `--source-ranges` replaces the whole list.
- For admin access, prefer IAP TCP forwarding. Allow only `35.235.240.0/20` on 22/3389 and grant `roles/iap.tunnelResourceAccessor`.

### False positives / negatives

- **FP:** a rule shadowed by a higher-priority deny or by a hierarchical policy; target tags that match no instances; instances with no external IP.
- **FN:** exposure granted by hierarchical or network firewall policies; world-open UDP; split CIDRs that cover the whole address space; non-standard admin ports.

---

## Multi-cloud control design

One logical requirement applies across providers: **no remote administration port (22, 3389) may be reachable from any internet source through a direct allow rule.** Each provider's network ACL model expresses it differently:

| Aspect | AWS security group (EC2.13/14) | GCP VPC firewall rule (GCP.FW.1/2) | Azure NSG (specified, not implemented) |
|---|---|---|---|
| Evaluated object | Group, a set of `IpPermissions` | Single rule | `securityRules[]` on an NSG |
| Direction | Ingress list only | `direction == INGRESS` (default) | `direction == Inbound` |
| Allow vs deny | Allow-only model | `allowed[]` vs `denied[]`; rule `disabled` flag | `access == Allow` |
| World source | `CidrIp 0.0.0.0/0`, `CidrIpv6 ::/0` | `sourceRanges` contains `0.0.0.0/0` / `::/0` | `sourceAddressPrefix(es)` in `*`, `Internet`, `0.0.0.0/0` (also `::/0` recommended) |
| Protocol | `tcp`, `6`, `-1` | `tcp`, `6`, `all` | `Tcp`, `*` |
| Port match | `FromPort <= p <= ToPort`; `-1` = all | `ports[]` of `"p"` / `"lo-hi"`; empty = all | `destinationPortRange` / `destinationPortRanges[]` of `*`, `p`, `lo-hi` |
| Precedence | None (union of allows) | `priority`; a deny with a lower number wins (not evaluated) | `priority`; first match wins (must be evaluated, or documented as a gap) |
| Indirect sources | Prefix lists → UNKNOWN | Tags / service accounts → not world-open | Service tags other than `Internet`, ASGs → not world-open |
| Benchmark | CIS AWS v1.2.0/4.1, 4.2 | CIS GCP 3.6, 3.7 | CIS Microsoft Azure Foundations Benchmark, networking section (RDP and SSH from the internet) |

Design rules for adding a provider:

1. Keep one control per port and per provider, each with its own ID, sharing the port-coverage and world-source semantics above.
2. A read failure is UNKNOWN, never PASSED. Unresolvable indirection, such as AWS prefix lists, is UNKNOWN unless a direct violation already exists.
3. Rule precedence, meaning priority-ordered deny or allow, must be either evaluated or listed as a scope gap. AWS has no precedence. GCP and Azure both do.

### Azure NSG rule (proposed, not implemented)

The Azure CIS numbering below comes from third-party mirrors (Cloudaware, Powerpipe), not from the CIS PDF:

| CIS Azure version | RDP | SSH |
|---|---|---|
| v2.1.0 | not checked | 6.2 |
| v3.0.0 | 7.1 | 7.2 |
| v4.0.0 | 8.1 | 8.2 |

Numbering changes between versions, so always cite the version with the section number.

```
for r in nsg.securityRules:
    world_open = r.direction == "Inbound" and r.access == "Allow"
                 and r.protocol in {"Tcp", "*"}
                 and any(s in {"*", "Internet", "0.0.0.0/0", "::/0"}
                         for s in [r.sourceAddressPrefix] + r.sourceAddressPrefixes)
                 and any(covers(x, port)
                         for x in [r.destinationPortRange] + r.destinationPortRanges)
    covers("*", p) = true; covers("lo-hi", p) = lo <= p <= hi; covers("n", p) = n == p
```

The rule's open questions are:

- whether to evaluate a shadowing lower-priority-number `Deny`;
- NSGs at both the subnet and NIC level;
- whether to treat `defaultSecurityRules` as in scope.

Remediation:

```
az network nsg rule update -g RG --nsg-name NSG -n RULE --source-address-prefixes <trusted CIDR>
```

Alternatively, delete the rule. Prefer Azure Bastion for administrative access.
