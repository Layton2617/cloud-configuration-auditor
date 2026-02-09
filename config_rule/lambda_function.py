"""AWS Config custom Lambda rule wrapping cspm.check_group (EC2.13 / EC2.14)."""

import json

import cspm


SG_TYPE = "AWS::EC2::SecurityGroup"
# PutEvaluations rejects INSUFFICIENT_DATA, and skipping the evaluation would leave a stale
# earlier result in place, so an unresolved prefix list is reported as NON_COMPLIANT for review.
COMPLIANCE = {"PASSED": "COMPLIANT", "FAILED": "NON_COMPLIANT", "UNKNOWN": "NON_COMPLIANT"}


def to_snapshot(configuration):
    permissions = []
    for p in configuration["ipPermissions"]:
        # ipRanges is the older flat list of CIDR strings; ipv4Ranges carries the same data as objects.
        cidrs = [r["cidrIp"] for r in p.get("ipv4Ranges", [])] + p.get("ipRanges", [])
        permissions.append({
            "IpProtocol": p["ipProtocol"], "FromPort": p.get("fromPort"), "ToPort": p.get("toPort"),
            "IpRanges": [{"CidrIp": c} for c in cidrs],
            "Ipv6Ranges": [{"CidrIpv6": r["cidrIpv6"]} for r in p.get("ipv6Ranges", [])],
            "PrefixListIds": [{"PrefixListId": r["prefixListId"]} for r in p.get("prefixListIds", [])],
        })
    return {"GroupId": configuration["groupId"], "IpPermissions": permissions}


def annotation(check, port):
    if check["status"] == "FAILED":
        detail = f"world-open (0.0.0.0/0 or ::/0) TCP ingress covers port {port}"
    elif check["status"] == "UNKNOWN":
        ids = ", ".join(p["PrefixListId"] for p in check["evidence"]["unresolved_prefix_lists"])
        detail = f"UNVERIFIED: prefix list(s) {ids} allow port {port} and were not resolved; review manually"
    else:
        detail = f"no direct world-open TCP ingress covers port {port}; routes/NACLs not evaluated"
    return f"{check['control_id']} {check['status']}: {detail}"[:256]


def config_item(invoking_event, client):
    if invoking_event["messageType"] == "ConfigurationItemChangeNotification":
        return invoking_event["configurationItem"]
    summary = invoking_event["configurationItemSummary"]
    item = client.get_resource_config_history(
        resourceType=summary["resourceType"], resourceId=summary["resourceId"],
        laterTime=summary["configurationItemCaptureTime"], limit=1)["configurationItems"][0]
    # The history API returns configuration as a JSON string and the capture time as a datetime.
    return {**item, "configuration": json.loads(item["configuration"])}


def lambda_handler(event, context, client=None):
    invoking_event = json.loads(event["invokingEvent"])
    if invoking_event["messageType"] not in (
        "ConfigurationItemChangeNotification", "OversizedConfigurationItemChangeNotification"
    ):
        return None
    port = int(json.loads(event.get("ruleParameters") or "{}").get("port", 22))
    if port not in (22, 3389):
        raise ValueError(f"port must be 22 or 3389, got {port}")
    if client is None:
        import boto3
        client = boto3.client("config")

    item = config_item(invoking_event, client)
    if (item["resourceType"] != SG_TYPE or event.get("eventLeftScope")
            or item["configurationItemStatus"] in ("ResourceDeleted", "ResourceDeletedNotRecorded")):
        compliance, note = "NOT_APPLICABLE", "Resource deleted, out of scope, or not a security group."
    else:
        check = cspm.check_group(to_snapshot(item["configuration"]), port)
        compliance, note = COMPLIANCE[check["status"]], annotation(check, port)

    evaluation = {
        "ComplianceResourceType": item["resourceType"], "ComplianceResourceId": item["resourceId"],
        "ComplianceType": compliance, "Annotation": note,
        "OrderingTimestamp": item["configurationItemCaptureTime"],
    }
    client.put_evaluations(Evaluations=[evaluation], ResultToken=event["resultToken"])
    return evaluation
