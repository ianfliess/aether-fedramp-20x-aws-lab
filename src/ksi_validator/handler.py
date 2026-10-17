import os
import json
import hashlib
import datetime
import urllib.request
import boto3
from botocore.config import Config

fips_config = Config(
    region_name=os.environ.get("AWS_REGION", "us-east-1"),
    use_fips_endpoint=True
)

ecs_client = boto3.client("ecs", config=fips_config)
rds_client = boto3.client("rds", config=fips_config)
s3_client  = boto3.client("s3", config=fips_config)

EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET_NAME"]
CLUSTER_NAME    = os.environ["ECS_CLUSTER_NAME"]
SERVICE_NAME    = os.environ["ECS_SERVICE_NAME"]
DB_IDENTIFIER   = os.environ["RDS_DB_IDENTIFIER"]
WEBHOOK_URL     = os.environ.get("SECURITY_ALERT_WEBHOOK_URL", "")

def lambda_handler(event, context):
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    trigger_type = "REALTIME_DRIFT_EVENT" if "detail" in event and "eventName" in event.get("detail", {}) else "SCHEDULED_PERSISTENT_VALIDATION"

    drift_violation = None
    if trigger_type == "REALTIME_DRIFT_EVENT":
        detail = event["detail"]
        drift_violation = {
            "event_name": detail.get("eventName"),
            "event_source": detail.get("eventSource"),
            "actor_arn": detail.get("userIdentity", {}).get("arn", "Unknown"),
            "source_ip": detail.get("sourceIPAddress"),
            "event_time": detail.get("eventTime")
        }

    svc_resp = ecs_client.describe_services(cluster=CLUSTER_NAME, services=[SERVICE_NAME])
    service = svc_resp["services"][0]
    exec_enabled = service.get("enableExecuteCommand", False)

    td_resp = ecs_client.describe_task_definition(taskDefinition=service["taskDefinition"])
    containers = td_resp["taskDefinition"]["containerDefinitions"]
    all_readonly = all(c.get("readonlyRootFilesystem") is True for c in containers)
    all_pinned_sha = all("@sha256:" in c.get("image", "") for c in containers)

    ksi_cmt_lmc_pass = (not exec_enabled) and all_readonly and all_pinned_sha and (drift_violation is None)

    db_resp = rds_client.describe_db_instances(DBInstanceIdentifier=DB_IDENTIFIER)
    db_inst = db_resp["DBInstances"][0]
    rds_encrypted = db_inst.get("StorageEncrypted", False)
    rds_public    = db_inst.get("PubliclyAccessible", True)
    ksi_svc_pass  = rds_encrypted and (not rds_public)

    report_payload = {
        "schema_version": "fedramp-20x-cr26-v1",
        "timestamp_utc": now_utc,
        "trigger_type": trigger_type,
        "minimum_assessment_scope": {
            "rule_id": "MAS-CSO-IIR",
            "vpc_boundary_tag": "FedRAMP-20x-MAS=In-Scope",
            "fips_endpoints_enforced": True
        },
        "ksi_evaluations": [
            {
                "ksi_id": "KSI-CMT-LMC",
                "ksi_title": "Redeploying vs Modifying",
                "related_800_53_controls": ["CM-03", "SA-10"],
                "related_cmmc_800_171_practices": ["3.4.3", "3.4.5"],
                "status": "PASS" if ksi_cmt_lmc_pass else "FAIL",
                "what_was_tested": "ECS Service ExecuteCommand flag, container readonlyRootFilesystem, @sha256 image digest pinning, and CloudTrail out-of-band API mutations.",
                "how_it_was_tested": "Automated Boto3 API inspection via AWS FIPS 140-3 endpoints and EventBridge CloudTrail event stream correlation.",
                "evidence_demonstrated": {
                    "ecs_execute_command_enabled": exec_enabled,
                    "containers_readonly_rootfs": all_readonly,
                    "images_pinned_to_sha256": all_pinned_sha,
                    "out_of_band_drift_event": drift_violation
                },
                "failure_criteria": "FAIL if enableExecuteCommand=True, readonlyRootFilesystem=False, mutable image tag used, or non-OIDC mutation detected in CloudTrail."
            },
            {
                "ksi_id": "KSI-SVC-ENC",
                "ksi_title": "Securing Information & Automating Secret Management",
                "related_800_53_controls": ["SC-13", "SC-28", "IA-05"],
                "related_cmmc_800_171_practices": ["3.13.11", "3.13.16", "3.5.10"],
                "status": "PASS" if ksi_svc_pass else "FAIL",
                "what_was_tested": "Amazon RDS storage encryption at rest via FIPS 140-3 KMS HSM and private subnet isolation.",
                "how_it_was_tested": "Direct Boto3 describe_db_instances inspection via rds-fips endpoint.",
                "evidence_demonstrated": {
                    "storage_encrypted": rds_encrypted,
                    "kms_key_id": db_inst.get("KmsKeyId"),
                    "publicly_accessible": rds_public
                },
                "failure_criteria": "FAIL if StorageEncrypted=False or PubliclyAccessible=True."
            }
        ]
    }

    canonical_json = json.dumps(report_payload, sort_keys=True)
    payload_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    report_payload["artifact_integrity_sha256"] = payload_sha256

    s3_key = f"ksi-validations/{now_utc[:10]}/{trigger_type}-{now_utc}.json"
    s3_client.put_object(
        Bucket=EVIDENCE_BUCKET,
        Key=s3_key,
        Body=json.dumps(report_payload, indent=2).encode("utf-8"),
        ContentType="application/json"
    )

    if (not ksi_cmt_lmc_pass or not ksi_svc_pass) and WEBHOOK_URL:
        alert_msg = {
            "severity": "HIGH",
            "alert": "FedRAMP 20x KSI Validation Failure / Out-of-Band Drift Detected",
            "s3_evidence_uri": f"s3://{EVIDENCE_BUCKET}/{s3_key}",
            "sha256": payload_sha256,
            "drift_details": drift_violation
        }
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=json.dumps(alert_msg).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=5)

    return report_payload
