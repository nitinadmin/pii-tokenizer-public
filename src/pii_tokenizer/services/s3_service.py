import json

import boto3
from botocore.exceptions import ClientError

from pii_tokenizer.config import settings
from pii_tokenizer.services.logger_service import PipelineLogger


def _get_client():
    kwargs = {"region_name": settings.AWS_REGION}
    # If explicit credentials are provided, use them; otherwise boto3 uses
    # its standard credential provider chain (IAM role, SSO, env, etc.).
    if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
        kwargs.update(
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )
        if settings.AWS_SESSION_TOKEN:
            kwargs["aws_session_token"] = settings.AWS_SESSION_TOKEN
    return boto3.client("s3", **kwargs)


def ensure_bucket(log: PipelineLogger, bucket: str | None = None):
    """Create the given S3 bucket (default: main data bucket) if absent,
    with Block Public Access, AES-256 default encryption and versioning."""
    client = _get_client()
    bucket = bucket or settings.S3_BUCKET_NAME
    try:
        client.head_bucket(Bucket=bucket)
        log.info(f"[S3] Bucket exists: {bucket}")
    except ClientError:
        log.info(f"[S3] Creating bucket: {bucket}")
        create_args: dict = {"Bucket": bucket}
        if settings.AWS_REGION != "us-east-1":
            create_args["CreateBucketConfiguration"] = {
                "LocationConstraint": settings.AWS_REGION
            }
        client.create_bucket(**create_args)

        client.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        log.info(f"[S3] Block Public Access enabled on {bucket}")

        client.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
        log.info(f"[S3] AES-256 encryption enabled on {bucket}")

        client.put_bucket_versioning(
            Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
        )
        log.info(f"[S3] Versioning enabled on {bucket}")


def ensure_all_buckets(log: PipelineLogger):
    """Ensure both the data bucket and the SEPARATE token vault bucket exist.

    The vault bucket holds PII->token mappings. Keeping it separate means
    access to tokenized output does NOT grant the ability to reverse it —
    in production, restrict this bucket to a dedicated detokenization role.
    """
    if not settings.AUTO_CREATE_BUCKETS:
        log.info("[S3] AUTO_CREATE_BUCKETS=false — assuming buckets are provisioned")
        return
    ensure_bucket(log, settings.S3_BUCKET_NAME)
    ensure_bucket(log, settings.S3_VAULT_BUCKET_NAME)


def upload_file(key: str, content: bytes, log: PipelineLogger, bucket: str | None = None) -> str:
    client = _get_client()
    bucket = bucket or settings.S3_BUCKET_NAME
    s3_path = f"s3://{bucket}/{key}"

    log.info(f"[S3] Uploading to: {s3_path}")
    client.put_object(
        Bucket=bucket, Key=key, Body=content, ServerSideEncryption="AES256"
    )
    log.success(f"[S3] File stored at {s3_path}")
    return s3_path


def upload_text(key: str, text: str, log: PipelineLogger, bucket: str | None = None) -> str:
    return upload_file(key, text.encode("utf-8"), log, bucket)


def upload_json(key: str, data: dict, log: PipelineLogger, bucket: str | None = None) -> str:
    return upload_file(key, json.dumps(data, indent=2).encode("utf-8"), log, bucket)


def promote_object(src_key: str, dst_key: str, log: PipelineLogger) -> str:
    """Promote a scanned object from quarantine/ to uploads/ using a
    server-side copy. copy_object guarantees the promoted bytes are exactly
    the bytes GuardDuty scanned — re-uploading from application memory
    would only be equal by trust."""
    client = _get_client()
    bucket = settings.S3_BUCKET_NAME

    log.info(f"[S3] Promoting (server-side copy): {src_key} → {dst_key}")
    client.copy_object(
        Bucket=bucket,
        Key=dst_key,
        CopySource={"Bucket": bucket, "Key": src_key},
        ServerSideEncryption="AES256",
    )
    delete_object(src_key, log)
    s3_path = f"s3://{bucket}/{dst_key}"
    log.success(f"[S3] Object promoted to {s3_path}")
    return s3_path


def delete_object(key: str, log: PipelineLogger, bucket: str | None = None):
    client = _get_client()
    bucket = bucket or settings.S3_BUCKET_NAME
    try:
        client.delete_object(Bucket=bucket, Key=key)
        log.info(f"[S3] Deleted: s3://{bucket}/{key}")
    except ClientError as e:
        log.warn(f"[S3] Failed to delete s3://{bucket}/{key}: {type(e).__name__}")


def purge_object(key: str, log: PipelineLogger, bucket: str | None = None):
    """Delete EVERY version of an object. On a versioned bucket a plain
    delete only adds a delete marker and leaves the bytes recoverable — not
    acceptable for a file GuardDuty flagged as malware. Requires
    s3:ListBucketVersions and s3:DeleteObjectVersion."""
    client = _get_client()
    bucket = bucket or settings.S3_BUCKET_NAME
    try:
        resp = client.list_object_versions(Bucket=bucket, Prefix=key)
        entries = resp.get("Versions", []) + resp.get("DeleteMarkers", [])
        for v in entries:
            if v["Key"] == key:
                client.delete_object(Bucket=bucket, Key=key, VersionId=v["VersionId"])
        log.info(f"[S3] Purged all versions: s3://{bucket}/{key}")
    except ClientError as e:
        log.warn(f"[S3] Version purge failed for s3://{bucket}/{key}: {type(e).__name__} — "
                 "falling back to a plain delete")
        delete_object(key, log, bucket)


def download_bytes(key: str, bucket: str | None = None) -> bytes:
    client = _get_client()
    bucket = bucket or settings.S3_BUCKET_NAME
    resp = client.get_object(Bucket=bucket, Key=key)
    return resp["Body"].read()


def download_text(key: str, bucket: str | None = None) -> str:
    return download_bytes(key, bucket).decode("utf-8")
