import json
import os
from datetime import datetime, timezone

import boto3
import psycopg


AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-1")
DB_HOST = os.environ["DB_HOST"]
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "secnet_cspm")
DB_SECRET_ARN = os.environ["DB_SECRET_ARN"]


secretsmanager = boto3.client(
    "secretsmanager",
    region_name=AWS_REGION,
)


def get_db_credentials():
    response = secretsmanager.get_secret_value(
        SecretId=DB_SECRET_ARN,
    )

    secret = json.loads(response["SecretString"])

    return (
        secret["username"],
        secret["password"],
    )


def create_scan(region: str, scope: str):
    username, password = get_db_credentials()

    connection = psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=username,
        password=password,
	sslmode="require",
    )

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO scans (
                    status,
                    provider,
                    region,
                    scope,
                    requested_by,
                    total_controls,
                    passed_controls,
                    failed_controls,
                    compliance_percent,
                    created_at
                )
                VALUES (
                    'QUEUED',
                    'AWS',
                    %s,
                    %s,
                    'EVENTBRIDGE',
                    0,
                    0,
                    0,
                    0,
                    %s
                )
                RETURNING id
                """,
                (
                    region,
                    scope,
                    datetime.now(timezone.utc),
                ),
            )

            scan_id = cursor.fetchone()[0]

        connection.commit()

        return scan_id

    finally:
        connection.close()


def lambda_handler(event, context):
    detail = event.get("detail", {})

    region = (
        detail.get("awsRegion")
        or AWS_REGION
    )

    scope = os.getenv(
        "CSPM_SCOPE",
        "LAB",
    )

    scan_id = create_scan(
        region=region,
        scope=scope,
    )

    return {
        "statusCode": 200,
        "scan_id": scan_id,
        "status": "QUEUED",
        "provider": "AWS",
        "region": region,
        "scope": scope,
    }