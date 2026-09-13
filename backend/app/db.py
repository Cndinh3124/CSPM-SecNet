import json
import os
from urllib.parse import quote_plus

import boto3
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


def get_database_url() -> str:
    """
    Build PostgreSQL connection URL.

    Local Docker:
        Uses DATABASE_URL when provided.

    AWS ECS:
        Uses DB_SECRET_ARN for username/password
        and DB_HOST/DB_PORT/DB_NAME for RDS connection details.
    """

    database_url = os.getenv("DATABASE_URL")

    if database_url:
        return database_url

    secret_arn = os.getenv("DB_SECRET_ARN")

    if not secret_arn:
        return (
            "postgresql+psycopg://"
            "secnet:secnet_dev@postgres:5432/secnet_cspm"
        )

    region = os.getenv(
        "AWS_REGION",
        "ap-southeast-1",
    )

    db_host = os.getenv("DB_HOST")

    db_port = os.getenv(
        "DB_PORT",
        "5432",
    )

    db_name = os.getenv(
        "DB_NAME",
        "secnet_cspm",
    )

    if not db_host:
        raise RuntimeError(
            "DB_HOST is required when DB_SECRET_ARN is configured"
        )

    client = boto3.client(
        "secretsmanager",
        region_name=region,
    )

    response = client.get_secret_value(
        SecretId=secret_arn,
    )

    secret_string = response.get("SecretString")

    if not secret_string:
        raise RuntimeError(
            "RDS secret does not contain SecretString"
        )

    secret = json.loads(secret_string)

    username = secret.get("username")
    password = secret.get("password")

    if not username:
        raise RuntimeError(
            "RDS secret does not contain username"
        )

    if not password:
        raise RuntimeError(
            "RDS secret does not contain password"
        )

    return (
        "postgresql+psycopg://"
        f"{quote_plus(username)}:"
        f"{quote_plus(password)}@"
        f"{db_host}:{db_port}/"
        f"{quote_plus(db_name)}"
    )


DATABASE_URL = get_database_url()

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()