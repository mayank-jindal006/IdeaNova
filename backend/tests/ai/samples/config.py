"""App configuration for the orders service."""
import boto3

AWS_REGION = "ap-south-1"
AWS_ACCESS_KEY_ID = "AKIAUJZDEGXDNCF32EPF"
BUCKET_NAME = "orders-invoices"


def get_s3_client():
    return boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
    )