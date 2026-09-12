import boto3


REGION = "ap-southeast-1"

REQUIRED_TAG_KEY = "CSPMTest"
REQUIRED_TAG_VALUE = "true"


def get_tag_value(tags, key):
    for tag in tags or []:
        if tag.get("Key") == key:
            return tag.get("Value")

    return None


def extract_resource_id(resource_id):
    """
    Extract AWS resource ID from Security Hub ARN.

    Examples:
        arn:aws:ec2:region:account:vpc/vpc-123
        -> vpc-123

        arn:aws:ec2:region:account:security-group/sg-123
        -> sg-123
    """

    if "/" in resource_id:
        return resource_id.rsplit("/", 1)[-1]

    return resource_id


def validate_vpc(resource_id):

    ec2 = boto3.client(
        "ec2",
        region_name=REGION
    )

    vpc_id = extract_resource_id(
        resource_id
    )

    try:

        response = ec2.describe_vpcs(
            VpcIds=[vpc_id]
        )

        vpcs = response.get(
            "Vpcs",
            []
        )

        if not vpcs:
            return False, "VPC not found"

        tags = vpcs[0].get(
            "Tags",
            []
        )

        value = get_tag_value(
            tags,
            REQUIRED_TAG_KEY
        )

        if value == REQUIRED_TAG_VALUE:

            return True, (
                "CSPMTest=true verified"
            )

        return False, (
            "CSPMTest tag not found"
        )

    except Exception as error:

        return False, (
            f"AWS VPC validation error: "
            f"{error}"
        )


def validate_security_group(
    resource_id
):

    ec2 = boto3.client(
        "ec2",
        region_name=REGION
    )

    sg_id = extract_resource_id(
        resource_id
    )

    try:

        response = ec2.describe_security_groups(
            GroupIds=[sg_id]
        )

        groups = response.get(
            "SecurityGroups",
            []
        )

        if not groups:
            return False, (
                "Security Group not found"
            )

        tags = groups[0].get(
            "Tags",
            []
        )

        value = get_tag_value(
            tags,
            REQUIRED_TAG_KEY
        )

        if value == REQUIRED_TAG_VALUE:

            return True, (
                "CSPMTest=true verified"
            )

        return False, (
            "CSPMTest tag not found"
        )

    except Exception as error:

        return False, (
            f"AWS Security Group "
            f"validation error: {error}"
        )


def validate_s3_bucket(
    resource_id
):

    bucket_name = resource_id.replace(
        "arn:aws:s3:::",
        "",
        1
    )

    s3 = boto3.client(
        "s3",
        region_name=REGION
    )

    try:

        response = s3.get_bucket_tagging(
            Bucket=bucket_name
        )

        tags = response.get(
            "TagSet",
            []
        )

        value = get_tag_value(
            tags,
            REQUIRED_TAG_KEY
        )

        if value == REQUIRED_TAG_VALUE:

            return True, (
                "CSPMTest=true verified"
            )

        return False, (
            "CSPMTest tag not found"
        )

    except Exception as error:

        error_code = getattr(
            error,
            "response",
            {}
        ).get(
            "Error",
            {}
        ).get(
            "Code"
        )

        if error_code in [
            "NoSuchTagSet",
            "NoSuchBucket",
            "AccessDenied"
        ]:

            return False, (
                f"S3 tag validation: "
                f"{error_code}"
            )

        return False, (
            f"AWS S3 validation error: "
            f"{error}"
        )


def validate_resource(
    resource_id,
    resource_type
):

    # S3
    if resource_id.startswith(
        "arn:aws:s3:::"
    ):

        return validate_s3_bucket(
            resource_id
        )

    # VPC
    if ":vpc/" in resource_id:

        return validate_vpc(
            resource_id
        )

    # Security Group
    if ":security-group/" in resource_id:

        return validate_security_group(
            resource_id
        )

    return False, (
        f"Unsupported resource: "
        f"{resource_type}"
    )


if __name__ == "__main__":

    print(
        "CSPM Resource Scope Validator"
    )

    print(
        f"Required tag: "
        f"{REQUIRED_TAG_KEY}="
        f"{REQUIRED_TAG_VALUE}"
    )