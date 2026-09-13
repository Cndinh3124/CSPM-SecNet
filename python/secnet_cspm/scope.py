from dataclasses import dataclass
import boto3

@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    tags: dict

class ScopeValidator:
    def __init__(self, registry, region="ap-southeast-1"):
        self.registry = registry
        tag = registry.get("scope_tag", {})
        self.tag_key = tag.get("key", "CSPMTest")
        self.tag_value = str(tag.get("value", "true"))
        self.require_scope = bool(registry.get("require_explicit_scope", True))
        self.allow_production = bool(registry.get("allow_production_resources", False))
        self.region = region
        self.ec2 = boto3.client("ec2", region_name=region)
        self.s3 = boto3.client("s3", region_name=region)

    def _tags(self, resource_id, resource_type):
        try:
            if resource_type == "AwsEc2SecurityGroup":
                r = self.ec2.describe_security_groups(GroupIds=[resource_id])["SecurityGroups"][0]
                return {t["Key"]: str(t["Value"]) for t in r.get("Tags", [])}
            if resource_type == "AwsEc2Vpc":
                r = self.ec2.describe_vpcs(VpcIds=[resource_id])["Vpcs"][0]
                return {t["Key"]: str(t["Value"]) for t in r.get("Tags", [])}
            if resource_type == "AwsS3Bucket":
                return {t["Key"]: str(t["Value"]) for t in self.s3.get_bucket_tagging(Bucket=resource_id).get("TagSet", [])}
        except Exception:
            return {}
        return {}

    def validate(self, resource_id, resource_type):
        tags = self._tags(resource_id, resource_type)
        if not self.allow_production and tags.get("Environment", "").lower() == "production":
            return ScopeDecision(False, "production resource is protected", tags)
        if self.require_scope and tags.get(self.tag_key) != self.tag_value:
            return ScopeDecision(False, f"{self.tag_key}={self.tag_value} not found", tags)
        return ScopeDecision(True, "explicit remediation scope verified", tags)
