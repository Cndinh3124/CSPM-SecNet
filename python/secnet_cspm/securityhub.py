import boto3

class SecurityHubCollector:
    def __init__(self, region):
        self.client = boto3.client("securityhub", region_name=region)

    def findings(self, control_id=None):
        filters = {
            "RecordState": [{"Value":"ACTIVE","Comparison":"EQUALS"}]
        }
        if control_id:
            filters["ComplianceSecurityControlId"] = [{"Value":control_id,"Comparison":"EQUALS"}]
        paginator = self.client.get_paginator("get_findings")
        out=[]
        for page in paginator.paginate(Filters=filters):
            out.extend(page.get("Findings", []))
        return out
