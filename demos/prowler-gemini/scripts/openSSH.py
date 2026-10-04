aws ec2 authorize-security-group-ingress \
  --group-id sg-0095b767e1f3f0fc5 \
  --ip-permissions '[
    {
      "IpProtocol": "tcp",
      "FromPort": 22,
      "ToPort": 22,
      "IpRanges": [
        {
          "CidrIp": "0.0.0.0/0",
          "Description": "INTENTIONAL CSPM DEMO MISCONFIGURATION"
        }
      ]
    }
  ]' \
  --region ap-southeast-1
