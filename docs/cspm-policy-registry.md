\# CSPM Policy Registry



\## 1. Mục đích



CSPM Policy Registry là danh mục quản lý tập trung các quy tắc bảo mật được triển khai trong hệ thống CSPM. Registry dùng để theo dõi control, phạm vi tài nguyên, phương thức phát hiện, phương thức remediation và trạng thái thực nghiệm.



\## 2. Danh mục Control



| Control | Nội dung kiểm tra | Resource | Detection | Remediation | Trạng thái |

|---|---|---|---|---|---|

| EC2.2 | Default Security Group không được phép có rule không an toàn | Security Group | AWS Config / Security Hub | Cloud Custodian | DONE |

| EC2.6 | VPC phải bật Flow Logs | VPC | AWS Config / Security Hub | AWS CLI / VPC Flow Logs | DONE |

| EC2.53 | Không cho phép SSH quản trị từ Internet | Security Group | Cloud Custodian / Security Hub | Cloud Custodian | DONE |

| S3.1 | Account-level S3 Public Access Block | AWS Account | AWS Config / Security Hub | AWS CLI | DONE |

| S3.5 | S3 bucket phải yêu cầu TLS | S3 Bucket | AWS Config / Security Hub | Bucket Policy | DONE |

| S3.22 | S3 phải ghi object-level write events | S3 / CloudTrail | AWS Config / Security Hub | CloudTrail | DONE |

| S3.23 | S3 phải ghi object-level read events | S3 / CloudTrail | AWS Config / Security Hub | CloudTrail | DONE |

| CloudTrail.2 | CloudTrail log phải được mã hóa at-rest | CloudTrail | AWS Config / Security Hub | KMS + CloudTrail | DONE |



\## 3. Control chưa remediation



| Control | Resource | Lý do chưa remediation |

|---|---|---|

| S3.20 | S3 Bucket | MFA Delete cần cơ chế xác thực MFA và không phù hợp để tự động hóa trực tiếp trong lab |

| CloudTrail.7 | CloudTrail S3 Bucket | Bucket đang phục vụ CloudTrail logging |

| Config.1 | AWS Account | Cần đánh giá lại cấu hình service-linked role |

| EC2.53 | Security Group | Một số Security Group đang gắn với workload hiện hữu |

| IAM.6 | Root User | Liên quan tài khoản root |

| Account.1 | AWS Account | Cấu hình thông tin liên hệ tài khoản |

| RDS.3 | RDS Instance | RDS hiện hữu, không tự động thay đổi khi chưa xác định workload |

| RDS.5 | RDS Instance | Thay đổi Multi-AZ có ảnh hưởng kiến trúc và chi phí |

| RDS.15 | RDS Cluster | Thay đổi Multi-AZ có ảnh hưởng kiến trúc và chi phí |

| IAM.2 | IAM User | Rule sử dụng IAM\_POLICY\_BLACKLISTED\_CHECK và test user chưa được AWS Config discovery |



\## 4. Nguyên tắc remediation



Remediation chỉ được thực hiện khi:



1\. Resource đã được xác định chính xác.

2\. Resource không thuộc workload cần bảo vệ.

3\. Có phương án remediation có thể kiểm soát.

4\. Có thể kiểm tra trạng thái trước và sau remediation.

5\. AWS Config hoặc Security Hub có thể xác nhận kết quả.



\## 5. Quy trình thực nghiệm



Detection:



AWS Resource

→ AWS Config

→ Security Hub

→ Security Finding



Remediation:



Finding

→ CSPM Policy

→ Cloud Custodian / AWS CLI / Lambda

→ Resource được sửa



Verification:



Resource

→ AWS Config re-evaluation

→ Security Hub

→ PASSED / COMPLIANT



\## 6. Môi trường thực nghiệm



\- Cloud Provider: AWS

\- Region: ap-southeast-1

\- IaC: Terraform

\- Compliance: CIS AWS Foundations Benchmark

\- Configuration assessment: AWS Config

\- Security findings: AWS Security Hub

\- Policy automation: Cloud Custodian

\- Automation language: Python

\- Serverless remediation: AWS Lambda

\- Event processing: Amazon EventBridge

\- Notification: Amazon SNS

\- Monitoring/Reporting: Grafana

