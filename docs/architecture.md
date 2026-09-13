# SecNet CSPM – Kiến trúc hoàn chỉnh

SecNet triển khai CSPM theo mô hình nhiều lớp. Lớp thu thập sử dụng AWS Config và AWS API để lấy trạng thái cấu hình; lớp đánh giá dùng AWS Security Hub/CIS và policy registry; lớp cảnh báo sử dụng EventBridge/SNS; lớp remediation dùng Cloud Custodian và Lambda; lớp báo cáo cung cấp dashboard và evidence. Đây là cách hiện thực hóa kiến trúc 5 lớp đã nêu trong đề xuất giải pháp.

## Luồng xử lý

```text
AWS Resources
      |
      v
AWS Config / AWS APIs
      |
      v
Security Hub + CIS findings
      |
      v
SecNet CSPM Engine
  |        |        |
  |        |        +--> Risk Engine
  |        +-----------> Scope Validator
  +--------------------> Finding Normalizer
                           |
             +-------------+-------------+
             |                           |
             v                           v
       Dashboard / Report         Remediation Planner
                                         |
                                         v
                              Approved Cloud Custodian
                                         |
                                         v
                                  AWS / Lambda
                                         |
                                         v
                                  Re-scan / Verify
```

## Nguyên tắc

Dashboard chỉ đọc. Engine quyết định trạng thái và lập kế hoạch. Policy quyết định hành động. Terraform quản lý hạ tầng. Scope validator là lớp bảo vệ cuối trước remediation.
