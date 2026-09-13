# Dashboard integration

Giữ dashboard hiện tại làm lớp presentation. Dashboard nên đọc:

- `tests/outputs/cspm-scan-*.json`
- `tests/outputs/cspm-remediation-plan.json`
- execution log nếu có.

Các bảng Findings / Compliance / Resources dùng selection để mở Detail. Dashboard không gọi API mutation.

Nếu muốn thay dashboard hiện tại bằng bản UI V3.2 đã chốt, copy thư mục `dashboard/` từ package `SecNet-CSPM-Dashboard-v3.2.zip` vào project.
