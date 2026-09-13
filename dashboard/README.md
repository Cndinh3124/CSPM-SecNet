# SecNet CSPM Dashboard V3.2

Dashboard SecNet CSPM giao diện tiếng Việt, giữ nguyên các thuật ngữ kỹ thuật cần thiết như CSPM, AWS, CIS, Security Hub, Resource, Control, Finding, Remediation và Engine.

## Tác giả / Project Owner
Nguyễn Công Định

- Project: SecNet CSPM
- Role: CSPM Developer / Cloud Security
- Điện thoại: 0962633364
- Email: dinhlabs.tech@gmail.com

## Chức năng
- Tổng quan bảo mật
- Security Findings
- CIS Compliance
- AWS Resources
- Remediation
- Policy Registry
- Lịch sử Scan
- Chọn một dòng trong bảng để xem chi tiết Finding / Control / Resource.

Dashboard chỉ đọc dữ liệu và không tự thực hiện remediation.

## Chạy
```powershell
cd D:\CSPM-Project
.\.venv\Scripts\Activate.ps1
pip install -r .\dashboard\requirements.txt
streamlit run .\dashboard\app.py
```
