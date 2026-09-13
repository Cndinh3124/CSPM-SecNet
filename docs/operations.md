# Quy trình vận hành SecNet CSPM

## 1. Scan

```powershell
$env:PYTHONPATH=".\python"
python -m secnet_cspm scan
```

## 2. Xem risk

```powershell
python -m secnet_cspm risk
```

## 3. Lập remediation plan

```powershell
python -m secnet_cspm plan
```

Plan chỉ cho phép các resource có `CSPMTest=true` trong lab.

## 4. Thực thi

Thực thi policy được tách khỏi Dashboard. Sau khi review plan, chạy policy Cloud Custodian tương ứng hoặc pipeline/Lambda đã phê duyệt.

## 5. Verify

Chạy scan lại. Finding phải chuyển sang PASSED/RESOLVED hoặc resource phải được loại khỏi tập FAILED nếu trạng thái đã được AWS cập nhật.

## 6. Báo cáo

Evidence JSON trong `tests/outputs` được dùng cho dashboard và hồ sơ nghiệm thu.

## 7. Cảnh báo

EventBridge bắt các finding mới/thay đổi trạng thái, SNS phân phối thông báo. Lambda có thể chuẩn hóa nội dung trước khi gửi.
