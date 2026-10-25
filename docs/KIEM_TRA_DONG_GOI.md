# Kiểm tra bản đóng gói — 25/10/2026

Thực hiện từ thư mục bàn giao, sử dụng môi trường Python 3.11 hiện có của dự án trên Windows. Mã nguồn và tài nguyên được nạp từ bản sao bàn giao; không thay đổi nguồn nghiên cứu gốc.

## Kết quả đã kiểm tra

- Đối chiếu SHA-256 các tệp trong manifest bàn giao: đạt.
- 16 mô hình chính, mã nguồn đã khóa, cấu hình và kết quả đánh giá: khớp manifest nghiên cứu gốc.
- Bốn mô hình bổ sung và các tệp đi kèm: khớp manifest thí nghiệm bổ sung.
- Ma trận, nhãn, danh sách mẫu và audit: khớp khóa dữ liệu; phân chia dữ liệu và khóa mô hình có ID tương ứng.
- Tái tạo dự đoán E1–RF và E4–RF trên 3.268 mẫu test: nhãn dự đoán khớp; sai lệch xác suất lớn nhất của mỗi mô hình khoảng `1,11 × 10^-16`, nhỏ hơn ngưỡng đối chiếu `10^-12`.
- Ba kiểm thử bản bàn giao: **3 passed**. Bao gồm điều hướng các trang khi không kèm APK gốc, suy luận hai mô hình từ bản ghi mẫu FP đã lưu, và từ chối tệp APK không hợp lệ mà không gán nhãn.
- Phân tích mới APK pilot DozenCalc từ ngoài thư mục bàn giao: trích xuất 163 đặc trưng, suy luận hai mô hình thành công; xác suất khớp bản ghi trước đó. Đây là kiểm tra chức năng; nhãn pilot chưa được xác minh.
- Không có APK, archive dữ liệu, tệp môi trường chứa cấu hình bí mật hay khóa riêng trong danh sách tệp rà soát. Quét mẫu khóa riêng/GitHub token/AWS access key có độ đặc hiệu cao trên các tệp văn bản không phát hiện khớp; đây không phải kiểm toán bí mật toàn diện.

Bản ghi kiểm thử nằm trong `kiem_thu_dong_goi.xml`; thông tin lần phân tích pilot mới nằm trong `kiem_tra_apk_dong_goi.json`. Muốn kiểm tra lại hiện trạng, chạy `KIEM_TRA.cmd`; kết quả mới nằm trong `results/package_verification.json`.

## Giới hạn xác minh

- Không cài lại toàn bộ thư viện trong một môi trường sạch ở lần đóng gói này. Lệnh cài đặt được chuẩn bị cho Python 3.11; cần thử ở máy bảo vệ.
- Các kiểm thử có cảnh báo deprecation từ thư viện phụ thuộc; không có kiểm thử thất bại. Chưa nâng phiên bản thư viện để tránh thay đổi môi trường mô hình đã khóa.
- Không huấn luyện lại và không xác minh toàn bộ chuỗi dữ liệu thô vì bản gọn không kèm `evidence.jsonl` và kho APK.
- Việc đóng gói và kiểm tra sản phẩm không xác nhận quyển báo cáo đã đạt yêu cầu giảng viên. Bản Word vẫn là báo cáo lần 2.
