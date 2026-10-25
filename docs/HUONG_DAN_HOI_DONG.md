# Trình tự xem sản phẩm và minh chứng

1. Đọc README và `TRANG_THAI_BAN_GIAO.md` để biết phạm vi đã có, phần còn thiếu.
2. Chạy `KIEM_TRA.cmd`: kiểm tra byte tệp, 16 mô hình gốc và bốn mô hình bổ sung; đối chiếu dự đoán E1/E4 với kết quả đã báo cáo. Lần kiểm tra mới ghi vào `results/package_verification.json`.
3. Mở demo bằng `MO_SAN_PHAM.cmd`. Trang **Kết quả thực nghiệm** trình bày số liệu chính và phần bổ sung, có thông tin về giới hạn diễn giải.
4. Trang **Minh chứng đã lưu** có TP, TN, FP, FN, mẫu gần ngưỡng và hai pilot. Chọn FP/FN để giải thích sai sót của mô hình. Những bản ghi này giữ thời điểm chạy cũ, không thay thế kiểm thử APK trực tiếp.
5. Nếu trình diễn trực tiếp, dùng trang **Phân tích APK** và tự cung cấp APK. Quan sát tên gói, SHA-256, điểm/ngưỡng của hai mô hình, kết quả và SHAP. Tải JSON để lưu bằng chứng mới. Thời gian xử lý phụ thuộc máy và APK; tệp lỗi có thể bị từ chối.
6. Mở `outputs/runs/main/test_metrics.csv`, `test_predictions.csv`, `cv_results.csv` và `model_cards.json` khi cần truy vết số liệu. Các manifest phân biệt trạng thái khóa trước đánh giá (`freeze.json`) với kết quả đã đánh giá (`evaluation_complete.json`).

## Chụp minh chứng mới

- Ảnh tổng quan: tiêu đề sản phẩm và chức năng đang thực hiện.
- Ảnh kết quả APK: tên tệp/tên gói, SHA-256, điểm và ngưỡng dự đoán. Giữ JSON cùng lần chạy để đối chiếu.
- Ảnh giải thích: chọn đúng mô hình và hiển thị biểu đồ SHAP cùng tên đặc trưng.
- Ảnh lỗi: thông báo từ chối, không có nhãn hoặc điểm suy đoán giả.
- Ghi chú dưới hình: chức năng, tên mẫu hoặc mã mẫu, mô hình, ngày chạy; ghi rõ “minh chứng đã lưu” nếu ảnh là kết quả lịch sử.

Các ảnh trong `anh_minh_chung/` được sao chép từ sản phẩm lần 3 trước đây. Giao diện bản bàn giao có thay đổi phần chọn APK và bổ sung trang xem lịch sử; cần chụp lại hình nếu quyển cuối mô tả giao diện mới. Hướng dẫn chụp chi tiết cũ nằm trong `HUONG_DAN_TRINH_DIEN_GOC.md`, có đánh dấu phạm vi lịch sử.

## Trước khi bảo vệ

Chạy thử các bước trên ở máy dùng để trình bày; chuẩn bị APK mẫu và bản ghi dự phòng ngoài repository. Hoàn thiện quyển Word/PDF, slide và hồ sơ theo biểu mẫu khoa trước khi coi đây là bộ nộp cuối cùng.
