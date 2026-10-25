# Trạng thái bộ bàn giao ngày 25/10/2026

## Đã đưa vào

- Mã nguồn nghiên cứu giữ nguyên bản đã khóa; demo được sửa để sử dụng đường dẫn trong thư mục bàn giao.
- 16 mô hình chính, bốn mô hình thí nghiệm bổ sung, cấu hình và số liệu đánh giá tương ứng.
- Ma trận 11.277 mẫu × 163 đặc trưng, nhãn và phân chia dữ liệu; chương trình đối chiếu dự đoán E1/E4 trên 3.268 mẫu test.
- Phân tích mẫu sai, vector trùng giữa các tập, kết quả độ nhạy và kết luận bổ sung hiện có.
- Bản ghi ngày 09/10/2026 của bảy ca APK và tám ca lỗi. Những con số này mô tả kiểm thử chức năng lịch sử, không phải độ chính xác và không phải kết quả chạy mới khi đóng gói.
- Ảnh minh chứng đã có, hướng dẫn trình diễn và bản Word lần 2.

## Chưa được coi là hoàn tất

1. **Quyển đồ án cuối:** bản `BAO_CAO_BAN_THAO_LAN_2.docx` chưa phải quyển cuối. Cần tích hợp sản phẩm, kiểm thử, mẫu sai, giới hạn dữ liệu, lựa chọn mô hình, thí nghiệm bổ sung và kết luận vào nội dung thống nhất; hoàn thiện trích dẫn, bảng/hình, mục lục, phụ lục và định dạng theo mẫu khoa. Tài liệu Markdown bổ sung là nguồn biên soạn.
2. **Xác nhận của giảng viên:** chưa có tiêu chí hoặc nhận xét chi tiết ngoài “chưa đạt” trong trao đổi hiện có; không coi danh sách này là tiêu chí duyệt chính thức của khoa.
3. **Đánh giá dữ liệu mới:** các thí nghiệm bổ sung sử dụng test đã biết. Chưa có bằng chứng đánh giá độc lập trên bộ ngoài có nhãn xác minh trong bộ này. Cần giới hạn kết luận tương ứng, hoặc bổ sung đánh giá trước khi đưa ra khẳng định rộng hơn.
4. **Trình diễn bản cuối:** chọn APK phù hợp, chạy trên máy bảo vệ, lưu JSON và ảnh phù hợp với giao diện bản cuối. APK pilot chưa xác minh nhãn chỉ dùng kiểm tra chức năng.
5. **Slide và hồ sơ:** chưa có slide bảo vệ cuối cùng, bản PDF cuối hoặc bộ phiếu được xác nhận trong thư mục này. Chuẩn bị theo mẫu khoa và thông tin thực tế; không tự ghi hoàn thành hay ký thay.
6. **Tái lập từ dữ liệu thô:** dữ liệu APK, bản ghi nguồn và `evidence.jsonl` được loại khỏi GitHub để giữ bộ bàn giao gọn. Giữ bản gốc bên ngoài nếu cần hội đồng kiểm tra chuỗi dữ liệu đầy đủ.

## Phần điều chỉnh khi đóng gói

- Chuyển demo từ đường dẫn cố định của máy phát triển sang thư mục hiện tại.
- Dùng tải APK cho lần chạy mới; thêm trang xem minh chứng lịch sử, ghi rõ không chạy APK trong lần xem.
- Thêm trình cài đặt/khởi chạy/kiểm tra và hướng dẫn chạy trên Windows với Python 3.11.
- Thêm kiểm tra toàn vẹn, đối chiếu dự đoán từ ma trận gọn và kiểm thử bản bàn giao. Không huấn luyện lại hoặc thay đổi số liệu nghiên cứu để đóng gói.

`KIEM_TRA_DONG_GOI.md` ghi kết quả kiểm tra thực tế của lần tập hợp này và giới hạn của việc xác minh.
