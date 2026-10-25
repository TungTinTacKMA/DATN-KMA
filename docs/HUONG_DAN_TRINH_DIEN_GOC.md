> Tài liệu lịch sử của lần 3, giữ để tham khảo cách chụp ảnh. Đường dẫn và lệnh khởi chạy cũ có thể không áp dụng cho bộ bàn giao. Xem README.md và HUONG_DAN_HOI_DONG.md để chạy bản đóng gói.

# Hướng dẫn trình diễn sản phẩm và chụp minh chứng lần 3

Đề tài của Phan Văn Tùng – AT190357. Mục tiêu của buổi trình diễn là chứng minh APK được đọc thật, tạo đặc trưng, dự đoán, giải thích và xử lý lỗi; đồng thời biết giải thích mẫu đúng và mẫu sai.

## Mở sản phẩm

1. Mở thư mục `bao-cao-lan-3` và bấm đúp `MO_SAN_PHAM.cmd`.
2. Mở Chrome hoặc Edge đến **http://127.0.0.1:8513**. Phóng to cửa sổ trình duyệt để hai mô hình hiện cạnh nhau.
3. Giữ cửa sổ chương trình đang chạy. Nếu cổng 8513 đã được sử dụng bởi bản này, chỉ cần mở địa chỉ trên, không mở thêm một bản thứ hai.
4. Chọn **Phân tích APK** ở thanh bên. Nếu thanh bên bị thu gọn, bấm mũi tên ở góc trên trái.

Sản phẩm dùng môi trường Python và các mô hình đã có tại `C:\Users\DATN\Chuong3`. Không chuyển riêng thư mục này sang máy khác rồi kỳ vọng chạy được: cần chuyển cả dự án nguồn, mô hình, cấu hình và tạo lại môi trường. Launcher hiện cấu hình cho máy này.

## Kịch bản trình diễn khoảng 8–10 phút

### Bước 1 — Giới thiệu đầu vào và quy trình

Nói: “Chương trình nhận APK, đọc AndroidManifest.xml và các tệp DEX để tạo 163 đặc trưng tĩnh. Mô hình chính là E1–RF dùng quyền; E4–RF dùng thêm API, cấu trúc ứng dụng và các chỉ báo kết hợp để so sánh.”

Chọn **APK mẫu đã chuẩn bị**. Danh sách TP/TN/FP/FN được chọn từ test theo quy tắc đã lưu; đây là các tình huống minh họa, không phải một tập đánh giá mới.

### Bước 2 — Chạy một mẫu được phát hiện đúng

Chọn **Mã độc được phát hiện đúng**, bấm **Phân tích APK từ đầu**. Đợi kết quả rồi chỉ rõ:

- Tên tệp và SHA-256 xác định APK nào đang được phân tích.
- Tên gói, 163 đặc trưng và thời gian xử lý.
- Nhãn dự đoán, điểm cho lớp mã độc và ngưỡng của từng mô hình.
- Nhãn nguồn chỉ hiển thị để đối chiếu; không được dùng làm đầu vào dự đoán.

Nói: “Cả hai mô hình dự đoán mã độc cho mẫu này. Điểm hiển thị là đầu ra mô hình, không phải chứng nhận giám định độc lập.”

### Bước 3 — Trình bày cả báo nhầm và bỏ sót

Chọn **Ứng dụng lành bị báo nhầm** rồi chạy lại. Mẫu có hash đầu `0230de75…`, nhãn nguồn Benign nhưng cả hai mô hình dự đoán mã độc. Nói rõ đây là FP, không sửa nhãn nguồn để làm mô hình có vẻ đúng.

Chọn **Mã độc bị bỏ sót**, chạy lại. Mẫu có hash đầu `159a8b22…`, nhãn nguồn Banking nhưng cả hai mô hình dự đoán lành. Nói: “Đây là FN; việc bổ sung đặc trưng chưa giải quyết được tất cả trường hợp.”

Ở mục giải thích, đọc tên đặc trưng, giá trị và dấu SHAP. Dấu âm kéo xác suất RF nền xuống; dấu dương đẩy lên. SHAP đang giải thích RF trước sigmoid; không cộng năm thanh đang hiện để suy ra trực tiếp điểm sau hiệu chỉnh.

### Bước 4 — So sánh một trường hợp gần ngưỡng

Chọn **Mẫu gần ngưỡng quyết định**, chạy lại. Mẫu nguồn Benign có hash đầu `5660d190…`:

- E1: điểm khoảng 0,237584 vượt ngưỡng 0,228097, nên báo nhầm.
- E4: điểm khoảng 0,006316 dưới ngưỡng 0,067051, nên dự đoán lành.

Nói: “Ví dụ này cho thấy hai bộ đặc trưng có thể đưa ra quyết định khác nhau. Kết luận về toàn bộ mô hình phải dựa vào kết quả trên cả tập test, không chỉ ví dụ này.”

### Bước 5 — Tải một APK trực tiếp từ máy

Chọn **Tải APK từ máy**, bấm **Browse files**, chọn:

`C:\Users\DATN\Chuong3\data\pilot_apks\dozencalc_1.apk`

Bấm **Phân tích APK từ đầu**. Đây là luồng upload thật, chương trình sẽ trích xuất lại. Nhãn của pilot chưa được xác minh độc lập; chỉ trình bày việc nhập tệp và nhận kết quả, không gọi đây là kiểm chứng độ chính xác ngoài CIC.

### Bước 6 — Chứng minh xử lý lỗi

Vẫn ở **Tải APK từ máy**, chọn `fixtures\invalid.apk` trong thư mục sản phẩm. Chạy phân tích. Kết quả mong đợi là “Không đủ dữ liệu để đánh giá”, có mã lỗi, không có xác suất hay nhãn lành/mã độc.

Có thể thử thêm `fixtures\broken_dex.apk`: manifest của fixture được giữ từ pilot nhưng DEX đã cố ý làm hỏng. Chương trình phải trả trạng thái partial và không phân loại bằng vector thiếu.

### Bước 7 — Trình bày kết quả tổng hợp

Chọn **Kết quả thực nghiệm** để xem mô hình chính, lỗi theo nhóm và bốn thí nghiệm bổ sung. Chọn **Kiểm thử và minh chứng** để xem kết quả kiểm thử chức năng.

Giải thích: “7/7 và 8/8 là số ca kiểm thử chức năng đạt, không phải độ chính xác phân loại 100%. Các trường hợp FP và FN vẫn giữ nguyên dự đoán sai.”

## Cách chụp ảnh đúng

Nên dùng Chrome/Edge ở cửa sổ phóng to, zoom 100%; nếu nội dung quá dài thì chụp hai ảnh liên tiếp. Không chụp bằng điện thoại. Dùng **Windows + Shift + S**, chọn vùng bao gồm nội dung cần minh chứng, rồi lưu PNG trong `anh_minh_chung`.

Giữ chữ rõ ở kích thước đọc bình thường. Không cắt mất tên tình huống, mô hình, nhãn, điểm hoặc ngưỡng. Tránh đưa thông báo cá nhân, tab không liên quan và đường dẫn riêng không cần thiết vào ảnh. Không chỉnh sửa số liệu trên ảnh. Mỗi tình huống tải thêm JSON bằng nút **Tải kết quả và minh chứng JSON** để giữ bằng chứng gốc.

Danh sách ảnh cần chụp:

1. **01_giao_dien_dau_vao.png** — Tên sản phẩm, hai cách nhập APK, danh sách tình huống và nút phân tích. Chụp trước khi chạy.
2. **02_apk_phat_hien_dung.png** — Sau khi chạy TP; giữ SHA-256, tên gói, hai dự đoán, điểm và ngưỡng.
3. **03_bao_nham_FP.png** — Chạy FP; ảnh phải có nhãn nguồn Benign và dự đoán mã độc.
4. **04_bo_sot_FN.png** — Chạy FN; ảnh phải có nhãn nguồn Banking và dự đoán lành.
5. **05_giai_thich_FN.png** — Biểu đồ SHAP, tên đặc trưng, phần ghi RF nền và sigmoid. Dùng thêm hình `results/figures/SHAP_FN_E1_P__RF.png` khi cần biểu đồ rõ để đưa vào Word.
6. **06_so_sanh_gan_nguong.png** — Cùng một APK, E1 báo mã độc và E4 dự đoán lành; giữ cả ngưỡng của hai mô hình.
7. **07_upload_apk_thuc_te.png** — Tải DozenCalc từ máy; chụp kết quả có tên tệp và SHA-256. Chú thích ảnh phải ghi nhãn pilot chưa được xác minh.
8. **08_tu_choi_apk_loi.png** — Upload invalid.apk; giữ tên tệp, thông báo không đủ dữ liệu và mã lỗi.
9. **09_kiem_thu_tong_hop.png** — Màn hình Kiểm thử và minh chứng, có phần giải thích ý nghĩa “đạt”.
10. **10_thi_nghiem_bo_sung.png** — Bảng thí nghiệm mới và dòng ghi rõ đây là phân tích sau khi đã biết test cũ.

Bạn không cần gửi tất cả ảnh ngay. Khi tự chạy, ưu tiên TP, FN, gần ngưỡng và APK lỗi để kiểm tra bạn đã nắm đúng quy trình. Ảnh do chương trình hoặc trợ lý đã chụp cần được gọi đúng là ảnh minh chứng của lần chạy đó, không thay ngày hay mô tả thành một lần bạn tự chạy.

## Cách đưa vào báo cáo sau này

- Mục triển khai: giao diện, module, đầu vào/đầu ra, mô hình sử dụng và hình minh họa.
- Mục kiểm thử: tách kiểm thử chức năng khỏi độ chính xác mô hình; ghi rõ 5 APK test và 2 pilot chưa có nhãn chuẩn.
- Mục phân tích lỗi: Banking, FP/FN, SHAP và giới hạn va chạm vector.
- Mục thí nghiệm bổ sung: nêu kế hoạch, cấu hình cố định, dữ liệu dùng lại và giới hạn kết luận.
- Kết luận: sử dụng nội dung có căn cứ trong `KET_QUA_VA_KET_LUAN_BO_SUNG.md`.

Không cần huấn luyện lại toàn bộ dự án để trình diễn. Mỗi nút “Phân tích APK từ đầu” chạy lại trích xuất APK và suy luận bằng mô hình đã lưu.
