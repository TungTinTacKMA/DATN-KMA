# Kết quả bổ sung và căn cứ cập nhật kết luận

Ngày lập: 2026-10-09T22:03:10+07:00. Đề tài của Phan Văn Tùng, AT190357.

Tài liệu này ghi các công việc thực sự đã chạy cho lần 3. Quyển DOCX chưa được sửa. Nguồn chính là dự án C:/Users/DATN/Chuong3; mã trình diễn và kết quả mới nằm trong thư mục bao-cao-lan-3.

## 1. Những gì đã được kiểm chứng

- Dữ liệu, nhãn, schema, danh sách chia tập, mã nguồn, 16 mô hình và các tệp kết quả đều khớp checksum đã lưu.
- Dataset: `d2f37686122f63a68b8c66ccba775f907a815b813cf5d4fe359cb4edb71254c5`.
- Split: `2987586bcaf03b44090b566e5be49ce74aa294aa44f03c723f54fb93e9b77478`.
- Freeze: `4c0f742d1bf7ffe59e3928c6ce6ad2f82a9598b303d34b9ba85469d777685f27`.
- Đã chạy lại dự đoán của E1–RF và E4–RF trên toàn bộ 3.268 vector test; chênh lệch xác suất tối đa dưới 10⁻¹² so với tệp đã báo cáo.
- Đã thực hiện 7 lượt kiểm thử APK từ đầu đến kết quả, gồm TP, TN, FP, FN, gần ngưỡng và hai APK pilot ngoài tập dữ liệu đã khóa.
- Cả 5 APK test tạo lại đúng 163 đặc trưng và dự đoán cũ. Đây là bằng chứng về tính nhất quán; FP/FN vẫn là dự đoán sai của mô hình.
- Hai APK pilot chưa có nhãn chuẩn độc lập. Chúng chỉ chứng minh module xử lý được đầu vào ngoài tập đã khóa.
- 8/8 ca lỗi được từ chối đúng: ZIP hỏng, thiếu manifest, định dạng không hỗ trợ, mất tệp, vượt giới hạn kích thước, quá thời gian, DEX hỏng gây partial và schema không tương thích.

Minh chứng: `results/integrity.json`, `results/apk_checks/plan.json`, các JSON từng ca, `cases.csv`, `negative_cases.csv`, `complete.json`.

## 2. Phân tích mẫu sai

E1–RF bỏ sót 45 mẫu: 38 Banking, 7 Adware, 0 SMS. Trong 369 mẫu Banking ở test, tỷ lệ bỏ sót là 10,30%. E4–RF bỏ sót 10 mẫu, đều thuộc Banking, tương ứng 2,71% nhóm này. E1 báo nhầm 51/763 mẫu lành; E4 báo nhầm 29/763.

Trong 45 FN của E1, không mẫu nào có SEND_SMS, trong khi khoảng 85,41% TP có quyền này. READ_PHONE_STATE xuất hiện ở khoảng 35,56% FN so với 98,50% TP. Ở phía mẫu lành, READ_PHONE_STATE xuất hiện trong khoảng 90,20% FP so với 33,01% TN. Các số này là thống kê liên hệ trong dữ liệu, không chứng minh quyền là nguyên nhân độc hại.

Không diễn giải p_custom_count theo một chiều cố định. Trong tập này, tỷ lệ có p_custom_count khác 0 ở FP thấp hơn TN; một giá trị bằng 0 cũng có thể đẩy dự đoán theo hướng mã độc tùy mẫu. Cần đọc cả giá trị đặc trưng lẫn dấu SHAP.

Ba trường hợp nên trình bày:

- FN `159a8b22808a87ba…`: nhãn nguồn Banking; cả E1 và E4 dự đoán lành. Cho thấy bộ đầy đủ vẫn có điểm mù.
- FP `0230de75c8b59896…`: nhãn nguồn Benign; cả hai mô hình báo mã độc. Không chọn riêng những ví dụ thuận lợi cho E4.
- Gần ngưỡng `5660d19076f71fb9…`: nhãn Benign; E1 có p=0,237584 vượt ngưỡng 0,228097 và báo nhầm; E4 có p=0,006316 dưới ngưỡng 0,067051 và dự đoán lành.

Minh chứng: `results/errors_all.csv`, `errors_by_source.csv`, `error_feature_profiles.csv`, JSON của từng APK và các hình SHAP trong `results/figures`.

## 3. Va chạm vector và giới hạn tổng quát

Với đủ 163 biến, có 630 nhóm vector lặp chứa 6.512 APK; một nhóm có cả hai nhãn. Có 130 nhóm vector chung giữa fit và test, liên quan 1.237 mẫu test. Khi đối chiếu cả fit, calibration và validation, 1.306/3.268 mẫu test có vector đã xuất hiện trong ít nhất một tập phát triển.

Với riêng 76 biến quyền, có 771 nhóm lặp chứa 8.272 APK, trong đó 26 nhóm có hai nhãn. Điều này cho thấy bộ quyền phân biệt các APK hạn chế hơn bộ đầy đủ.

Vector giống nhau không tự chứng minh mã nguồn APK trùng nhau hoặc giao thức đã rò rỉ nhãn. Dù package không giao nhau, bộ biểu diễn có thể ánh xạ các APK khác nhau về cùng vector. Chỉ số rất cao cần được đọc cùng giới hạn này.

Phân tích hậu nghiệm trên phần test có vector chưa xuất hiện ở bất kỳ tập phát triển nào:
- full_163, E1_P__RF: 1962 mẫu; F1 97,02%, Recall 97,79%, FPR 6,90%.
- full_163, E4_PCIAB__RF: 1962 mẫu; F1 98,75%, Recall 99,68%, FPR 4,02%.
- permissions_76, E1_P__RF: 1172 mẫu; F1 95,60%, Recall 96,08%, FPR 7,04%.
- permissions_76, E4_PCIAB__RF: 1172 mẫu; F1 98,21%, Recall 99,56%, FPR 4,55%.

Các tập con trên được xác định sau khi xem kết quả, có phân bố khác toàn bộ test và không phải bộ dữ liệu ngoài nguồn. Chúng là kiểm tra độ nhạy bổ sung, không thay thế đánh giá độc lập.

Giới hạn còn lại: nhãn kế thừa CIC; loại Riskware; Banking chỉ trích xuất đạt 79,01%; chưa đánh giá theo thời gian/họ mã độc; chưa có bộ APK ngoài CIC với nhãn chuẩn; chưa phân tích hành vi thực thi. Không gọi kết quả này là phát hiện zero-day hoặc khả năng phát hiện mã độc Android hiện tại ngoài phân bố nghiên cứu.

## 4. Bốn thí nghiệm bổ sung đã chạy

Kế hoạch lưu trước khi fit ở `results/supplementary/plan.json`. Mỗi biến thể dùng RF 300 cây, max_depth=20, min_samples_leaf=5, max_features=0,5; cùng các tập và 5 fold bên trong fit. Học mô hình trên fit, sigmoid trên calibration, chọn ngưỡng trên validation với FPR thực nghiệm không quá 5%. Tổng cộng 20 lượt fit CV và 4 lượt fit mô hình cuối, cộng 4 bước học calibrator.

Test lịch sử đã được biết trước khi đề xuất các thí nghiệm này. Kết quả được ghi là thăm dò/độ nhạy, không phải một thử nghiệm xác nhận mù. Không chọn lại mô hình chính theo kết quả này.

### S1 — Bộ quyền bỏ p_custom_count và p_total_count

AP CV: 0.992236 ± 0.001818. Test: F1 97,72%, Recall 97,37%, FPR 6,29%; FP=48, FN=66.

### S2 — Bộ đầy đủ bỏ p_custom_count và p_total_count

AP CV: 0.998279 ± 0.000364. Test: F1 99,15%, Recall 99,64%, FPR 4,46%; FP=34, FN=9.

### S3 — Bộ đầy đủ chỉ giữ API nhị phân, bỏ 12 biến log-count

AP CV: 0.997390 ± 0.000653. Test: F1 99,15%, Recall 99,60%, FPR 4,33%; FP=33, FN=10.

### S4 — Chỉ dùng 17 chỉ báo B_core

AP CV: 0.977658 ± 0.003581. Test: F1 96,60%, Recall 94,57%, FPR 4,06%; FP=31, FN=136.

Bỏ p_total_count cùng p_custom_count là cần thiết để tránh khôi phục trực tiếp số quyền tùy biến từ tổng quyền và số quyền nền tảng. Việc này chưa loại được mọi biến tương quan với nguồn ứng dụng.

Cách diễn giải:

- S1 giảm 3 báo nhầm nhưng tăng 21 bỏ sót so với E1. Không đủ căn cứ chọn biến thể này chỉ vì FPR giảm nhẹ.
- S2 có AP và F1 gần E4 nhưng tăng 5 báo nhầm và giảm 1 bỏ sót. Kết quả quan sát không cho thấy lợi ích của việc bỏ hai thống kê này trong cấu hình đã thử.
- S3 giữ số bỏ sót bằng E4 và tăng 4 báo nhầm. Thông tin số điểm gọi có lợi ích nhỏ quan sát được ở cấu hình này; chưa có kiểm định riêng để khẳng định ý nghĩa thống kê.
- S4 bỏ sót 136 mẫu. B_core hỗ trợ biểu diễn/diễn giải nhưng không đủ thay toàn bộ quyền, API, component và intent.

Không khẳng định các chênh lệch nhỏ có ý nghĩa thống kê vì thí nghiệm bổ sung này chưa tính khoảng tin cậy ghép cặp. Tham số được giữ cố định để so sánh tác động thay đổi đầu vào, không phải tìm cấu hình tối ưu cho từng biến thể.

## 5. Lý do lựa chọn mô hình khi trình bày

E1–RF vẫn là hệ thống chính của lần thực nghiệm đã đăng ký: AP CV 0,993606 nằm trong dải chênh 0,005 so với tốt nhất, và chỉ giữ 60 biến sau lọc. Quy tắc này là chính sách ưu tiên sự gọn nhẹ, không phải kiểm định tương đương thống kê.

E4–RF có kết quả test quan sát tốt hơn và được đưa lên giao diện để so sánh. Không gọi E1 là tốt nhất tuyệt đối; không đổi lịch sử lựa chọn mô hình sau khi thấy test. Nếu chọn E4 cho một phiên bản triển khai tiếp theo, cần ghi rõ quyết định mới và kiểm chứng trên dữ liệu độc lập.

Giao diện hiện trích đủ 163 biến để đối chiếu hai mô hình trên cùng APK. Vì vậy demo này chưa chứng minh một đường chạy E1 chỉ đọc manifest có độ bao phủ hoặc tốc độ tốt hơn. Thời gian toàn quy trình đã bao gồm hai mô hình và SHAP; không so trực tiếp với số microsecond suy luận vector trong báo cáo cũ.

## 6. Đoạn kết luận có thể đưa vào bản lần 3

Trong đợt hoàn thiện lần 3, đồ án bổ sung giao diện trình diễn và kiểm thử trực tiếp chuỗi APK–trích xuất–dự đoán–giải thích. Bảy lượt kiểm thử APK hoàn thành xử lý, trong đó năm APK của tập test tái tạo đúng đặc trưng và kết quả đã công bố; tám ca đầu vào lỗi được từ chối đúng mà không sinh nhãn phân loại. Hai APK pilot ngoài tập dữ liệu đã khóa được xử lý thành công nhưng chưa có nhãn chuẩn độc lập, nên chỉ dùng làm minh chứng chức năng.

Phân tích lỗi cho thấy phần lớn mẫu bị E1–RF bỏ sót thuộc nhóm Banking. Kiểm tra va chạm vector phát hiện các biểu diễn giống nhau giữa tập phát triển và test dù nhóm package không giao nhau; các chỉ số trên phần test có vector chưa gặp đã được báo cáo bổ sung. Bốn thí nghiệm độ nhạy cho thấy loại thống kê quyền tùy biến không tạo cải thiện đồng đều, còn chỉ sử dụng B_core làm tăng đáng kể số mẫu bỏ sót. Những kết quả này củng cố yêu cầu diễn giải mô hình trong phạm vi dữ liệu và bộ biểu diễn đã khảo sát.

Đồ án đã bổ sung bằng chứng về khả năng vận hành của module và phân tích hạn chế. Kết quả chưa đủ để khẳng định khả năng tổng quát trên APK ngoài CIC có nhãn chuẩn hoặc theo thời gian. E1–RF vẫn là hệ thống chính theo giao thức ban đầu, với FPR test 6,68%; E4–RF là phương án so sánh có kết quả quan sát tốt hơn và cần đánh giá độc lập trước khi khẳng định ưu thế triển khai.

## 7. Phần còn cần bạn thực hiện

- Tự chạy lại kịch bản trong HUONG_DAN_TRINH_DIEN.md để nắm thao tác và giải thích kết quả.
- Chụp các màn hình thực tế theo danh sách trong hướng dẫn; giữ JSON tương ứng.
- Nếu có APK bên ngoài với nhãn/bằng chứng đáng tin cậy, bổ sung một đợt đánh giá độc lập. Không tự gán mọi ứng dụng tải được là lành tính.
- Chọn nội dung và hình đưa vào Chương 3; quyển báo cáo chưa được chỉnh sửa trong đợt này.
