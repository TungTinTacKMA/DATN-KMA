# Phạm vi dữ liệu đi kèm

`dataset/` chứa ma trận đặc trưng, nhãn, danh sách mẫu, audit và `dataset_lock.json`. Các tệp được sao chép nguyên byte để đối chiếu với SHA-256 đã khóa. `samples.csv` giữ nguồn CICMalDroid2020, nhóm nguồn, nhãn, tên gói và đường dẫn tương đối lịch sử.

**Không kèm:** `dataset/evidence.jsonl` (khoảng 570 MB theo byte thập phân), APK gốc, archive nguồn, các bản trích xuất từng APK và hồ sơ nguồn đầy đủ. Các đường dẫn này có thể xuất hiện trong metadata; chúng là dấu vết nghiên cứu, không có nghĩa các tệp đó có trong bộ GitHub.

`verify_package.py --predictions` xác minh phần dữ liệu hiện có và tái tạo dự đoán từ ma trận. Nó ghi rõ không xác minh đầy đủ nguồn APK và chuỗi trích xuất.

Hàm nghiên cứu gốc `androidml.dataset.load_dataset` vẫn yêu cầu đủ mọi tệp trong khóa, bao gồm `evidence.jsonl`; vì vậy huấn luyện/kiểm tra đầy đủ không chạy chỉ với snapshot gọn. Không sửa khóa hoặc bỏ kiểm tra trong mã nghiên cứu để che việc thiếu dữ liệu.

Muốn chạy lại đầy đủ, khôi phục `evidence.jsonl` đúng checksum trong khóa và kho dữ liệu nguồn tương ứng từ bản lưu nghiên cứu. Để chạy lại `run_apk_checks.py`, còn cần các APK được ghi trong danh sách mẫu, `data/extracted/` và hai APK pilot trong `data/pilot_apks/`. Script giữ kết quả cũ khi đã có `complete.json`; nếu cần kiểm thử lại, thực hiện trong một bản sao riêng để bảo toàn minh chứng lịch sử.

Bản này giữ thông tin nguồn và các thông báo gốc; không tự cấp giấy phép mới cho dữ liệu hoặc mã nguồn bên thứ ba. Không dùng bảng nhãn đã trích xuất để suy ra rằng mọi APK ngoài bộ dữ liệu đều được xác minh nhãn.
