# Đồ án: Phát hiện mã độc Android bằng học máy

**Phan Văn Tùng — AT190357 — AT19CT**  
GVHD: ThS. Nguyễn Quách Duy Anh — Học viện Kỹ thuật Mật mã.

**Trạng thái: đang hoàn thiện.** Đây là bộ mã nguồn, sản phẩm và minh chứng được tập hợp ngày 25/10/2026 để chuẩn bị báo cáo cuối cùng. Quyển Word đi kèm là **bản báo cáo lần 2**, chưa phải quyển hoàn chỉnh đã được giảng viên duyệt. Các kết quả nghiên cứu và kiểm thử lịch sử giữ nguyên thời điểm ghi nhận.

Ứng dụng phân tích tĩnh manifest/DEX của APK, trích xuất 163 đặc trưng, dự đoán bằng Random Forest và trình bày giải thích SHAP. E1–RF là hệ thống chính được chọn bằng kiểm định chéo; E4–RF dùng đối chiếu. Đây là sản phẩm nghiên cứu; chỉ báo hành vi được suy ra từ phân tích tĩnh.

## Chạy sản phẩm trên Windows

Cần Python **3.11**. Mở thư mục này, chạy lần lượt:

1. `CAI_DAT.cmd` — tạo môi trường cục bộ và cài thư viện.
2. `MO_SAN_PHAM.cmd` — chạy demo, sau đó mở <http://127.0.0.1:8501>.
3. `KIEM_TRA.cmd` — kiểm tra checksum, tái tạo dự đoán E1/E4 trên 3.268 mẫu test và chạy các kiểm thử bàn giao.

Lệnh tương đương trong PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install --no-deps -e .
.\.venv\Scripts\python.exe verify_package.py --predictions
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

Demo không phụ thuộc đường dẫn ổ đĩa của máy phát triển. Phần **Phân tích APK** nhận APK người dùng tải lên. Phần **Minh chứng đã lưu** hiển thị kết quả cũ và không được trình bày như một lần chạy mới. Kho bàn giao không có APK. Chỉ nạp các mô hình joblib đi kèm từ nguồn tin cậy.

## Các thư mục quan trọng

- `src/androidml/`: mã trích xuất, đặc trưng, dữ liệu, huấn luyện, đánh giá và giải thích; giữ nguyên byte của bản nghiên cứu đã khóa.
- `configs/`: thiết lập thí nghiệm, định nghĩa 163 đặc trưng và nguồn đối chiếu quyền/thành phần Android.
- `data/dataset/`: ma trận đặc trưng, nhãn, danh sách mẫu, audit và khóa dữ liệu; đủ để đối chiếu dự đoán đã lưu. Không kèm `evidence.jsonl` và APK gốc.
- `outputs/`: 16 mô hình chính, CV, phân chia dữ liệu, dự đoán test, chỉ số, biểu đồ, giải thích và các manifest kiểm tra toàn vẹn.
- `results/`: phân tích mẫu sai, giới hạn dữ liệu, bốn thí nghiệm bổ sung, bản ghi kiểm thử APK và hình phục vụ báo cáo lần 3.
- `docs/`: bản Word lần 2, kết quả/kết luận bổ sung, ảnh minh chứng, hướng dẫn hội đồng và danh sách việc còn thiếu.
- `tests/`: kiểm thử bản bàn giao về giao diện, đối chiếu suy luận và từ chối tệp APK lỗi.

`app.py`/`common.py` là lớp demo đã điều chỉnh đường dẫn cho bộ bàn giao. `verify_package.py` kiểm tra dữ liệu gọn và hiện trạng đóng gói. `.gitattributes` giữ nguyên byte khi đưa lên Git; đổi kết thúc dòng của mã nguồn đã khóa sẽ làm sai checksum.

## Phạm vi tái lập

- Có thể kiểm tra checksum các tệp đi kèm và tái tạo dự đoán E1/E4 từ ma trận đặc trưng có sẵn mà không huấn luyện lại.
- Có thể phân tích APK mới do người trình diễn cung cấp; không cài đặt hay chạy mã APK.
- Chưa thể tái lập toàn bộ chuỗi **kho APK gốc → trích xuất toàn bộ dữ liệu → huấn luyện lại** chỉ bằng thư mục này. Kho gốc, metadata nguồn và `evidence.jsonl` được giữ ngoài bộ GitHub.
- `run_analysis.py` và `run_apk_checks.py` giữ mã thực hiện phân tích/kiểm thử lần 3 để đọc và tham khảo. Muốn chạy lại đầy đủ cần khôi phục dữ liệu gốc theo [phạm vi dữ liệu](data/README.md); chúng không phải bước bắt buộc để mở demo. Một số hàm nghiên cứu gốc giữ quy ước đường dẫn Windows.
- `requirements.txt` ghim các thư viện chính. `requirements-lock.txt` là bản ghi phụ thuộc của môi trường nghiên cứu để tham khảo, không khẳng định cài mới đã được thử trên mọi máy.

Bốn thí nghiệm bổ sung là phân tích thăm dò sau khi đã xem test cũ. Bảy APK đạt kiểm thử chức năng không đồng nghĩa với bảy dự đoán đều đúng; các mẫu FP/FN vẫn là dự đoán sai. Không dùng hai APK pilot chưa xác minh nhãn để tính độ chính xác.

## Tài liệu cho hội đồng và phần còn thiếu

Bắt đầu từ [hướng dẫn xem sản phẩm và minh chứng](docs/HUONG_DAN_HOI_DONG.md), [trạng thái hoàn thiện](docs/TRANG_THAI_BAN_GIAO.md) và [bản thảo Word lần 2](docs/BAO_CAO_BAN_THAO_LAN_2.docx).

## Đưa lên GitHub

Tạo repository từ **chính thư mục này**, đưa cả các tệp ẩn `.gitignore`, `.gitattributes` và `.streamlit/config.toml` lên cùng. Không chọn thư mục đồ án cha vì có nhiều dữ liệu và sản phẩm không thuộc bộ bàn giao. Chưa tạo repository hoặc đẩy lên tài khoản GitHub trong lần tập hợp này.

`PACKAGE_MANIFEST.json` ghi SHA-256 của bản bàn giao ban đầu. Khi chủ động sửa nội dung để hoàn thiện đồ án, checksum cũ sẽ báo thay đổi; lưu lại lịch sử thay đổi và tạo manifest mới sau khi kiểm tra phiên bản mới. Đây là bảng đối chiếu toàn vẹn, không phải chữ ký số xác minh tác giả.
