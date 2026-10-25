"""Presentation interface for the verified progress-3 experiment."""
from pathlib import Path
import hashlib
import json
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pandas as pd
import streamlit as st
from common import ROOT, OUT, RUN, MODEL_IDS, now, read_json, save_json, analyse_apk

st.set_page_config(page_title='Phát hiện mã độc Android | Đồ án', page_icon='🔎', layout='wide')
st.title('Phát hiện mã độc Android')
st.caption('Phan Văn Tùng · AT190357 · Quyền và chỉ báo hành vi tĩnh')
page = st.sidebar.radio('Nội dung', ['Phân tích APK', 'Kết quả thực nghiệm', 'Kiểm thử và minh chứng', 'Minh chứng đã lưu'])
st.sidebar.markdown('**Mô hình trình diễn**')
st.sidebar.write('E1–RF: mô hình chính đã chọn bằng kiểm định chéo.\n\nE4–RF: mô hình so sánh có thêm API, cấu trúc và chỉ báo kết hợp.')
st.sidebar.caption('Ứng dụng đọc manifest và DEX. Các APK được phân tích tĩnh.')


def percent(value):
    return f'{100 * float(value):.2f}%'


def display_result(value, historical=False):
    record = value['record']
    st.subheader('Kết quả đã lưu từ lần kiểm thử trước' if historical else 'Kết quả của APK vừa phân tích')
    st.write(f'**Tệp:** {value["input_name"]}')
    st.caption('Thời điểm: ' + value['started_at'] + (' · Đang xem bản ghi cũ; không trích xuất APK trong lần xem này.' if historical else ' · Mỗi lần bấm phân tích đều đọc lại APK.'))
    st.code(record.get('sha256') or 'Không có SHA-256', language=None)
    if record['status'] != 'ok':
        st.warning('Không đủ dữ liệu để đánh giá. APK này không được gán nhãn lành tính hoặc mã độc.')
        st.write('Trạng thái:', record['status'], '· Mã lỗi:', record.get('error_code'))
        with st.expander('Chi tiết xử lý'):
            st.json(record)
    else:
        a, b, c = st.columns(3)
        a.metric('Tên gói', record.get('package_name') or 'Không xác định')
        b.metric('Đặc trưng trích xuất', len(record['features']))
        c.metric('Thời gian toàn quy trình', f'{value["wall_seconds_including_two_models_and_explanations"]:.2f} giây')
        st.caption('Thời gian được ghi nhận trên máy thực hiện lần phân tích tương ứng, gồm trích xuất, hai mô hình và giải thích.')
        columns = st.columns(2)
        for column, model_id, title in zip(columns, MODEL_IDS, ['E1–RF · Mô hình chính', 'E4–RF · Mô hình so sánh']):
            p = value['predictions'][model_id]
            with column:
                st.markdown('#### ' + title)
                st.markdown('**Dự đoán mã độc**' if p['predicted_label'] else '**Dự đoán lành tính**')
                st.metric('Điểm cho lớp mã độc', percent(p['p_malware']))
                st.write('Ngưỡng quyết định:', f'{p["threshold"]:.6f}' if p['threshold'] is not None else '+∞')
        st.caption('Điểm là đầu ra xác suất đã hiệu chỉnh của mô hình trong phạm vi nghiên cứu; dự đoán lành tính không bảo đảm APK an toàn.')
        case = value.get('case') or {}
        if case:
            if case.get('label_true') is None:
                st.info('Mẫu trình diễn chưa có nhãn chuẩn được xác minh. Kết quả này dùng kiểm tra chức năng, không tính độ chính xác.')
            else:
                st.write('**Nhãn nguồn để đối chiếu:**', 'Mã độc' if case['label_true'] else 'Lành tính',
                         '· Nhóm nguồn:', case.get('source_label'), '· Tập:', case.get('split'))
                st.caption('Nhãn nguồn được hiển thị sau dự đoán và không được đưa vào mô hình.')
        explain_model = st.selectbox('Xem giải thích cho', MODEL_IDS,
                                     format_func=lambda m: 'E1–RF' if m == MODEL_IDS[0] else 'E4–RF', key='explanation_model')
        explanation = value['predictions'][explain_model]['explanation']
        st.subheader('Đặc trưng ảnh hưởng đến dự đoán')
        st.caption('TreeSHAP giải thích xác suất của Random Forest nền, trước bước hiệu chỉnh sigmoid. Dấu dương đẩy điểm về phía mã độc; dấu âm kéo điểm xuống.')
        rows = explanation.get('top_five_contributions', [])
        if rows:
            table = pd.DataFrame([{'Đặc trưng': r['feature'], 'Giá trị đầu vào': r['extracted_feature_value'],
                                   'Đóng góp SHAP': r['contribution']} for r in rows])
            st.bar_chart(table.set_index('Đặc trưng')['Đóng góp SHAP'], horizontal=True, color='#315b7b')
            st.dataframe(table, hide_index=True, use_container_width=True)
            st.caption(f'Giá trị nền: {explanation["base_value"]:.6f} · Đầu ra RF nền: {explanation["base_output"]:.6f} · Sai số cộng toàn bộ đóng góp: {explanation["additivity_absolute_residual"]:.2e}. Hình chỉ hiển thị 5 đóng góp lớn nhất.')
        with st.expander('Đặc trưng và bằng chứng manifest / DEX'):
            features = record['features']
            st.dataframe(pd.DataFrame([{'Đặc trưng': k, 'Giá trị': v} for k,v in features.items() if v != 0]),
                         hide_index=True, use_container_width=True)
            st.json(record.get('evidence', {}))
    st.download_button('Tải kết quả và minh chứng JSON', json.dumps(value, ensure_ascii=False, indent=2),
                       file_name=f'ket_qua_{(record.get("sha256") or "loi")[:16]}.json', mime='application/json')


if page == 'Phân tích APK':
    st.write('Đưa một tệp APK qua bộ trích xuất và hai mô hình đã được kiểm tra với kết quả thực nghiệm.')
    st.info('Bộ bàn giao không kèm APK. Tải APK của bạn để phân tích mới, hoặc chọn “Minh chứng đã lưu” để xem các lần kiểm thử trước.')
    plan_path = OUT / 'apk_checks/plan.json'
    selected_case, selected_path, fingerprint = None, None, None
    upload = st.file_uploader('Chọn tệp APK đơn, tối đa 200 MiB', type=['apk'])
    if upload is not None:
        fingerprint = 'upload:' + upload.name + ':' + hashlib.sha256(upload.getbuffer()).hexdigest()
    if st.button('Phân tích APK từ đầu', type='primary', disabled=fingerprint is None):
        try:
            with st.spinner('Đang trích xuất manifest, DEX, dự đoán và tạo giải thích…'):
                if selected_path is not None:
                    value = analyse_apk(selected_path)
                    value['case'] = selected_case
                else:
                    with tempfile.TemporaryDirectory(prefix='progress3_upload_') as folder:
                        path = Path(folder) / 'input.apk'
                        path.write_bytes(upload.getbuffer())
                        value = analyse_apk(path)
                        value['input_name'] = upload.name
                        known_cases = read_json(plan_path)['cases'] if plan_path.exists() else []
                        value['case'] = next((c for c in known_cases if c.get('sha256') and c['sha256'] == value['record'].get('sha256')),
                                             {'label_true': None, 'source_label': 'UNLABELED', 'split': 'unverified_upload'})
                digest = (value['record'].get('sha256') or 'error')[:16]
                stamp = value['started_at'].replace(':','').replace('+','_')
                save_json(OUT / 'live_runs' / f'{stamp}_{digest}.json', value)
                st.session_state['live_result'] = value
                st.session_state['input_fingerprint'] = fingerprint
        except Exception as exc:
            st.error('Không hoàn thành lần phân tích: ' + str(exc))
            st.session_state.pop('live_result', None)
    if fingerprint is not None and st.session_state.get('input_fingerprint') == fingerprint and 'live_result' in st.session_state:
        display_result(st.session_state['live_result'])

elif page == 'Kết quả thực nghiệm':
    integrity_path = OUT / 'integrity.json'
    if integrity_path.exists():
        integrity = read_json(integrity_path)
        st.info('Bản ghi kiểm tra trước đây: checksum dữ liệu, mã nguồn, 16 mô hình và dự đoán E1–RF / E4–RF trên 3.268 mẫu test. Trang này hiển thị kết quả đã lưu; dùng verify_package.py để kiểm tra bộ bàn giao hiện tại.')
        st.caption('Thời điểm kiểm tra: ' + integrity['checked_at'])
    st.subheader('Kết quả chính đã báo cáo')
    original = pd.read_csv(RUN / 'test_metrics.csv')
    selected = original[original.model_id.isin(MODEL_IDS)]
    wanted = [k for k in ['model_id','accuracy','precision','recall','f1','fpr','average_precision'] if k in selected]
    st.dataframe(selected[wanted], hide_index=True, use_container_width=True)
    st.caption('Chỉ số trong bảng ở thang 0–1. Nguồn: tập test CIC đã khóa. E1–RF được chọn bằng CV; E4–RF dùng so sánh.')
    source_path = OUT / 'errors_by_source.csv'
    if source_path.exists():
        st.subheader('Báo nhầm và bỏ sót theo nhóm nguồn')
        st.dataframe(pd.read_csv(source_path), hide_index=True, use_container_width=True)
    supplement = OUT / 'supplementary/metrics.csv'
    if supplement.exists():
        st.subheader('Thí nghiệm bổ sung lần 3')
        st.warning('Đây là phân tích độ nhạy sau khi đã biết kết quả test cũ. Chưa phải đánh giá độc lập trên bộ dữ liệu mới.')
        data = pd.read_csv(supplement)
        st.dataframe(data[['variant','n_features','cv_ap_mean','recall','f1','fpr','delta_fpr']], hide_index=True, use_container_width=True)
        st.caption('Bỏ đồng thời p_custom_count và p_total_count để tránh suy ra lại số quyền tùy biến qua tổng quyền. Các đặc trưng tương quan khác vẫn có thể tồn tại.')
    overlap = OUT / 'cross_split_vectors.csv'
    if overlap.exists():
        with st.expander('Giới hạn dữ liệu: vector giống nhau giữa các tập'):
            st.dataframe(pd.read_csv(overlap), hide_index=True, use_container_width=True)
            st.caption('Vector giống nhau không tự chứng minh APK trùng mã. Chia theo package không bảo đảm mọi vector ở test khác fit.')

elif page == 'Kiểm thử và minh chứng':
    st.subheader('Kết quả kiểm thử APK đã thực hiện')
    summary = OUT / 'apk_checks/complete.json'
    if summary.exists():
        data = read_json(summary)
        a,b = st.columns(2)
        a.metric('APK xử lý và đối chiếu đạt', f'{data["apk_passed"]}/{data["apk_cases"]}')
        b.metric('Ca lỗi được từ chối đúng', f'{data["negative_passed"]}/{data["negative_cases"]}')
        st.caption('Thời điểm ghi nhận: ' + data['completed_at'])
        st.caption('“Đạt” là đạt kiểm thử chức năng / tính nhất quán. Mẫu FP và FN vẫn giữ kết quả dự đoán sai của mô hình.')
    for name, title in [('cases.csv','Các APK đã chạy'), ('negative_cases.csv','Các trường hợp lỗi')]:
        path = OUT / 'apk_checks' / name
        if path.exists():
            st.markdown('**' + title + '**')
            st.dataframe(pd.read_csv(path), hide_index=True, use_container_width=True)
    st.write('Bản ghi JSON được lưu trong results/apk_checks và results/live_runs. Hướng dẫn bàn giao nằm trong README.md và docs/HUONG_DAN_HOI_DONG.md.')

else:
    st.info('Đây là minh chứng lịch sử, không phải lần chạy mới. APK gốc không nằm trong bộ bàn giao.')
    cases = [c for c in read_json(OUT / 'apk_checks/plan.json')['cases']
             if (OUT / 'apk_checks' / (c['case_id'] + '.json')).is_file()]
    selected = st.selectbox('Chọn bản ghi', [c['case_id'] for c in cases])
    display_result(read_json(OUT / 'apk_checks' / (selected + '.json')), historical=True)
