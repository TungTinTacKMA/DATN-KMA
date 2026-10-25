from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, OUT, MODEL_IDS, analyse_apk, read_json, trusted_model
from streamlit.testing.v1 import AppTest


def test_app_pages_work_without_original_apks():
    view = AppTest.from_file(str(ROOT / 'app.py'), default_timeout=60).run()
    assert not view.exception
    assert view.button[0].disabled
    for page in ('Kết quả thực nghiệm', 'Kiểm thử và minh chứng', 'Minh chứng đã lưu'):
        view.sidebar.radio[0].set_value(page).run()
        assert not view.exception
    assert any('không phải lần chạy mới' in item.value for item in view.info)
    assert any('Kết quả đã lưu' in item.value for item in view.subheader)
    view.selectbox[0].set_value('PILOT_dozencalc_1').run()
    assert not view.exception
    assert any('chưa có nhãn chuẩn' in item.value for item in view.info)


def test_saved_record_inference_matches_both_models():
    from androidml.experiment import predict_record
    saved = read_json(OUT / 'apk_checks/FP.json')
    for model_id in MODEL_IDS:
        current = predict_record(saved['record'], trusted_model(model_id))
        old = saved['predictions'][model_id]
        assert abs(current['p_malware'] - old['p_malware']) < 1e-12
        assert current['predicted_label'] == old['predicted_label']


def test_invalid_apk_gets_no_classification(tmp_path):
    path = tmp_path / 'invalid.apk'
    path.write_bytes(b'This is an invalid archive, not an Android application.')
    result = analyse_apk(path)
    assert result['record']['status'] != 'ok'
    assert all(p['status'] == 'not_classified' and p['p_malware'] is None
               for p in result['predictions'].values())
