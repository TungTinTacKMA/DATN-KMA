"""Helpers for the progress-3 demo; original research artifacts remain authoritative."""
from pathlib import Path
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import sys

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT
sys.path.insert(0, str(PROJECT / 'src'))
OUT = ROOT / 'results'
RUN = PROJECT / 'outputs/runs/main'
DATA = PROJECT / 'data/dataset'
SPLITS = PROJECT / 'outputs/splits/main'
MODEL_IDS = ('E1_P__RF', 'E4_PCIAB__RF')


def now():
    return datetime.now(timezone(timedelta(hours=7))).isoformat(timespec='seconds')


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def trusted_model(model_id):
    if model_id not in MODEL_IDS:
        raise ValueError('Mô hình không nằm trong danh sách trình diễn đã kiểm tra.')
    freeze = read_json(RUN / 'freeze.json')
    path = RUN / 'models' / (model_id + '.joblib')
    if sha_file(path) != freeze['models']['models/' + path.name]:
        raise ValueError('Checksum mô hình không khớp bản thực nghiệm đã khóa.')
    for name, digest in freeze['source_hashes'].items():
        if sha_file(PROJECT / name.replace('\\', '/')) != digest:
            raise ValueError('Mã nguồn thực nghiệm thay đổi: ' + name)
    return path


def verified_dataset():
    from androidml.dataset import load_dataset
    from androidml.experiment import _load_splits, _verify_freeze
    X, y, samples, lock = load_dataset(DATA)
    split, partitions, inner = _load_splits(SPLITS, lock, samples)
    freeze = _verify_freeze(RUN, lock, split)
    evaluation = read_json(RUN / 'evaluation_complete.json')
    if evaluation['freeze_id'] != freeze['freeze_id'] or evaluation['synthetic']:
        raise ValueError('Evaluation manifest is incompatible.')
    for name, digest in evaluation['files'].items():
        if sha_file(RUN / name) != digest:
            raise ValueError('Evaluation artifact changed: ' + name)
    return X, y, samples, lock, split, partitions, inner, freeze


def analyse_apk(path, timeout=300):
    from androidml.extract import extract_apk
    from androidml.experiment import predict_record
    import time
    start = time.perf_counter()
    started_at = now()
    record = extract_apk(path, timeout=timeout)
    predictions = {}
    for model_id in MODEL_IDS:
        predictions[model_id] = predict_record(record, trusted_model(model_id))
    return {'started_at': started_at, 'input_name': Path(path).name, 'fresh_extraction': True,
            'record': record, 'predictions': predictions,
            'wall_seconds_including_two_models_and_explanations': time.perf_counter() - start,
            'scope': 'Static APK parsing only; no APK installation or execution.'}
