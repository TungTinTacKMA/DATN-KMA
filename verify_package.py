"""Check the handover snapshot; optionally reproduce predictions, without retraining.

The raw APK corpus and evidence.jsonl are intentionally absent. This verifies the
included artifacts, not the full extraction provenance of the original dataset.
"""
import argparse
import json
from pathlib import Path
from common import ROOT, RUN, DATA, SPLITS, OUT, MODEL_IDS, read_json, sha_file, now, save_json


def require(ok, message):
    if not ok:
        raise ValueError(message)


def check_hash(path, digest):
    require(path.is_file(), 'Missing file: ' + str(path))
    require(sha_file(path) == digest, 'SHA-256 mismatch: ' + str(path))


def canonical_id(value, key):
    import hashlib
    content = {k: v for k, v in value.items() if k != key}
    actual = hashlib.sha256(json.dumps(content, sort_keys=True, ensure_ascii=False,
                                      separators=(',', ':')).encode()).hexdigest()
    require(actual == value[key], 'Invalid ' + key)


def verify_files():
    manifest = read_json(ROOT / 'PACKAGE_MANIFEST.json')
    for name, entry in manifest['files'].items():
        check_hash(ROOT / name, entry['sha256'])
    freeze = read_json(RUN / 'freeze.json')
    canonical_id(freeze, 'freeze_id')
    for name, digest in freeze['source_hashes'].items():
        check_hash(ROOT / name.replace('\\', '/'), digest)
    for name, digest in freeze['models'].items():
        check_hash(RUN / name, digest)
    for name, key in [('model_cards.json', 'cards_sha256'), ('cv_results.csv', 'cv_sha256'),
                      ('environment.json', 'environment_sha256')]:
        check_hash(RUN / name, freeze[key])
    check_hash(ROOT / 'configs/experiment.json', freeze['config_sha256'])
    require(read_json(RUN / 'registered_config.json') == read_json(ROOT / 'configs/experiment.json'),
            'Registered configuration differs')
    evaluation = read_json(RUN / 'evaluation_complete.json')
    require(evaluation['freeze_id'] == freeze['freeze_id'], 'Evaluation freeze differs')
    for name, digest in evaluation['files'].items():
        check_hash(RUN / name, digest)
    lock = read_json(DATA / 'dataset_lock.json')
    canonical_id(lock, 'dataset_id')
    split = read_json(SPLITS / 'splits.json')
    canonical_id(split, 'split_id')
    require(lock['dataset_id'] == split['dataset_id'] == freeze['dataset_id'], 'Dataset IDs differ')
    require(split['split_id'] == freeze['split_id'], 'Split IDs differ')
    omitted = []
    for name, digest in lock['files'].items():
        if name == 'evidence.jsonl' and not (DATA / name).exists():
            omitted.append('data/dataset/' + name)
        else:
            check_hash(DATA / name, digest)
    for name, digest in read_json(OUT / 'supplementary/complete.json')['files'].items():
        check_hash(OUT / 'supplementary' / name, digest)
    return {'checked_at': now(), 'package_files_verified': len(manifest['files']),
            'main_models_verified': len(freeze['models']), 'supplementary_models_verified': 4,
            'omitted_locked_files': omitted, 'raw_apk_provenance_verified': False,
            'scope': 'Included snapshot hashes; raw APKs and full extraction evidence are not included.'}


def reproduce_predictions():
    import joblib
    import numpy as np
    import pandas as pd
    import sklearn
    from scipy import sparse
    from androidml.features import FEATURE_NAMES, SCHEMA_HASH
    require(sklearn.__version__ == '1.5.2', 'Use scikit-learn==1.5.2')
    X = sparse.load_npz(DATA / 'dataset.npz')
    y = np.load(DATA / 'labels.npy', allow_pickle=False)
    samples = pd.read_csv(DATA / 'samples.csv', keep_default_na=False)
    require(X.shape == (len(samples), len(FEATURE_NAMES)), 'Matrix shape differs')
    require(np.array_equal(y, samples.label_binary.to_numpy()), 'Labels differ')
    require(not samples.sha256.duplicated().any(), 'Duplicate sample hash')
    test = read_json(SPLITS / 'splits.json')['partitions']['test']
    indices = samples.reset_index().set_index('sha256').loc[test, 'index'].to_numpy()
    predictions = pd.read_csv(RUN / 'test_predictions.csv')
    differences = {}
    for model_id in MODEL_IDS:
        bundle = joblib.load(RUN / 'models' / (model_id + '.joblib'))
        require(bundle['schema_hash'] == SCHEMA_HASH and bundle['feature_names'] == list(FEATURE_NAMES), 'Schema differs')
        old = predictions[predictions.model_id == model_id].set_index('sha256').loc[test]
        p = bundle['calibrator'].predict_proba(X[indices][:, bundle['columns']])[:, 1]
        delta = float(np.max(np.abs(p - old.p_malware.to_numpy())))
        require(delta <= 1e-12, 'Probabilities differ: ' + model_id)
        require(np.array_equal(y[indices], old.label_true.to_numpy()), 'Test labels differ')
        require(np.array_equal(p >= bundle['threshold'], old.label_predicted.to_numpy()), 'Predicted labels differ')
        differences[model_id] = {'test_samples': len(test), 'max_probability_difference': delta}
    return differences


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--predictions', action='store_true', help='Reproduce E1/E4 predictions from included matrix')
    args = parser.parse_args()
    report = verify_files()
    if args.predictions:
        report['prediction_reproduction'] = reproduce_predictions()
    save_json(OUT / 'package_verification.json', report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
