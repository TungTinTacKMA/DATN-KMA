"""Fresh static APK-to-result checks with retained evidence; never executes APK code."""
import copy
import csv
from pathlib import Path
import time
import zipfile
import numpy as np
import pandas as pd

from common import PROJECT, ROOT, OUT, RUN, DATA, SPLITS, MODEL_IDS, now, save_json, read_json, analyse_apk, trusted_model
from androidml.experiment import predict_record
from androidml.extract import extract_apk, sha256_file
from androidml.features import FEATURE_NAMES


def main():
    target = OUT / 'apk_checks'
    target.mkdir(parents=True, exist_ok=True)
    if (target / 'complete.json').exists():
        print('APK checks already complete. Evidence retained; use the app for a new run.', flush=True)
        return
    samples = pd.read_csv(DATA / 'samples.csv', keep_default_na=False).set_index('sha256')
    preds = pd.read_csv(RUN / 'test_predictions.csv')
    primary = preds[preds.model_id == MODEL_IDS[0]].copy()
    primary['outcome'] = np.where(primary.label_true == 1, np.where(primary.label_predicted == 1, 'TP', 'FN'),
                                  np.where(primary.label_predicted == 1, 'FP', 'TN'))
    primary['path'] = primary.sha256.map(lambda h: str(PROJECT / samples.loc[h, 'apk_path']))
    primary['available'] = primary.path.map(lambda p: Path(p).is_file())
    plans = []
    for tag in ('TP', 'TN', 'FP', 'FN'):
        eligible = primary[(primary.outcome == tag) & primary.available].sort_values('sha256')
        if eligible.empty:
            plans.append({'case_id': tag, 'blocked': True, 'reason': 'No accessible APK in category'})
        else:
            row = eligible.iloc[0]
            plans.append({'case_id': tag, 'path': row.path, 'sha256': row.sha256,
                          'source_label': samples.loc[row.sha256, 'source_label'], 'label_true': int(row.label_true),
                          'split': 'test', 'selection': 'Smallest SHA-256 among accessible APKs in original E1 outcome group.'})
    eligible = primary[primary.available].copy()
    eligible['distance'] = (eligible.p_malware - eligible.threshold).abs()
    if not eligible.empty:
        row = eligible.sort_values(['distance', 'sha256']).iloc[0]
        plans.append({'case_id': 'NEAR_THRESHOLD', 'path': row.path, 'sha256': row.sha256,
                      'source_label': samples.loc[row.sha256, 'source_label'], 'label_true': int(row.label_true),
                      'split': 'test', 'selection': 'Closest original E1 score to its fixed threshold, among accessible APKs.'})
    for name in ('dozencalc_1.apk', 'fdroid_1.23.2.apk'):
        path = PROJECT / 'data/pilot_apks' / name
        digest = sha256_file(path)
        plans.append({'case_id': 'PILOT_' + path.stem, 'path': str(path), 'sha256': digest,
                      'source_label': 'UNLABELED', 'label_true': None,
                      'split': 'outside_locked_dataset' if digest not in samples.index else 'dataset_overlap',
                      'selection': 'Existing local pilot; no verified benign/malware label. Functional check only.'})
    save_json(target / 'plan.json', {'created_at': now(), 'fresh_extraction': True, 'original_test_already_known': True,
              'cases': plans, 'classification_accuracy_claim': False})
    results, valid_record = [], None
    for plan in plans:
        if plan.get('blocked'):
            results.append({**plan, 'passed': False})
            continue
        print('Fresh APK check: ' + plan['case_id'], flush=True)
        try:
            value = analyse_apk(plan['path'])
            value['case'] = plan
            record = value['record']
            passed = record['status'] == 'ok' and record['sha256'] == plan['sha256']
            checks = {'fresh_status_ok': record['status'] == 'ok', 'sha256_matches_plan': record['sha256'] == plan['sha256']}
            if record['status'] == 'ok':
                valid_record = record
                if plan['split'] == 'test':
                    stored = read_json(PROJECT / 'data/extracted' / (plan['sha256'] + '.json'))
                    maxdiff = max(abs(record['features'][n] - stored['features'][n]) for n in FEATURE_NAMES)
                    checks['max_feature_difference_from_original'] = maxdiff
                    passed &= maxdiff <= 1e-6
                    for model_id in MODEL_IDS:
                        old = preds[(preds.model_id == model_id) & (preds.sha256 == plan['sha256'])].iloc[0]
                        current = value['predictions'][model_id]
                        delta = abs(current['p_malware'] - float(old.p_malware))
                        checks[model_id + '_probability_difference'] = delta
                        checks[model_id + '_label_matches_original'] = current['predicted_label'] == int(old.label_predicted)
                        passed &= delta <= 1e-12 and checks[model_id + '_label_matches_original']
            value['checks'] = checks
            value['passed'] = bool(passed)
            save_json(target / (plan['case_id'] + '.json'), value)
            row = {'case_id': plan['case_id'], 'sha256': plan['sha256'], 'source_label': plan['source_label'],
                   'label_true': plan['label_true'], 'split': plan['split'], 'status': record['status'],
                   'error_code': record.get('error_code'), 'passed': bool(passed),
                   'extraction_seconds': record['elapsed_seconds'],
                   'end_to_end_seconds': value['wall_seconds_including_two_models_and_explanations']}
            for model_id in MODEL_IDS:
                prediction = value['predictions'][model_id]
                row[model_id + '_p'] = prediction.get('p_malware')
                row[model_id + '_label'] = prediction.get('predicted_label')
            results.append(row)
            print(f'  status={record["status"]}; passed={passed}; time={row["end_to_end_seconds"]:.2f}s', flush=True)
        except Exception as exc:
            results.append({'case_id': plan['case_id'], 'passed': False, 'error': str(exc)})
            print('  ERROR: ' + str(exc), flush=True)
        pd.DataFrame(results).to_csv(target / 'cases.csv', index=False, encoding='utf-8-sig')

    fixtures = ROOT / 'fixtures'
    fixtures.mkdir(exist_ok=True)
    (fixtures / 'invalid.apk').write_text('This is a deliberately invalid APK fixture.', encoding='ascii')
    (fixtures / 'unsupported.txt').write_text('Unsupported-format fixture.', encoding='ascii')
    with zipfile.ZipFile(fixtures / 'missing_manifest.apk', 'w') as archive:
        archive.writestr('readme.txt', 'Missing AndroidManifest.xml fixture')
    pilot = PROJECT / 'data/pilot_apks/dozencalc_1.apk'
    with zipfile.ZipFile(pilot) as source, zipfile.ZipFile(fixtures / 'broken_dex.apk', 'w', zipfile.ZIP_DEFLATED) as output:
        for item in source.infolist():
            output.writestr(item.filename, b'not-valid-dex' if item.filename == 'classes.dex' else source.read(item.filename))
    negative_specs = [
        ('INVALID_ZIP', fixtures / 'invalid.apk', {}, {'failed'}),
        ('MISSING_MANIFEST', fixtures / 'missing_manifest.apk', {}, {'failed'}),
        ('UNSUPPORTED_FORMAT', fixtures / 'unsupported.txt', {}, {'unsupported'}),
        ('MISSING_FILE', fixtures / 'nonexistent.apk', {}, {'failed'}),
        ('SIZE_LIMIT', pilot, {'max_mb': 1}, {'unsupported'}),
        ('TIMEOUT', pilot, {'timeout': .001}, {'timeout'}),
        ('PARTIAL_DEX', fixtures / 'broken_dex.apk', {}, {'partial'}),
    ]
    negative = []
    for name, path, kwargs, expected in negative_specs:
        record = extract_apk(path, **kwargs)
        prediction = predict_record(record, trusted_model(MODEL_IDS[0]))
        passed = record['status'] in expected and prediction['status'] == 'not_classified' and prediction['predicted_label'] is None and prediction['p_malware'] is None
        row = {'case_id': name, 'passed': bool(passed), 'status': record['status'], 'error_code': record.get('error_code'),
               'expected_statuses': '|'.join(sorted(expected)), 'prediction_status': prediction['status']}
        negative.append(row)
        save_json(target / (name + '.json'), {'record': record, 'prediction': prediction, 'check': row})
    if valid_record:
        bad = copy.deepcopy(valid_record)
        bad['schema_hash'] = 'deliberately_incompatible_schema'
        try:
            predict_record(bad, trusted_model(MODEL_IDS[0]))
            row = {'case_id': 'SCHEMA_MISMATCH', 'passed': False, 'error_code': 'Unexpected acceptance'}
        except ValueError as exc:
            row = {'case_id': 'SCHEMA_MISMATCH', 'passed': 'incompatible' in str(exc), 'error_code': str(exc)}
        negative.append(row)
    pd.DataFrame(negative).to_csv(target / 'negative_cases.csv', index=False, encoding='utf-8-sig')
    summary = {'completed_at': now(), 'apk_cases': len(results), 'apk_passed': sum(bool(r.get('passed')) for r in results),
               'negative_cases': len(negative), 'negative_passed': sum(bool(r.get('passed')) for r in negative),
               'meaning_of_pass': 'Correct functional processing, repeatability or error rejection; not classification accuracy.',
               'external_labelled_evaluation': False}
    save_json(target / 'complete.json', summary)
    print(summary, flush=True)


if __name__ == '__main__':
    main()
