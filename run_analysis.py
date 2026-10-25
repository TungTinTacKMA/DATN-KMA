"""Verify the locked experiment, analyse errors, then run exploratory ablations."""
import os
for key in ('OMP_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS', 'NUMEXPR_NUM_THREADS'):
    os.environ[key] = '1'
from collections import Counter
from itertools import combinations
import hashlib
import json
import math
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import average_precision_score
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from common import OUT, RUN, ROOT, PROJECT, MODEL_IDS, now, read_json, save_json, sha_file, verified_dataset
from androidml.features import FEATURE_NAMES, GROUPS
from androidml.experiment import _pipeline, _fit_checked, _score, choose_threshold, threshold_metrics


def csv(name, rows):
    pd.DataFrame(rows).to_csv(OUT / name, index=False, encoding='utf-8-sig')


def metrics_or_empty(y, p, threshold):
    if len(y) == 0:
        return {'n': 0, 'note': 'No samples'}
    pred = p >= threshold
    result = {'n': len(y), 'benign': int((y == 0).sum()), 'malware': int((y == 1).sum()),
              'accuracy': float((pred == y).mean()), 'fp': int(((y == 0) & pred).sum()),
              'fn': int(((y == 1) & ~pred).sum())}
    if len(np.unique(y)) == 2:
        result.update(threshold_metrics(y, p, threshold))
    return result


def main():
    OUT.mkdir(exist_ok=True)
    (OUT / 'figures').mkdir(exist_ok=True)
    print('Verifying dataset, source, split, all 16 models and recorded results...', flush=True)
    X, y, samples, lock, split, parts, inner, freeze = verified_dataset()
    metadata = pd.DataFrame(samples)
    groups = metadata.group_id.to_numpy()
    test = parts['test']
    pred = pd.read_csv(RUN / 'test_predictions.csv')
    original_pred = {m: pred[pred.model_id == m].set_index('sha256').loc[metadata.iloc[test].sha256] for m in MODEL_IDS}
    integrity = {'checked_at': now(), 'dataset_id': lock['dataset_id'], 'split_id': split['split_id'],
                 'freeze_id': freeze['freeze_id'], 'synthetic': lock['synthetic'],
                 'matrix_shape': list(X.shape), 'all_locked_artifacts_verified': True,
                 'source_project': str(PROJECT), 'selected_system': freeze['selected_system']}
    for model_id in MODEL_IDS:
        bundle = joblib.load(RUN / 'models' / (model_id + '.joblib'))
        p = bundle['calibrator'].predict_proba(X[test][:, bundle['columns']])[:, 1]
        difference = float(np.max(np.abs(p - original_pred[model_id].p_malware.to_numpy())))
        if difference > 1e-12:
            raise ValueError(f'{model_id}: predictions differ by {difference}')
        integrity[model_id + '_max_probability_difference'] = difference
    save_json(OUT / 'integrity.json', integrity)
    print('Integrity and full test prediction reproduction passed.', flush=True)

    error_rows, by_source, feature_rows = [], [], []
    for model_id, frame in original_pred.items():
        yp = frame.label_predicted.to_numpy()
        outcomes = np.where(y[test] == 1, np.where(yp == 1, 'TP', 'FN'), np.where(yp == 1, 'FP', 'TN'))
        for pos, index in enumerate(test):
            if outcomes[pos] in ('FP', 'FN'):
                error_rows.append({'model_id': model_id, **{k: samples[index][k] for k in ('sha256', 'package_name', 'source_label')},
                                   'outcome': outcomes[pos], 'label_true': int(y[index]), 'label_predicted': int(yp[pos]),
                                   'p_malware': float(frame.iloc[pos].p_malware), 'threshold': float(frame.iloc[pos].threshold)})
        for source in sorted(metadata.source_label.unique()):
            mask = metadata.iloc[test].source_label.to_numpy() == source
            counts = Counter(outcomes[mask])
            by_source.append({'model_id': model_id, 'source_label': source, 'n': int(mask.sum()),
                              **{k: counts[k] for k in ('TP', 'TN', 'FP', 'FN')},
                              'error_rate': float((outcomes[mask] == ('FP' if source == 'Benign' else 'FN')).mean())})
        for outcome, comparison in [('FN', 'TP'), ('FP', 'TN')]:
            a, b = X[test[outcomes == outcome]].toarray(), X[test[outcomes == comparison]].toarray()
            for j, name in enumerate(FEATURE_NAMES):
                feature_rows.append({'model_id': model_id, 'error_type': outcome, 'comparison': comparison,
                                     'feature': name, 'error_n': len(a), 'comparison_n': len(b),
                                     'error_nonzero_rate': float((a[:, j] != 0).mean()),
                                     'comparison_nonzero_rate': float((b[:, j] != 0).mean()),
                                     'error_mean': float(a[:, j].mean()), 'comparison_mean': float(b[:, j].mean())})
    csv('errors_all.csv', error_rows)
    csv('errors_by_source.csv', by_source)
    csv('error_feature_profiles.csv', feature_rows)

    # Identical vectors are an ambiguity of this representation, not proof of identical code.
    collision_rows, cross_rows, subset_metrics = [], [], []
    split_for_row = np.empty(len(y), dtype=object)
    for name, indices in parts.items():
        split_for_row[indices] = name
    dense = X.toarray()
    for space, columns in [('full_163', list(range(X.shape[1]))), ('permissions_76', [FEATURE_NAMES.index(n) for n in GROUPS['P']])]:
        signatures = np.array([hashlib.sha256(row.tobytes()).hexdigest() for row in np.ascontiguousarray(dense[:, columns])])
        counts = Counter(signatures)
        for signature, n in counts.items():
            if n < 2:
                continue
            indices = np.flatnonzero(signatures == signature)
            present = sorted(set(split_for_row[indices]))
            collision_rows.append({'feature_space': space, 'vector_sha256': signature, 'n': n,
                                   'n_packages': int(metadata.iloc[indices].package_name.nunique()),
                                   'mixed_labels': len(set(y[indices])) > 1, 'splits': '|'.join(present),
                                   'cross_split': len(present) > 1})
        for first, second in combinations(parts, 2):
            shared = set(signatures[parts[first]]) & set(signatures[parts[second]])
            cross_rows.append({'feature_space': space, 'split_a': first, 'split_b': second,
                               'shared_vector_groups': len(shared),
                               'samples_a': int(np.isin(signatures[parts[first]], list(shared)).sum()),
                               'samples_b': int(np.isin(signatures[parts[second]], list(shared)).sum())})
        fit_signatures = set(signatures[parts['fit']])
        development_signatures = set(signatures[np.concatenate([parts[k] for k in ('fit', 'calibration', 'validation')])])
        for comparison_name, seen in [('fit', fit_signatures), ('development', development_signatures)]:
            mask = np.isin(signatures[test], list(seen))
            for model_id, frame in original_pred.items():
                for tag, subset in [('seen_vector', mask), ('unseen_vector', ~mask)]:
                    subset_metrics.append({'feature_space': space, 'compared_with': comparison_name, 'subset': tag,
                                           'model_id': model_id, **metrics_or_empty(y[test][subset], frame.p_malware.to_numpy()[subset], float(frame.threshold.iloc[0]))})
    csv('vector_collisions.csv', collision_rows)
    csv('cross_split_vectors.csv', cross_rows)
    csv('test_metrics_by_vector_overlap.csv', subset_metrics)
    print('Error analysis and cross-split vector audit written.', flush=True)

    # Save the exploratory plan before fitting any new variant; the historical test is already known.
    rf_params = {'max_depth': 20, 'min_samples_leaf': 5, 'max_features': 0.5}
    all_names = list(FEATURE_NAMES)
    specs = [
        ('S1_P_without_custom_and_total', [n for n in GROUPS['P'] if n not in ('p_custom_count', 'p_total_count')], 'E1_P__RF'),
        ('S2_FULL_without_custom_and_total', [n for n in all_names if n not in ('p_custom_count', 'p_total_count')], 'E4_PCIAB__RF'),
        ('S3_FULL_API_binary_only', [n for n in all_names if not (n.startswith('api_') and n.endswith('_count'))], 'E4_PCIAB__RF'),
        ('S4_Bcore_only', list(GROUPS['B']), 'E4_PCIAB__RF'),
    ]
    plan = {'created_at': now(), 'study_type': 'exploratory follow-up after original test results were known',
            'independent_final_validation': False, 'dataset_id': lock['dataset_id'], 'split_id': split['split_id'],
            'algorithm': 'RF', 'n_estimators': 300, 'fixed_params': rf_params,
            'selection': 'No new grid search and no best supplementary model selection using test.',
            'protocol': 'Existing five fit-only folds; fit only on fit; sigmoid on calibration; threshold on validation under empirical FPR<=0.05; descriptive test afterward.',
            'custom_count_note': 'Remove both p_custom_count and p_total_count to avoid direct reconstruction via total minus platform. Correlated proxies may remain.',
            'script_sha256': sha_file(__file__),
            'variants': [{'id': k, 'feature_names': names, 'baseline': baseline} for k, names, baseline in specs]}
    study_dir = OUT / 'supplementary'
    study_dir.mkdir(exist_ok=True)
    if (study_dir / 'complete.json').exists():
        print('Supplementary run already complete; preserving existing run.', flush=True)
        return
    save_json(study_dir / 'plan.json', plan)
    fit, cal, val = (parts[k] for k in ('fit', 'calibration', 'validation'))
    results, cv_rows = [], []
    for name, names, baseline in specs:
        columns = [FEATURE_NAMES.index(n) for n in names]
        Xv = X[:, columns]
        scores, warnings_log = [], []
        start = time.perf_counter()
        for fold, (tr, va) in enumerate(inner):
            model = _pipeline('RF', rf_params)
            warnings_log.extend(_fit_checked(model, Xv[tr], y[tr]))
            score = float(average_precision_score(y[va], _score(model, Xv[va])))
            scores.append(score)
            cv_rows.append({'variant': name, 'fold': fold, 'average_precision': score})
        model = _pipeline('RF', rf_params)
        warnings_log.extend(_fit_checked(model, Xv[fit], y[fit]))
        calibrated = CalibratedClassifierCV(estimator=model, method='sigmoid', cv='prefit', n_jobs=1)
        warnings_log.extend(_fit_checked(calibrated, Xv[cal], y[cal]))
        threshold_info = choose_threshold(y[val], calibrated.predict_proba(Xv[val])[:, 1])
        threshold = threshold_info['threshold']
        bundle_path = study_dir / (name + '.joblib')
        joblib.dump({'base_model': model, 'calibrator': calibrated, 'columns': columns, 'threshold': threshold,
                     'supplementary_only': True, 'dataset_id': lock['dataset_id'], 'split_id': split['split_id']}, bundle_path, compress=3)
        save_json(study_dir / (name + '_before_test.json'), {'model_sha256': sha_file(bundle_path),
                  'threshold': None if math.isinf(threshold) else threshold, 'threshold_is_infinite': math.isinf(threshold),
                  'cv_mean': float(np.mean(scores)), 'cv_std': float(np.std(scores, ddof=1)), 'warnings': warnings_log})
        p = calibrated.predict_proba(Xv[test])[:, 1]
        measured = threshold_metrics(y[test], p, threshold)
        row = {'variant': name, 'baseline': baseline, 'n_features': len(columns),
               'retained_features': int(model.named_steps['filter'].get_support().sum()),
               'cv_ap_mean': float(np.mean(scores)), 'cv_ap_std': float(np.std(scores, ddof=1)),
               'threshold': None if math.isinf(threshold) else threshold,
               'validation_fpr': threshold_info['validation_fpr'], 'validation_recall': threshold_info['validation_recall'],
               **measured, 'elapsed_seconds': time.perf_counter() - start}
        baseframe = original_pred[baseline]
        baseline_metrics = threshold_metrics(y[test], baseframe.p_malware.to_numpy(), float(baseframe.threshold.iloc[0]))
        for metric in ('average_precision', 'recall', 'fpr', 'f1'):
            row['delta_' + metric] = measured[metric] - baseline_metrics[metric]
        results.append(row)
        pd.DataFrame({'sha256': metadata.iloc[test].sha256.to_numpy(), 'label_true': y[test],
                      'p_malware': p, 'label_predicted': (p >= threshold).astype(int)}).to_csv(study_dir / (name + '_predictions.csv'), index=False)
        pd.DataFrame(results).to_csv(study_dir / 'metrics.csv', index=False, encoding='utf-8-sig')
        pd.DataFrame(cv_rows).to_csv(study_dir / 'cv.csv', index=False, encoding='utf-8-sig')
        print(f'{name}: F1={measured["f1"]:.4f}, FPR={measured["fpr"]:.4f}, CV AP={np.mean(scores):.5f}', flush=True)
    save_json(study_dir / 'complete.json', {'completed_at': now(), 'n_variants': len(results), 'new_fit_count': len(specs) * 6,
              'interpretation': 'Exploratory sensitivity results on previously inspected test; no independent superiority claim.',
              'files': {p.name: sha_file(p) for p in study_dir.iterdir() if p.is_file() and p.name != 'complete.json'}})

    fig, ax = plt.subplots(figsize=(8.4, 4.7))
    rows = pd.DataFrame(by_source)
    sources = ['Benign', 'Adware', 'Banking', 'SMS malware']
    x = np.arange(len(sources))
    for offset, model_id, color in [(-0.18, MODEL_IDS[0], '#315b7b'), (0.18, MODEL_IDS[1], '#aa6038')]:
        vals = rows[rows.model_id == model_id].set_index('source_label').loc[sources]
        ax.bar(x + offset, vals.error_rate * 100, width=.36, label=model_id, color=color)
    ax.set_xticks(x, ['Benign (FP)', 'Adware (FN)', 'Banking (FN)', 'SMS (FN)'])
    ax.set_ylabel('Error rate within source group (%)')
    ax.set_title('Errors by source category on the locked CIC test set')
    ax.legend(frameon=False)
    fig.text(.01, .01, 'Source: verified main run; historical test, 3,268 APK. Labels inherited from CIC.', fontsize=8)
    fig.tight_layout(rect=(0,.04,1,1))
    fig.savefig(OUT / 'figures/errors_by_source.png', dpi=180)
    plt.close(fig)
    print('Analysis complete.', flush=True)


if __name__ == '__main__':
    main()
