"""Four-way group protocol with an explicit frozen-test boundary."""
from __future__ import annotations

import itertools
import json
import math
import platform
import sys
import threading
import time
import warnings
from collections import Counter
from importlib.metadata import version
from pathlib import Path

import joblib
import numpy as np
import psutil
import sklearn
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, balanced_accuracy_score,
                             brier_score_loss, confusion_matrix, f1_score, log_loss,
                             precision_recall_curve, precision_score, recall_score,
                             roc_auc_score, roc_curve)
from sklearn.model_selection import ParameterGrid, StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MaxAbsScaler
from sklearn.svm import LinearSVC

from .dataset import (canonical_hash, create_synthetic_smoke_dataset, load_dataset, read_json, sha_file, write_csv, write_json)
from .features import FEATURE_NAMES, FEATURE_SPACE_ID, GROUPS, SCHEMA_HASH, validate_features

FEATURE_SETS = {'E1_P': ['P'], 'E2_PA': ['P', 'A'], 'E3_PCIA': ['P', 'C', 'I', 'A'],
                'E4_PCIAB': ['P', 'C', 'I', 'A', 'B_core']}
ALGORITHMS = ['Dummy', 'LR', 'SVM', 'RF']


def _require_version():
    if sklearn.__version__ != '1.5.2':
        raise RuntimeError('This registered protocol requires scikit-learn==1.5.2; run the supplied installer.')


def _source_hashes():
    base = Path(__file__).resolve().parent
    return {str(p.relative_to(base.parent.parent)): sha_file(p) for p in sorted(base.glob('*.py'))}


def environment_snapshot():
    return {'python': sys.version, 'platform': platform.platform(), 'processor': platform.processor(),
            'logical_cpus': psutil.cpu_count(), 'physical_cpus': psutil.cpu_count(logical=False),
            'ram_bytes': psutil.virtual_memory().total,
            'packages': {n: version(n) for n in ('numpy', 'scipy', 'scikit-learn', 'joblib', 'psutil')},
            'source_hashes': _source_hashes()}


class FoldFeatureFilter(BaseEstimator, TransformerMixin):
    """Fit only inside the current training fold; no validation/test statistics."""
    def __init__(self, min_frequency=1):
        self.min_frequency = min_frequency

    def fit(self, X, y=None):
        X = sparse.csr_matrix(X, dtype=np.float32)
        if X.ndim != 2 or not np.isfinite(X.data).all():
            raise ValueError('Feature matrix must be finite and two dimensional.')
        self.n_features_in_ = X.shape[1]
        spread = X.max(axis=0).toarray().ravel() - X.min(axis=0).toarray().ravel()
        self.support_ = (spread > 0) & (np.asarray((X != 0).sum(axis=0)).ravel() >= self.min_frequency)
        if not self.support_.any():
            raise ValueError('All features are constant/absent in a training fold; cannot fit this model.')
        return self

    def transform(self, X):
        X = sparse.csr_matrix(X, dtype=np.float32)
        if X.shape[1] != self.n_features_in_:
            raise ValueError('Unexpected feature count.')
        return X[:, self.support_]

    def get_support(self):
        return self.support_.copy()


def _check_partition(y, groups, label):
    if len(np.unique(y)) != 2:
        raise ValueError(f'{label} lacks one class. Do not search seeds; revise and preregister group protocol.')
    if len(np.unique(groups)) < 2:
        raise ValueError(f'{label} has fewer than two independent groups.')


def _group_cv(X, y, groups, n_splits, seed):
    if len(np.unique(groups)) < n_splits:
        raise ValueError(f'Need at least {n_splits} groups for the registered split.')
    if min(len(np.unique(groups[y == c])) for c in (0, 1)) < n_splits:
        raise ValueError(f'Each class must occur in at least {n_splits} groups for this protocol.')
    folds = []
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    for i, (train, test) in enumerate(cv.split(X, y, groups)):
        _check_partition(y[train], groups[train], f'fold {i} train')
        _check_partition(y[test], groups[test], f'fold {i} heldout')
        if set(groups[train]) & set(groups[test]):
            raise ValueError('Group leakage.')
        folds.append((train, test))
    return folds


def prepare_splits(dataset_dir, output_dir, seed=42):
    if seed != 42:
        raise ValueError('The registered main protocol fixes seed=42.')
    X, y, samples, lock = load_dataset(dataset_dir)
    out = Path(output_dir)
    if (out / 'splits.json').exists():
        raise ValueError('Split is already locked. Use a new directory for a preregistered revision.')
    groups = np.array([r['group_id'] for r in samples])
    dev, test = _group_cv(X, y, groups, 5, seed)[0]
    sub = _group_cv(X[dev], y[dev], groups[dev], 8, seed)
    cal, val = dev[sub[0][1]], dev[sub[1][1]]
    fit = np.sort(np.concatenate([dev[sub[i][1]] for i in range(2, 8)]))
    partitions = {'fit': fit, 'calibration': cal, 'validation': val, 'test': test}
    for name, inds in partitions.items():
        _check_partition(y[inds], groups[inds], name)
    for a, b in itertools.combinations(partitions, 2):
        if set(groups[partitions[a]]) & set(groups[partitions[b]]):
            raise ValueError('Group leakage between four partitions.')
    if set(np.concatenate(list(partitions.values()))) != set(range(len(y))):
        raise ValueError('Split does not partition the complete dataset.')
    inner = _group_cv(X[fit], y[fit], groups[fit], 5, seed)
    result = {'protocol': 'chapter2-v2-locked-2026-09', 'seed': seed,
              'dataset_id': lock['dataset_id'], 'synthetic': lock['synthetic'],
              'partitions': {k: [samples[int(i)]['sha256'] for i in v] for k, v in partitions.items()},
              'inner_folds': [{'train': [samples[int(i)]['sha256'] for i in fit[tr]],
                               'heldout': [samples[int(i)]['sha256'] for i in fit[va]]} for tr, va in inner],
              'summary': {k: {'n': len(v), 'groups': len(set(groups[v])),
                              'benign': int((y[v] == 0).sum()), 'malware': int((y[v] == 1).sum())}
                          for k, v in partitions.items()},
              'source_hashes_at_registration': _source_hashes()}
    result['split_id'] = canonical_hash(result)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / 'splits.json', result)
    assignment = {samples[int(i)]['sha256']: k for k, v in partitions.items() for i in v}
    write_csv(out / 'split_manifest.csv', [{'sha256': s['sha256'], 'group_id': s['group_id'],
               'label_binary': s['label_binary'], 'partition': assignment[s['sha256']]} for s in samples])
    return result


def _load_splits(split_dir, lock, samples):
    split = read_json(Path(split_dir) / 'splits.json')
    claimed = split.pop('split_id')
    if canonical_hash(split) != claimed or split['dataset_id'] != lock['dataset_id']:
        raise ValueError('Split modified or belongs to a different dataset.')
    split['split_id'] = claimed
    lookup = {s['sha256']: i for i, s in enumerate(samples)}
    partitions = {k: np.array([lookup[h] for h in v], dtype=int) for k, v in split['partitions'].items()}
    all_rows = np.concatenate(list(partitions.values()))
    if len(all_rows) != len(samples) or set(all_rows) != set(range(len(samples))):
        raise ValueError('Invalid split coverage or duplicate samples.')
    group_sets = {k: {samples[i]['group_id'] for i in inds} for k, inds in partitions.items()}
    for a, b in itertools.combinations(group_sets, 2):
        if group_sets[a] & group_sets[b]:
            raise ValueError('Group leakage in stored split.')
    inner = [(np.array([lookup[h] for h in f['train']]), np.array([lookup[h] for h in f['heldout']]))
             for f in split['inner_folds']]
    fit_set = set(partitions['fit'])
    for tr, va in inner:
        if set(tr) | set(va) != fit_set or set(tr) & set(va):
            raise ValueError('Inner fold escapes fit partition.')
        if {samples[i]['group_id'] for i in tr} & {samples[i]['group_id'] for i in va}:
            raise ValueError('Inner group leakage.')
    return split, partitions, inner


def choose_threshold(y_true, p_malware, fpr_target=0.05):
    """Recall max under empirical FPR; largest threshold on a tie, including inf."""
    y = np.asarray(y_true, dtype=int)
    p = np.asarray(p_malware, dtype=float)
    if set(np.unique(y)) != {0, 1} or not np.isfinite(p).all():
        raise ValueError('Threshold validation requires both classes and finite scores.')
    if p.shape != y.shape or np.any((p < 0) | (p > 1)) or not 0 <= fpr_target <= 1:
        raise ValueError('Invalid probabilities or FPR target.')
    candidates = np.r_[np.inf, np.sort(np.unique(p))[::-1]]
    best_threshold, best_recall, best_fpr = math.inf, 0.0, 0.0
    for threshold in candidates:
        predicted = p >= threshold
        fpr = float(predicted[y == 0].mean())
        recall = float(predicted[y == 1].mean())
        if fpr <= fpr_target + 1e-12 and (recall > best_recall or
                                         (recall == best_recall and threshold > best_threshold)):
            best_threshold, best_recall, best_fpr = float(threshold), recall, fpr
    return {'threshold': best_threshold, 'validation_recall': best_recall,
            'validation_fpr': best_fpr, 'fpr_target': fpr_target,
            'validation_benign_n': int((y == 0).sum()),
            'fpr_resolution': 1 / int((y == 0).sum()), 'no_alert': math.isinf(best_threshold)}


def threshold_metrics(y, p, threshold):
    y, p = np.asarray(y), np.asarray(p)
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {'average_precision': float(average_precision_score(y, p)),
            'roc_auc': float(roc_auc_score(y, p)), 'accuracy': float(accuracy_score(y, pred)),
            'precision': float(precision_score(y, pred, zero_division=0)),
            'recall': float(recall_score(y, pred, zero_division=0)),
            'f1': float(f1_score(y, pred, zero_division=0)),
            'fpr': float(fp / (fp + tn)), 'specificity': float(tn / (fp + tn)),
            'balanced_accuracy': float(balanced_accuracy_score(y, pred)),
            'brier_score': float(brier_score_loss(y, p)),
            'log_loss': float(log_loss(y, p, labels=[0, 1])),
            'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)}


def _score(model, X):
    if hasattr(model, 'decision_function'):
        return np.asarray(model.decision_function(X)).reshape(-1)
    return model.predict_proba(X)[:, 1]


def _pipeline(algorithm, params, smoke=False):
    if algorithm == 'Dummy':
        return Pipeline([('model', DummyClassifier(strategy='prior'))])
    if algorithm == 'LR':
        estimator = LogisticRegression(solver='liblinear', penalty='l2', max_iter=5000,
                                       class_weight='balanced', random_state=42, **params)
    elif algorithm == 'SVM':
        estimator = LinearSVC(dual='auto', max_iter=10000, class_weight='balanced', random_state=42, **params)
    else:
        estimator = RandomForestClassifier(n_estimators=12 if smoke else 300,
                                            class_weight='balanced', n_jobs=1, random_state=42, **params)
    steps = [('filter', FoldFeatureFilter(1))]
    if algorithm in ('LR', 'SVM'):
        steps.append(('scale', MaxAbsScaler()))
    return Pipeline(steps + [('model', estimator)])


class _ResourceMonitor:
    """Sample total process RSS every 50 ms (not a per-fit incremental allocation)."""
    def __enter__(self):
        self.stop = threading.Event()
        self.peak = psutil.Process().memory_info().rss
        def sample():
            while not self.stop.wait(0.05):
                self.peak = max(self.peak, psutil.Process().memory_info().rss)
        self.thread = threading.Thread(target=sample, daemon=True)
        self.thread.start()
        self.start = time.perf_counter()
        return self
    def __exit__(self, *args):
        self.elapsed = time.perf_counter() - self.start
        self.peak = max(self.peak, psutil.Process().memory_info().rss)
        self.stop.set()
        self.thread.join()


def _fit_checked(model, X, y):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        model.fit(X, y)
    issues = [str(w.message) for w in caught]
    if any(issubclass(w.category, ConvergenceWarning) for w in caught):
        raise RuntimeError('Convergence warning prevents finalization: ' + '; '.join(issues))
    return issues


def _columns(feature_set):
    names = {n for group in FEATURE_SETS[feature_set] for n in GROUPS['B' if group == 'B_core' else group]}
    # Always maintain the single canonical global order.
    return [i for i, n in enumerate(FEATURE_NAMES) if n in names]


def _latency(model, X, probability=False):
    function = model.predict_proba if probability else lambda x: _score(model, x)
    function(X)  # warm-up, no labels consulted
    measured = []
    for _ in range(5):
        start = time.perf_counter()
        function(X)
        measured.append((time.perf_counter() - start) / X.shape[0])
    return float(np.median(measured))


def _configuration():
    path = Path(__file__).resolve().parents[2] / 'configs' / 'experiment.json'
    config = read_json(path)
    fixed = {'seed': 42, 'outer_folds': 5, 'development_folds': 8, 'inner_folds': 5,
             'test_fold': 0, 'calibration_fold': 0, 'validation_fold': 1, 'min_frequency': 1,
             'fpr_target': 0.05, 'ap_tolerance': 0.005, 'bootstrap_repetitions': 2000, 'n_jobs': 1}
    if any(config.get(k) != v for k, v in fixed.items()) or config.get('feature_sets') != FEATURE_SETS:
        raise ValueError('Main protocol configuration changed. Register an explicit new protocol before running.')
    expected_grids = {'Dummy': [{}], 'LR': {'C': [0.1, 1.0, 10.0]}, 'SVM': {'C': [0.1, 1.0, 10.0]},
                      'RF': {'max_depth': [20, None], 'min_samples_leaf': [1, 5], 'max_features': ['sqrt', 0.5]}}
    if config.get('grids') != expected_grids:
        raise ValueError('Main hyperparameter grid changed; register a new protocol explicitly.')
    return config, sha_file(path)


def train_experiments(dataset_dir, split_dir, run_dir, smoke=False):
    """Fit all 16 preregistered pairs. No test prediction or metric is computed."""
    _require_version()
    config, config_hash = _configuration()
    X, y, samples, lock = load_dataset(dataset_dir)
    if bool(lock['synthetic']) != bool(smoke):
        raise ValueError('Synthetic fixtures require smoke=True; real experiments require smoke=False.')
    split, partitions, inner = _load_splits(split_dir, lock, samples)
    out = Path(run_dir)
    if (out / 'freeze.json').exists() or (out / 'models').exists():
        raise ValueError('Run directory is already used. Choose a fresh run directory.')
    (out / 'models').mkdir(parents=True, exist_ok=True)
    fit, cal, val = (partitions[k] for k in ('fit', 'calibration', 'validation'))
    for k in ('fit', 'calibration', 'validation'):
        _check_partition(y[partitions[k]], np.array([s['group_id'] for s in samples])[partitions[k]], k)
    env = environment_snapshot()
    write_json(out / 'environment.json', env)
    write_json(out / 'registered_config.json', config)
    rows, cards, model_hashes, warnings_log = [], [], {}, []
    for feature_set in FEATURE_SETS:
        cols = _columns(feature_set)
        Xf = X[:, cols]
        for algorithm in ALGORITHMS:
            model_id = feature_set + '__' + algorithm
            params_grid = list(ParameterGrid(config['grids'][algorithm]))
            if smoke:
                params_grid = params_grid[:1]
            candidates = []
            for candidate_index, params in enumerate(params_grid):
                scores, kept, elapsed, latencies = [], [], [], []
                for fold_number, (tr, va) in enumerate(inner):
                    pipeline = _pipeline(algorithm, params, smoke)
                    with _ResourceMonitor() as resource:
                        issues = _fit_checked(pipeline, Xf[tr], y[tr])
                    warnings_log.extend({'model_id': model_id, 'fold': fold_number, 'warning': w} for w in issues)
                    score = float(average_precision_score(y[va], _score(pipeline, Xf[va])))
                    retained = int(pipeline.named_steps['filter'].get_support().sum()) if algorithm != 'Dummy' else 0
                    # Validation labels are never used for timing or CV selection.
                    latency = _latency(pipeline, Xf[val])
                    row = {'model_id': model_id, 'candidate_index': candidate_index,
                           'params': json.dumps(params, sort_keys=True), 'fold': fold_number,
                           'average_precision': score, 'retained_features': retained,
                           'fit_seconds': resource.elapsed, 'process_peak_rss_bytes': resource.peak,
                           'validation_prediction_seconds_per_sample': latency}
                    rows.append(row)
                    scores.append(score); kept.append(retained); elapsed.append(resource.elapsed); latencies.append(latency)
                candidates.append({'params': params, 'candidate_index': candidate_index,
                                   'cv_average_precision_mean': float(np.mean(scores)),
                                   'cv_average_precision_std': float(np.std(scores, ddof=1)),
                                   'cv_retained_features_mean': float(np.mean(kept)),
                                   'cv_fit_seconds': float(sum(elapsed)),
                                   'validation_timing_seconds_per_sample': float(np.median(latencies))})
            best_ap = max(c['cv_average_precision_mean'] for c in candidates)
            tied = [c for c in candidates if best_ap - c['cv_average_precision_mean'] <= config['ap_tolerance'] + 1e-12]
            selected = min(tied, key=lambda c: (c['cv_retained_features_mean'],
                                               c['validation_timing_seconds_per_sample'], c['candidate_index']))
            base = _pipeline(algorithm, selected['params'], smoke)
            with _ResourceMonitor() as resource:
                issues = _fit_checked(base, Xf[fit], y[fit])
                if algorithm == 'Dummy':
                    calibrated = base
                else:
                    calibrated = CalibratedClassifierCV(estimator=base, method='sigmoid', cv='prefit', n_jobs=1)
                    issues += _fit_checked(calibrated, Xf[cal], y[cal])
            warnings_log.extend({'model_id': model_id, 'fold': 'final', 'warning': w} for w in issues)
            p_val = calibrated.predict_proba(Xf[val])[:, 1]
            threshold = choose_threshold(y[val], p_val, config['fpr_target'])
            latency = _latency(calibrated, Xf[val], probability=True)
            keep = base.named_steps['filter'].get_support() if algorithm != 'Dummy' else np.zeros(len(cols), dtype=bool)
            card = {'model_id': model_id, 'algorithm': algorithm, 'feature_set': feature_set,
                    'input_features': len(cols), 'retained_features': int(keep.sum()), **selected,
                    'threshold': None if threshold['no_alert'] else threshold['threshold'],
                    'threshold_is_infinite': threshold['no_alert'],
                    'validation_recall': threshold['validation_recall'],
                    'validation_fpr': threshold['validation_fpr'],
                    'validation_benign_n': threshold['validation_benign_n'],
                    'fpr_resolution': threshold['fpr_resolution'],
                    'validation_prediction_seconds_per_sample': latency,
                    'final_fit_calibration_seconds': resource.elapsed,
                    'process_peak_rss_bytes': resource.peak,
                    'calibration': 'none; fixed fit prior baseline' if algorithm == 'Dummy' else 'heldout sigmoid, prefit base',
                    'synthetic': smoke}
            bundle = {'model_id': model_id, 'algorithm': algorithm, 'feature_set': feature_set,
                      'feature_names': list(FEATURE_NAMES), 'schema_hash': SCHEMA_HASH,
                      'feature_space_id': FEATURE_SPACE_ID, 'columns': cols,
                      'selected_feature_names': [FEATURE_NAMES[cols[i]] for i in np.flatnonzero(keep)],
                      'base_model': base, 'calibrator': calibrated, 'threshold': threshold['threshold'],
                      'dataset_id': lock['dataset_id'], 'split_id': split['split_id'], 'synthetic': smoke,
                      'card': card, 'background_fit': Xf[fit[np.random.default_rng(42).choice(len(fit), min(200, len(fit)), replace=False)]]}
            path = out / 'models' / (model_id + '.joblib')
            joblib.dump(bundle, path, compress=3)
            model_hashes[str(path.relative_to(out)).replace('\\', '/')] = sha_file(path)
            cards.append(card)
            write_csv(out / 'cv_results.csv', rows)
            write_json(out / 'training_warnings.json', warnings_log)
            write_json(out / 'training_progress.json', {'completed_pairs': len(cards), 'total_pairs': 16,
                                                       'last_model': model_id, 'synthetic': smoke})
            print(f'[{len(cards)}/16] trained {model_id}; test remains unopened', flush=True)
    eligible = [c for c in cards if c['algorithm'] != 'Dummy']
    top = max(c['cv_average_precision_mean'] for c in eligible)
    eligible = [c for c in eligible if top - c['cv_average_precision_mean'] <= config['ap_tolerance'] + 1e-12]
    selected_system = min(eligible, key=lambda c: (c['retained_features'], c['validation_prediction_seconds_per_sample'],
                                                  ['LR', 'SVM', 'RF'].index(c['algorithm']), c['feature_set']))
    write_json(out / 'model_cards.json', cards)
    write_csv(out / 'model_cards.csv', cards)
    freeze = {'protocol': config['protocol'], 'dataset_id': lock['dataset_id'], 'split_id': split['split_id'],
              'config_sha256': config_hash, 'source_hashes': _source_hashes(),
              'environment_sha256': sha_file(out / 'environment.json'),
              'selected_system': selected_system['model_id'], 'models': model_hashes,
              'cards_sha256': sha_file(out / 'model_cards.json'),
              'cv_sha256': sha_file(out / 'cv_results.csv'), 'synthetic': smoke,
              'test_state': 'not evaluated', 'bootstrap_repetitions': 20 if smoke else 2000,
              'tie_rule': 'AP within 0.005; fewer retained features; lower validation inference time; LR,SVM,RF; feature set id',
              'hyperparameter_tie_rule': 'AP within 0.005; mean retained fold features; median fold-model inference time on validation X; registered candidate index',
              'baseline_note': 'Dummy prior is uncalibrated and repeated in all 4 sets; present once in thesis.'}
    freeze['freeze_id'] = canonical_hash(freeze)
    write_json(out / 'freeze.json', freeze)
    return freeze


def _verify_freeze(run_dir, lock, split):
    out = Path(run_dir)
    freeze = read_json(out / 'freeze.json')
    expected = freeze.pop('freeze_id')
    if canonical_hash(freeze) != expected or freeze['dataset_id'] != lock['dataset_id'] or freeze['split_id'] != split['split_id']:
        raise ValueError('Frozen model protocol was modified or data/split differs.')
    freeze['freeze_id'] = expected
    if len(freeze['models']) != 16:
        raise ValueError('All 16 preregistered pairs must be frozen before test evaluation.')
    for name, digest in freeze['models'].items():
        if sha_file(out / name) != digest:
            raise ValueError('A frozen model changed: ' + name)
    if sha_file(out / 'model_cards.json') != freeze['cards_sha256'] or sha_file(out / 'cv_results.csv') != freeze['cv_sha256']:
        raise ValueError('Frozen selection artifacts changed.')
    if _source_hashes() != freeze['source_hashes']:
        raise ValueError('Source code changed after model freeze. Audit the change; use a new run.')
    _, config_hash = _configuration()
    if config_hash != freeze['config_sha256']:
        raise ValueError('Configuration changed after freeze.')
    return freeze


def group_bootstrap_indices(y, groups, repetitions=2000, seed=42):
    y, groups = np.asarray(y), np.asarray(groups)
    unique = np.unique(groups)
    members = {g: np.flatnonzero(groups == g) for g in unique}
    rng = np.random.default_rng(seed)
    valid = []
    for _ in range(repetitions):
        picked = rng.choice(unique, size=len(unique), replace=True)
        indices = np.concatenate([members[g] for g in picked])
        if len(np.unique(y[indices])) == 2:
            valid.append(indices)
    return valid


def _bootstrap_summary(y, p, threshold, indices):
    metric_names = ['average_precision', 'roc_auc', 'recall', 'fpr', 'f1', 'accuracy', 'precision',
                    'specificity', 'balanced_accuracy', 'brier_score', 'log_loss']
    values = {k: [] for k in metric_names}
    for inds in indices:
        metric = threshold_metrics(y[inds], p[inds], threshold)
        for key in metric_names:
            values[key].append(metric[key])
    summary = {}
    for key, v in values.items():
        summary[key + '_ci95_low'] = float(np.percentile(v, 2.5)) if v else None
        summary[key + '_ci95_high'] = float(np.percentile(v, 97.5)) if v else None
    return summary, values


def _figures(y, p, threshold, path, title):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(2, 2, figsize=(11, 9), constrained_layout=True)
    cm = confusion_matrix(y, p >= threshold, labels=[0, 1])
    axes[0, 0].imshow(cm, cmap='Blues')
    for (i, j), value in np.ndenumerate(cm):
        axes[0, 0].text(j, i, str(value), ha='center', va='center')
    axes[0, 0].set(xticks=[0, 1], yticks=[0, 1], xlabel='Predicted label', ylabel='True label', title='Confusion matrix [0=benign, 1=malware]')
    fpr, tpr, _ = roc_curve(y, p)
    axes[0, 1].plot(fpr, tpr, label=f'ROC-AUC={roc_auc_score(y, p):.3f}')
    axes[0, 1].plot([0, 1], [0, 1], '--', color='gray'); axes[0, 1].legend()
    axes[0, 1].set(xlabel='False positive rate', ylabel='True positive rate', title='ROC')
    prec, rec, _ = precision_recall_curve(y, p)
    axes[1, 0].step(rec, prec, where='post', label=f'AP={average_precision_score(y, p):.3f}')
    axes[1, 0].axhline(np.mean(y), linestyle='--', color='gray', label='Positive prevalence')
    axes[1, 0].legend(); axes[1, 0].set(xlabel='Recall', ylabel='Precision', title='Precision-recall (AP is not trapezoidal area)')
    obs, pred = calibration_curve(y, p, n_bins=10, strategy='uniform')
    axes[1, 1].plot(pred, obs, marker='o'); axes[1, 1].plot([0, 1], [0, 1], '--', color='gray')
    axes[1, 1].set(xlabel='Mean predicted malware probability', ylabel='Observed malware fraction', title='Reliability curve')
    fig.suptitle(title)
    fig.savefig(path, dpi=180)
    plt.close(fig)


def _importance_plot(rows, name_key, mean_key, std_key, path, title):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    ranked = sorted(rows, key=lambda row: row[mean_key], reverse=True)[:20][::-1]
    fig, axis = plt.subplots(figsize=(10, max(4, len(ranked) * .3)), constrained_layout=True)
    axis.barh([r[name_key] for r in ranked], [r[mean_key] for r in ranked],
              xerr=[r[std_key] for r in ranked], color='#357098')
    axis.axvline(0, color='black', linewidth=.6)
    axis.set(xlabel='Decrease in validation Average Precision (mean +/- SD)', title=title)
    fig.savefig(path, dpi=180)
    plt.close(fig)


def evaluate_run(dataset_dir, split_dir, run_dir):
    """Explicit final opening of the frozen test; never chooses models from test."""
    _require_version()
    X, y, samples, lock = load_dataset(dataset_dir)
    split, partitions, _ = _load_splits(split_dir, lock, samples)
    out = Path(run_dir)
    freeze = _verify_freeze(out, lock, split)
    if (out / 'evaluation_complete.json').exists():
        done = read_json(out / 'evaluation_complete.json')
        if done['freeze_id'] != freeze['freeze_id']:
            raise ValueError('Existing evaluation differs from frozen run.')
        for filename, digest in done['files'].items():
            if sha_file(out / filename) != digest:
                raise ValueError('A completed evaluation artifact changed: ' + filename)
        return done
    test, val = partitions['test'], partitions['validation']
    yt = y[test]
    groups = np.array([samples[i]['group_id'] for i in test])
    boot = group_bootstrap_indices(yt, groups, freeze['bootstrap_repetitions'], 42)
    (out / 'figures').mkdir(exist_ok=True)
    (out / 'explanations').mkdir(exist_ok=True)
    predictions, metrics, bootstrap_values, bundles = [], [], {}, {}
    all_scores = {}
    for artifact in freeze['models']:
        bundle = joblib.load(out / artifact)
        model_id = bundle['model_id']; bundles[model_id] = bundle
        cols = bundle['columns']
        start = time.perf_counter()
        p = bundle['calibrator'].predict_proba(X[test][:, cols])[:, 1]
        elapsed = time.perf_counter() - start
        threshold = bundle['threshold']; all_scores[model_id] = p
        result = threshold_metrics(yt, p, threshold)
        confidence, values = _bootstrap_summary(yt, p, threshold, boot)
        bootstrap_values[model_id] = values
        metrics.append({'model_id': model_id, 'feature_set': bundle['feature_set'], 'algorithm': bundle['algorithm'],
                        'synthetic': freeze['synthetic'], 'n_test': len(test), 'n_test_groups': len(set(groups)),
                        'test_malware_prevalence': float(np.mean(yt)), 'threshold': threshold,
                        'test_prediction_seconds': elapsed, 'bootstrap_requested': freeze['bootstrap_repetitions'],
                        'bootstrap_valid': len(boot), **result, **confidence})
        for i, prob in zip(test, p):
            predictions.append({'model_id': model_id, 'sha256': samples[i]['sha256'],
                                'package_name': samples[i]['package_name'], 'group_id': samples[i]['group_id'],
                                'source_id': samples[i]['source_id'], 'label_true': int(y[i]),
                                'p_malware': float(prob), 'threshold': threshold,
                                'label_predicted': int(prob >= threshold), 'synthetic': freeze['synthetic']})
        prefix = 'SYNTHETIC SOFTWARE TEST ONLY | ' if freeze['synthetic'] else ''
        _figures(yt, p, threshold, out / 'figures' / (model_id + '.png'), prefix + model_id)
        print(f'Evaluated frozen test: {model_id}', flush=True)
    paired = []
    for algorithm in ALGORITHMS:
        for reference in ('E1_P', 'E3_PCIA'):
            full_id, ref_id = 'E4_PCIAB__' + algorithm, reference + '__' + algorithm
            for metric in ('average_precision', 'roc_auc', 'recall', 'fpr', 'f1'):
                diff = np.array(bootstrap_values[full_id][metric]) - np.array(bootstrap_values[ref_id][metric])
                point_full = next(r for r in metrics if r['model_id'] == full_id)[metric]
                point_ref = next(r for r in metrics if r['model_id'] == ref_id)[metric]
                paired.append({'algorithm': algorithm, 'comparison': 'E4_PCIAB-minus-' + reference,
                               'metric': metric, 'difference': point_full - point_ref,
                               'ci95_low': float(np.percentile(diff, 2.5)) if len(diff) else None,
                               'ci95_high': float(np.percentile(diff, 97.5)) if len(diff) else None,
                               'bootstrap_valid': len(diff), 'synthetic': freeze['synthetic']})
    write_csv(out / 'test_metrics.csv', metrics)
    write_csv(out / 'test_predictions.csv', predictions)
    write_csv(out / 'paired_ablation.csv', paired)
    # Explanations concern the CV-selected system, never the test winner.
    selected_id = freeze['selected_system']; selected = bundles[selected_id]
    cols = selected['columns']; selected_scores = all_scores[selected_id]
    if selected['algorithm'] != 'Dummy':
        validation_dense = X[val][:, cols].toarray()
        result = permutation_importance(selected['calibrator'], validation_dense, y[val],
                                         scoring='average_precision', n_repeats=2 if freeze['synthetic'] else 10,
                                         random_state=42, n_jobs=1)
        names = [FEATURE_NAMES[i] for i in cols]
        importance = [{'feature': n, 'permutation_ap_mean': float(result.importances_mean[i]),
                       'permutation_ap_std': float(result.importances_std[i])} for i, n in enumerate(names)]
        importance.sort(key=lambda r: r['permutation_ap_mean'], reverse=True)
        write_csv(out / 'explanations' / 'validation_permutation_importance.csv', importance)
        prefix = 'SYNTHETIC SOFTWARE TEST ONLY | ' if freeze['synthetic'] else ''
        _importance_plot(importance, 'feature', 'permutation_ap_mean', 'permutation_ap_std',
                         out / 'figures' / 'validation_top_features.png', prefix + selected_id + ' | validation permutation')
        # Jointly permute each entire semantic group using a shared row permutation.
        rng = np.random.default_rng(42); group_importance = []
        base_ap = average_precision_score(y[val], selected['calibrator'].predict_proba(X[val][:, cols])[:, 1])
        for group, group_names in GROUPS.items():
            local_cols = [j for j, n in enumerate(names) if n in group_names]
            if not local_cols:
                continue
            deltas = []
            for _ in range(2 if freeze['synthetic'] else 10):
                permuted = validation_dense.copy(); order = rng.permutation(len(val))
                permuted[:, local_cols] = permuted[order][:, local_cols]
                deltas.append(float(base_ap - average_precision_score(y[val], selected['calibrator'].predict_proba(permuted)[:, 1])))
            group_importance.append({'group': group, 'mean_ap_decrease': float(np.mean(deltas)),
                                     'std_ap_decrease': float(np.std(deltas))})
        write_csv(out / 'explanations' / 'validation_group_permutation.csv', group_importance)
        _importance_plot(group_importance, 'group', 'mean_ap_decrease', 'std_ap_decrease',
                         out / 'figures' / 'validation_group_importance.png', prefix + selected_id + ' | joint group permutation')
        if selected['algorithm'] == 'RF':
            mdi = selected['base_model'].named_steps['model'].feature_importances_
            write_csv(out / 'explanations' / 'supplemental_rf_impurity_importance.csv',
                      [{'feature': n, 'impurity_importance': float(v), 'caution': 'Supplementary; biased toward multi-valued features; not causal.'}
                       for n, v in zip(selected['selected_feature_names'], mdi)])
    from .explain import explain_bundle
    cases = []
    pred = selected_scores >= selected['threshold']
    for name, mask in {'TP': (yt == 1) & pred, 'TN': (yt == 0) & ~pred,
                       'FP': (yt == 0) & pred, 'FN': (yt == 1) & ~pred}.items():
        options = np.flatnonzero(mask)
        if len(options):
            local = min(options, key=lambda j: samples[test[j]]['sha256'])
            cases.append((name, int(test[local])))
    if np.isfinite(selected['threshold']):
        local = min(range(len(test)), key=lambda j: (abs(selected_scores[j] - selected['threshold']), samples[test[j]]['sha256']))
        cases.append(('nearest_threshold', int(test[local])))
    for name, index in cases:
        target_hash = samples[index]['sha256']
        evidence = {}
        with (Path(dataset_dir) / 'evidence.jsonl').open(encoding='utf-8') as stream:
            for line in stream:
                extracted = json.loads(line)
                if extracted['sha256'] == target_hash:
                    evidence = extracted['evidence']
                    break
        record = {'sha256': target_hash, 'features': dict(zip(FEATURE_NAMES, X[index].toarray().ravel().astype(float))), 'evidence': evidence}
        explanation = explain_bundle(selected, record, validate=False)
        write_json(out / 'explanations' / (name + '.json'), {'case_selection': name, 'selection_rule': 'smallest SHA256 within error class; nearest threshold tie by SHA256',
                    'label_true': int(y[index]), 'sha256': samples[index]['sha256'], **explanation})
    done = {'freeze_id': freeze['freeze_id'], 'selected_system': selected_id,
            'synthetic': freeze['synthetic'], 'bootstrap_valid': len(boot),
            'bootstrap_requested': freeze['bootstrap_repetitions'],
            'test_group_count': len(set(groups)), 'interval_note': 'Group percentile bootstrap; few groups make intervals unstable; CV std is not a CI.',
            'files': {p.name: sha_file(p) for p in (out / 'test_metrics.csv', out / 'test_predictions.csv', out / 'paired_ablation.csv')},
            'source_hashes': _source_hashes()}
    write_json(out / 'evaluation_complete.json', done)
    return done


def predict_record(record, bundle_path):
    """Load only a trusted locally-created joblib bundle (pickle is executable)."""
    _require_version()
    if record.get('status') != 'ok':
        return {'status': 'not_classified', 'reason': record.get('error_code') or record.get('status'),
                'p_malware': None, 'predicted_label': None}
    bundle = joblib.load(bundle_path)
    if bundle.get('synthetic'):
        raise ValueError('Synthetic smoke model cannot classify a real APK.')
    if (record.get('schema_hash') != bundle['schema_hash'] or record.get('feature_space_id') != bundle['feature_space_id']
            or bundle['schema_hash'] != SCHEMA_HASH or bundle['feature_names'] != list(FEATURE_NAMES)):
        raise ValueError('Extractor and model feature schema are incompatible.')
    validate_features(record['features'])
    X = sparse.csr_matrix([[record['features'][n] for n in FEATURE_NAMES]], dtype=np.float32)
    p = float(bundle['calibrator'].predict_proba(X[:, bundle['columns']])[0, 1])
    from .explain import explain_bundle
    return {'status': 'ok', 'sha256': record.get('sha256'), 'model_id': bundle['model_id'],
            'feature_space_id': bundle['feature_space_id'], 'schema_hash': bundle['schema_hash'],
            'p_malware': p, 'threshold': None if math.isinf(bundle['threshold']) else bundle['threshold'],
            'threshold_is_infinite': math.isinf(bundle['threshold']),
            'predicted_label': int(p >= bundle['threshold']), 'explanation': explain_bundle(bundle, record)}
