"""Audited dataset assembly. Metadata is never a predictive feature."""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from scipy import sparse

from .features import FEATURE_NAMES, FEATURE_SPACE_ID, SCHEMA_HASH, validate_features

MANIFEST_FIELDS = ['sha256', 'apk_path', 'source_id', 'source_version', 'source_label',
                   'label_binary', 'label_evidence', 'package_name', 'group_id',
                   'collection_time', 'time_kind', 'pilot']


def sha_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2,
                                    allow_nan=False), encoding='utf-8')


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write_csv(path, rows, fieldnames=None):
    rows = list(rows)
    if fieldnames is None:
        fieldnames = list(dict.fromkeys(k for row in rows for k in row))
    with Path(path).open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_dataset(output_dir, X, samples, audit, synthetic=False, evidence_records=None):
    target = Path(output_dir)
    if (target / 'dataset_lock.json').exists():
        raise ValueError('Dataset locked; choose a new output directory, never overwrite a registered dataset.')
    target.mkdir(parents=True, exist_ok=True)
    sparse.save_npz(target / 'dataset.npz', sparse.csr_matrix(X, dtype=np.float32))
    np.save(target / 'labels.npy', np.asarray([int(s['label_binary']) for s in samples], dtype=np.int8), allow_pickle=False)
    write_csv(target / 'samples.csv', samples, MANIFEST_FIELDS)
    write_json(target / 'audit.json', audit)
    with (target / 'evidence.jsonl').open('w', encoding='utf-8') as stream:
        for record in evidence_records or []:
            stream.write(json.dumps({'sha256': record['sha256'], 'evidence': record.get('evidence', {})}, ensure_ascii=False, allow_nan=False) + '\n')
    lock = {'format_version': 1, 'feature_space_id': FEATURE_SPACE_ID, 'schema_hash': SCHEMA_HASH,
            'feature_names': list(FEATURE_NAMES), 'n_samples': len(samples), 'synthetic': synthetic,
            'matrix_format': 'CSR float32',
            'files': {name: sha_file(target / name) for name in ('dataset.npz', 'labels.npy', 'samples.csv', 'audit.json', 'evidence.jsonl')}}
    lock['dataset_id'] = canonical_hash(lock)
    write_json(target / 'dataset_lock.json', lock)
    return {**audit, 'dataset_id': lock['dataset_id'], 'output_dir': str(target.resolve())}


def load_dataset(dataset_dir):
    base = Path(dataset_dir)
    lock = read_json(base / 'dataset_lock.json')
    expected_id = lock.pop('dataset_id')
    if canonical_hash(lock) != expected_id:
        raise ValueError('Dataset lock was modified.')
    lock['dataset_id'] = expected_id
    if lock['schema_hash'] != SCHEMA_HASH or lock['feature_space_id'] != FEATURE_SPACE_ID or lock['feature_names'] != list(FEATURE_NAMES):
        raise ValueError('Incompatible feature schema.')
    for name, expected in lock['files'].items():
        if sha_file(base / name) != expected:
            raise ValueError(f'Dataset artifact changed: {name}')
    X = sparse.load_npz(base / 'dataset.npz').tocsr()
    y = np.load(base / 'labels.npy', allow_pickle=False)
    with (base / 'samples.csv').open(encoding='utf-8-sig', newline='') as stream:
        samples = list(csv.DictReader(stream))
    if X.shape != (len(samples), len(FEATURE_NAMES)) or len(y) != len(samples) or not np.isfinite(X.data).all() or X.dtype != np.float32:
        raise ValueError('Malformed dataset.')
    if not np.array_equal(y, np.array([int(s['label_binary']) for s in samples])):
        raise ValueError('Labels differ between artifacts.')
    return X, y, samples, lock


def build_dataset(manifest_path, extraction_dir, output_dir):
    """Use only complete, verified-by-curator labels. Record every rejection.

    label_evidence stores the curator's cited evidence; this function cannot
    independently establish that a malware label is true.
    """
    manifest_path = Path(manifest_path)
    if (Path(output_dir) / 'dataset_lock.json').exists():
        raise ValueError('Dataset already locked. Choose a new output directory.')
    with manifest_path.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if not set(MANIFEST_FIELDS).issubset(reader.fieldnames or []):
            raise ValueError('Manifest must contain: ' + ', '.join(MANIFEST_FIELDS))
        rows = [{k: (v or '').strip() for k, v in row.items()} for row in reader]
    indexed = defaultdict(list)
    for number, row in enumerate(rows, 2):
        indexed[row['sha256'].lower()].append((number, row))
    # Quarantine the entire identity on label conflict, including conflicting duplicates.
    conflicts = {h for h, entries in indexed.items()
                 if len({r['label_binary'] for _, r in entries if r['label_binary'] in ('0', '1')}) > 1}
    rejected, accepted, vectors, seen = [], [], [], set()
    records_by_hash = {}
    for p in sorted(Path(extraction_dir).rglob('*.json')):
        try:
            value = read_json(p)
            if isinstance(value, dict) and 'sha256' in value:
                key = str(value['sha256']).lower()
                if key in records_by_hash and canonical_hash(records_by_hash[key]) != canonical_hash(value):
                    records_by_hash[key] = {'status': 'conflicting_extraction_records', 'sha256': key}
                else:
                    records_by_hash[key] = value
        except (ValueError, OSError):
            continue
    for number, row in enumerate(rows, 2):
        h = row['sha256'].lower()
        normalized_label = ''.join(row['source_label'].casefold().split())
        reason = None
        if h in conflicts:
            reason = 'conflicting_labels_same_sha256'
        elif row['pilot'].lower() not in ('0', 'false', 'no'):
            reason = 'pilot_or_missing_pilot_declaration'
        elif row['label_binary'] not in ('0', '1'):
            reason = 'unknown_label'
        elif row['source_label'].lower().replace(' ', '') == 'riskware':
            reason = 'riskware_excluded_by_protocol'
        elif row['source_label'].lower() in ('unlabeled', 'unknown', 'uncertain', 'unverified'):
            reason = 'unverified_source_label'
        elif row['source_label'].lower() in ('benign', 'clean') and row['label_binary'] != '0':
            reason = 'source_label_binary_mismatch'
        elif normalized_label in ('malware', 'adware', 'banking', 'sms', 'smsmalware') and row['label_binary'] != '1':
            reason = 'source_label_binary_mismatch'
        elif not all(row[k] for k in ('source_id', 'source_version', 'source_label', 'label_evidence')):
            reason = 'missing_label_provenance'
        elif not row['package_name']:
            reason = 'missing_package'
        elif len(h) != 64 or any(c not in '0123456789abcdef' for c in h):
            reason = 'invalid_sha256'
        else:
            apk = Path(row['apk_path'])
            if not apk.is_absolute():
                project_root = Path(__file__).resolve().parents[2]
                # Intake tools always emit paths relative to the project root.
                apk = project_root / apk
            rec = records_by_hash.get(h)
            if not apk.is_file():
                reason = 'apk_missing'
            elif sha_file(apk) != h:
                reason = 'apk_sha256_mismatch'
            elif rec is None:
                reason = 'extraction_missing'
            elif rec.get('status') != 'ok':
                reason = 'extraction_not_complete:' + str(rec.get('status'))
            elif rec.get('error_code'):
                reason = 'extraction_error_despite_ok_status'
            elif rec.get('schema_hash') != SCHEMA_HASH or rec.get('feature_space_id') != FEATURE_SPACE_ID:
                reason = 'schema_mismatch'
            elif rec.get('package_name') != row['package_name']:
                reason = 'package_mismatch'
            else:
                try:
                    validate_features(rec['features'])
                except (KeyError, ValueError, TypeError) as exc:
                    reason = 'invalid_features:' + str(exc)
        if reason is None and h in seen:
            reason = 'duplicate_sha256'
        if reason:
            rejected.append({'line': number, 'sha256': h, 'reason': reason,
                             'source_id': row['source_id'], 'label_binary': row['label_binary']})
            continue
        seen.add(h)
        row['sha256'] = h
        accepted.append({k: row[k] for k in MANIFEST_FIELDS})
        vectors.append([rec['features'][n] for n in FEATURE_NAMES])
    # Connected components of package links and explicit trusted group links.
    parent = list(range(len(accepted)))
    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    anchors = {}
    for i, sample in enumerate(accepted):
        links = [('package', sample['package_name'])]
        if sample['group_id']:
            links.append(('declared', sample['group_id']))
        for link in links:
            if link in anchors:
                parent[root(i)] = root(anchors[link])
            else:
                anchors[link] = i
    members = defaultdict(list)
    for i, sample in enumerate(accepted):
        members[root(i)].append(sample['sha256'])
    for i, sample in enumerate(accepted):
        sample['group_id'] = 'g_' + canonical_hash(sorted(members[root(i)]))[:24]
    ordered = sorted(zip(accepted, vectors), key=lambda item: item[0]['sha256'])
    accepted = [s for s, _ in ordered]
    vectors = [v for _, v in ordered]
    collisions = defaultdict(list)
    for sample, vector in zip(accepted, vectors):
        collisions[canonical_hash(vector)].append(sample)
    collision_sets = [v for v in collisions.values() if len(v) > 1]
    audit = {'input_rows': len(rows), 'accepted': len(accepted), 'rejected': len(rejected),
             'rejection_counts': dict(Counter(r['reason'] for r in rejected)), 'rejections': rejected,
             'class_counts': dict(Counter(s['label_binary'] for s in accepted)),
             'source_counts': dict(Counter(s['source_id'] for s in accepted)),
             'group_count': len({s['group_id'] for s in accepted}),
             'vector_collision_sets': len(collision_sets),
             'vector_collision_samples': sum(map(len, collision_sets)),
             'vector_collision_conflicting_labels': sum(len({s['label_binary'] for s in group}) > 1 for group in collision_sets),
             'manifest_sha256': sha_file(manifest_path),
             'label_verification': 'Curator-provided label_evidence; not independently certified by software.'}
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    if not accepted:
        write_json(target / 'audit.json', audit)
        raise ValueError('No eligible verified real samples. See audit.json; no dataset created.')
    return _write_dataset(target, vectors, accepted, audit,
                          evidence_records=[records_by_hash[s['sha256']] for s in accepted])


def create_synthetic_smoke_dataset(output_dir, n_groups=100):
    """Generate isolated software fixtures; never use for research claims."""
    if n_groups < 60:
        raise ValueError('Smoke fixture requires >=60 groups for four partitions and inner CV.')
    rng = np.random.default_rng(4217)
    samples, X = [], []
    for group in range(n_groups):
        label = group % 2
        # Two versions share the same group. Some uninformative/constant columns
        # intentionally exercise fold-wise selection.
        base = rng.binomial(1, 0.12 + 0.25 * label, len(FEATURE_NAMES)).astype(float)
        base[-2:] = 0
        for version in (1, 2):
            digest = hashlib.sha256(f'SYNTHETIC_SOFTWARE_TEST:{group}:{version}'.encode()).hexdigest()
            sample = {k: '' for k in MANIFEST_FIELDS}
            sample.update(sha256=digest, source_id='SYNTHETIC_SOFTWARE_TEST', source_version='1',
                          source_label=str(label), label_binary=str(label), label_evidence='SYNTHETIC_NOT_THESIS_RESULTS',
                          package_name=f'synthetic.group{group}', group_id=f'synthetic.group{group}', pilot='1')
            samples.append(sample)
            X.append(base.copy())
    return _write_dataset(output_dir, X, samples, {'purpose': 'SYNTHETIC SOFTWARE TEST ONLY',
                                                 'accepted': len(samples), 'group_count': n_groups}, synthetic=True)
