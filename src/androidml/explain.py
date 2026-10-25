"""Faithful explanations of the base score, distinct from calibrated probability."""
from __future__ import annotations

import numpy as np
from scipy import sparse

from .features import B_DEPENDENCIES, FEATURE_NAMES, PERMISSION_SEED, validate_features


def _feature_evidence(name, evidence, features):
    if name.startswith('api_'):
        family = name[4:].removesuffix('_count')
        api = evidence.get('api', {})
        return {'raw_callsites_count': api.get('callsites_count', {}).get(family),
                'callsites_examples': api.get('callsites_examples', {}).get(family, [])}
    if name.startswith('perm_'):
        return {'requested_permission': PERMISSION_SEED.get(name[5:]),
                'permission_evidence': evidence.get('permissions', {})}
    if name.startswith('b_'):
        return {'rule_dependencies': {n: features[n] for n in B_DEPENDENCIES[name]},
                'note': 'Deterministic static combination; no runtime claim.'}
    return {'manifest': evidence.get('manifest', {})}


def explain_bundle(bundle, record, validate=True):
    if validate:
        validate_features(record['features'])
    all_values = np.array([record['features'][n] for n in FEATURE_NAMES], dtype=np.float32)
    inputs = sparse.csr_matrix(all_values.reshape(1, -1)[:, bundle['columns']])
    pipeline = bundle['base_model']
    model = pipeline.named_steps['model']
    algorithm = bundle['algorithm']
    if algorithm == 'Dummy':
        return {'method': 'constant fit prior', 'target': 'baseline malware probability',
                'base_value': float(model.class_prior_[1]), 'contributions': []}
    transformed = pipeline[:-1].transform(inputs)
    dense = transformed.toarray() if sparse.issparse(transformed) else np.asarray(transformed)
    names = bundle['selected_feature_names']
    if algorithm in ('LR', 'SVM'):
        contributions = model.coef_[0].astype(float) * dense[0].astype(float)
        base_value = float(model.intercept_[0])
        output = float(model.decision_function(transformed)[0])
        reconstruction = float(base_value + contributions.sum())
        method = 'direct w_j * transformed_x_j (not SHAP)'
        target = 'base decision score; these contributions do not add to calibrated p_malware'
    elif algorithm == 'RF':
        import shap
        background = pipeline[:-1].transform(bundle['background_fit'])
        background = background.toarray() if sparse.issparse(background) else np.asarray(background)
        # SHAP 0.46: tree probability output is the base RF vote probability.
        explainer = shap.TreeExplainer(model, data=background, feature_perturbation='interventional', model_output='probability')
        values = explainer.shap_values(dense, check_additivity=True)
        if isinstance(values, list):
            contributions = np.asarray(values[1])[0]
        else:
            values = np.asarray(values)
            if values.ndim != 3 or values.shape[-1] != 2:
                raise ValueError('Unexpected TreeSHAP output shape; explanation cannot be trusted.')
            contributions = values[0, :, 1]
        base_value = float(np.asarray(explainer.expected_value).ravel()[1])
        output = float(model.predict_proba(transformed)[0, 1])
        reconstruction = float(base_value + contributions.sum())
        method = 'TreeSHAP interventional; background from fit only'
        target = 'base Random Forest malware probability; not the sigmoid-calibrated p_malware'
    else:
        raise ValueError('Unsupported explanation algorithm.')
    residual = abs(reconstruction - output)
    if not np.isclose(reconstruction, output, atol=1e-5, rtol=1e-5):
        raise ValueError(f'Explanation additivity failed: residual={residual}')
    evidence = record.get('evidence') or {}
    top = np.argsort(-np.abs(contributions), kind='stable')[:5]
    rows = []
    for index in top:
        name = names[int(index)]
        raw_value = float(record['features'][name])
        row = {'feature': name, 'contribution': float(contributions[index]),
               'direction': 'toward malware score' if contributions[index] > 0 else 'away from malware score' if contributions[index] < 0 else 'zero',
               'extracted_feature_value': raw_value, 'transformed_model_value': float(dense[0, index]),
               'evidence': _feature_evidence(name, evidence, record['features']) if evidence else None}
        if name.startswith('api_') and name.endswith('_count'):
            row['estimated_raw_call_sites_from_log1p'] = int(round(np.expm1(raw_value)))
        rows.append(row)
    return {'method': method, 'target': target, 'base_value': base_value, 'base_output': output,
            'all_contributions_sum': float(contributions.sum()), 'reconstructed_output': reconstruction,
            'additivity_absolute_residual': residual, 'top_five_contributions': rows,
            'evidence_available': bool(evidence),
            'evidence_note': 'Dataset-level evaluation retains feature values; retrieve original extraction JSON by SHA256 for manifest/DEX evidence.' if not evidence else 'Evidence is static; it does not prove runtime execution.'}
