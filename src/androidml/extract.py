"""Read-only APK parsing in a disposable, timed subprocess; never installs APKs."""
from __future__ import annotations

import hashlib
import gc
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Iterable

from .features import (API_RULES, FEATURE_NAMES, FEATURE_SPACE_ID, GROUPS, INTENT_SEED,
                       PERMISSION_SEED, REFERENCE_API, ROOT, SCHEMA_HASH, SENSITIVE_PERMISSIONS,
                       derive_group_b, empty_features, intent_feature_name, validate_features)

ANDROID_NS = "http://schemas.android.com/apk/res/android"
PLATFORM = json.loads((ROOT / "configs/platform_permissions_android15.json").read_text(encoding="utf-8"))["permissions"]
COMPILED_RULES = {family: [(re.compile(r["owner"]), re.compile(r["method"]), re.compile(r["descriptor"]), r["subtype"])
                          for r in rules] for family, rules in API_RULES.items()}
DEX_PATTERN = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex")
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_WORKER_RSS_MB = 1536
MAX_EXAMPLE_CALLSITES = 100

def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def _local(tag: Any) -> str:
    return str(tag).rsplit("}", 1)[-1]

def _attr(element: Any, name: str) -> str | None:
    # Empty string is an explicit override and MUST NOT fall through to default.
    value = element.get("{" + ANDROID_NS + "}" + name)
    return value if value is not None else element.get("android:" + name)

def _children(element: Any, name: str) -> list:
    return [child for child in element if _local(child.tag) == name]

def _boolean(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    if value.lower() in {"true", "1", "0xffffffff"}:
        return True
    if value.lower() in {"false", "0", "0x0", "0x00000000"}:
        return False
    raise ValueError("UNRESOLVED_MANIFEST_BOOLEAN: " + value)

def _sdk_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        result = int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError as exc:
        raise ValueError("UNRESOLVED_SDK_VERSION: " + value) from exc
    if result < 1:
        raise ValueError("INVALID_SDK_VERSION")
    return result

def _full_component_name(name: str, package: str) -> str:
    if name.startswith("."):
        return package + name
    return name if "." in name else package + "." + name

def resolve_manifest_resources(root: Any, apk: Any) -> list[dict]:
    """Resolve only unanimous resource values; never pick an arbitrary locale/API.

    Original references and all configurations are retained for auditing. A
    configuration-dependent scalar cannot be represented faithfully by one
    locked feature value and is therefore rejected from the complete cohort.
    """
    relevant = {"name", "permission", "readPermission", "writePermission", "enabled",
                "exported", "targetSdkVersion", "minSdkVersion", "targetActivity"}
    records, parser = [], None
    for element in root.iter():
        for attribute, original in list(element.attrib.items()):
            if _local(attribute) not in relevant or not original.startswith("@"):
                continue
            if parser is None:
                parser = apk.get_android_resources()
            if parser is None or not re.fullmatch(r"@[0-9a-fA-F]{8}", original):
                raise ValueError("UNRESOLVED_MANIFEST_RESOURCE: " + original)
            configs = parser.get_resolved_res_configs(int(original[1:], 16))
            values = {str(value) for _, value in configs}
            if len(values) != 1 or next(iter(values)).startswith("@"):
                raise ValueError("AMBIGUOUS_MANIFEST_RESOURCE: " + original)
            resolved = next(iter(values))
            records.append({"element": _local(element.tag), "attribute": _local(attribute),
                            "original_reference": original, "resolved_value": resolved,
                            "configurations": [{"config": str(config), "value": str(value)} for config, value in configs]})
            element.set(attribute, resolved)
    return records

def extract_permissions(root: Any, features: dict[str, float]) -> dict:
    requested_elements = [e for e in root if _local(e.tag) in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}]
    requested = sorted({_attr(e, "name") for e in requested_elements if _attr(e, "name")})
    definitions = {_attr(e, "name"): _attr(e, "protectionLevel") or "normal" for e in root
                   if _local(e.tag) == "permission" and _attr(e, "name")}
    platform = sorted(set(requested) & PLATFORM.keys())
    custom = sorted((set(requested) & definitions.keys()) - PLATFORM.keys())
    unknown = sorted(set(requested) - set(platform) - set(custom))
    dangerous = [name for name in platform if PLATFORM[name]["base_protection"] == "dangerous"]
    for alias, full_name in PERMISSION_SEED.items():
        features["perm_" + alias] = float(full_name in requested)
    features.update(p_total_count=float(len(requested)), p_platform_count=float(len(platform)),
                    p_custom_count=float(len(custom)), p_dangerous_count=float(len(dangerous)),
                    p_sensitive_count=float(len(set(requested) & SENSITIVE_PERMISSIONS)))
    return {"requested": requested, "platform": platform, "custom_confirmed_local": custom,
            "unclassified": unknown, "unclassified_count": len(unknown), "dangerous_reference": dangerous,
            "defined_by_apk": definitions, "outside_seed": sorted(set(requested) - set(PERMISSION_SEED.values())),
            "uses_permission_declarations": [{"name": _attr(e, "name"), "tag": _local(e.tag),
                                              "max_sdk_version": _attr(e, "maxSdkVersion"),
                                              "uses_permission_flags": _attr(e, "usesPermissionFlags")} for e in requested_elements]}

def _effective_permissions(component: Any, application_permission: str | None) -> dict:
    kind = _local(component.tag)
    declared = _attr(component, "permission")
    # Android documentation defines alias permission independently of target.
    # An alias without its own permission has no alias access permission.
    inherited = None if kind == "activity-alias" else application_permission
    effective = declared if declared is not None else inherited
    result = {"declared": declared, "application": application_permission,
              "effective": effective, "read": None, "write": None, "paths": []}
    if kind == "provider":
        read, write = _attr(component, "readPermission"), _attr(component, "writePermission")
        result["read"] = read if read is not None else effective
        result["write"] = write if write is not None else effective
        for path in _children(component, "path-permission"):
            general = _attr(path, "permission")
            rp, wp = _attr(path, "readPermission"), _attr(path, "writePermission")
            result["paths"].append({"path": _attr(path, "path"), "path_prefix": _attr(path, "pathPrefix"),
                                    "path_pattern": _attr(path, "pathPattern"),
                                    "read": rp if rp is not None else general,
                                    "write": wp if wp is not None else general})
        result["any_protection"] = bool(result["read"] or result["write"] or
                                        any(p["read"] or p["write"] for p in result["paths"]))
    else:
        result["any_protection"] = bool(effective)
    return result

def extract_components_and_intents(root: Any, features: dict[str, float], reference_api: int = REFERENCE_API) -> dict:
    package = root.get("package", "")
    sdk = next(iter(_children(root, "uses-sdk")), None)
    min_sdk = _sdk_int(_attr(sdk, "minSdkVersion") if sdk is not None else None, 1)
    target_sdk = _sdk_int(_attr(sdk, "targetSdkVersion") if sdk is not None else None, min_sdk)
    application = next(iter(_children(root, "application")), None)
    if application is None:
        raise ValueError("MISSING_APPLICATION")
    application_permission = _attr(application, "permission")
    application_enabled = _boolean(_attr(application, "enabled"), True)
    evidence, warnings, all_actions, filter_count, names_seen = [], [], [], 0, set()
    for component in application:
        kind = _local(component.tag)
        if kind not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        raw_name = _attr(component, "name")
        if not raw_name:
            raise ValueError("MISSING_COMPONENT_NAME")
        name = _full_component_name(raw_name, package)
        # Duplicate declarations and missing alias targets have ambiguous parser
        # merge semantics; reject rather than make an undocumented count choice.
        if name in names_seen:
            raise ValueError("DUPLICATE_COMPONENT_NAME: " + name)
        if kind == "activity-alias":
            target = _attr(component, "targetActivity")
            if not target or _full_component_name(target, package) not in {
                entry["name"] for entry in evidence if entry["type"] == "activity"
            }:
                raise ValueError("MISSING_OR_LATER_ALIAS_TARGET: " + name)
        names_seen.add(name)
        filters = _children(component, "intent-filter")
        actions = [_attr(a, "name") for f in filters for a in _children(f, "action") if _attr(a, "name")]
        all_actions.extend(actions)
        filter_count += len(filters)
        declared_exported = _attr(component, "exported")
        missing_required = declared_exported is None and bool(filters) and target_sdk >= 31 and reference_api >= 31 and kind != "provider"
        if kind == "provider" and reference_api < 17:
            exported, export_rule = True, "provider API<=16 treats exported as true"
        elif declared_exported is not None:
            exported, export_rule = _boolean(declared_exported), "explicit"
        elif kind == "provider":
            exported, export_rule = target_sdk < 17, "provider default depends on targetSdk<17 at reference API>=17"
        else:
            exported, export_rule = bool(filters), "activity/service/receiver/alias default: has intent-filter"
        if missing_required:
            warnings.append({"code": "MISSING_REQUIRED_EXPORTED", "component": name,
                             "message": "targetSdk>=31 with filter: manifest is not installability-validated; legacy structural default retained"})
        permissions = _effective_permissions(component, application_permission)
        feature_kind = "activity" if kind == "activity-alias" else kind
        features[f"c_{feature_kind}_count"] += 1.0
        features[f"c_{feature_kind}_exported"] += float(exported)
        features["c_protected_count"] += float(permissions["any_protection"])
        evidence.append({"type": kind, "name": name, "target_activity": _attr(component, "targetActivity"),
                         "exported_declared": declared_exported, "exported_inferred": exported,
                         "exported_rule": export_rule, "reference_api": reference_api,
                         "missing_required_exported": missing_required,
                         "enabled_effective": application_enabled and _boolean(_attr(component, "enabled"), True),
                         "permissions": permissions, "actions": actions,
                         "metadata": [{"name": _attr(e, "name"), "resource": _attr(e, "resource"),
                                       "value": _attr(e, "value")} for e in _children(component, "meta-data")]})
    features["c_total_exported"] = sum(features[f"c_{kind}_exported"] for kind in ("activity", "service", "receiver", "provider"))
    for action in set(all_actions) & set(INTENT_SEED):
        features[intent_feature_name(action)] = 1.0
    features["i_filter_count"] = float(filter_count)
    features["i_seed_action_count"] = float(sum(a in INTENT_SEED for a in all_actions))
    features["i_outside_seed_action_count"] = float(sum(a not in INTENT_SEED for a in all_actions))
    enriched = {
        "accessibility_service_configuration": any(e["type"] == "service" and e["permissions"]["effective"] == "android.permission.BIND_ACCESSIBILITY_SERVICE" and "android.accessibilityservice.AccessibilityService" in e["actions"] for e in evidence),
        "notification_listener_configuration": any(e["type"] == "service" and e["permissions"]["effective"] == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" and "android.service.notification.NotificationListenerService" in e["actions"] for e in evidence),
        "device_admin_receiver_configuration": any(e["type"] == "receiver" and e["permissions"]["effective"] == "android.permission.BIND_DEVICE_ADMIN" and "android.app.action.DEVICE_ADMIN_ENABLED" in e["actions"] and any(m["name"] == "android.app.device_admin" and m["resource"] for m in e["metadata"]) for e in evidence),
    }
    return {"target_sdk": target_sdk, "min_sdk": min_sdk, "reference_api": reference_api,
            "components": evidence, "warnings": warnings, "actions": all_actions,
            "outside_seed_actions": sorted(set(all_actions) - set(INTENT_SEED)),
            "enriched_evidence_only": enriched,
            "note": "Exported count describes declaration/default, including disabled components; permission count means some protection, not full access prevention. Enriched booleans do not enter B_core and do not prove activation."}

def _raw_method(method: Any) -> Any:
    return method.get_method() if hasattr(method, "get_method") else method

def method_parts(method: Any) -> tuple[str, str, str]:
    method = _raw_method(method)
    values = []
    for getter in ("get_class_name", "get_name", "get_descriptor"):
        value = getattr(method, getter)()
        values.append(value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value))
    values[2] = values[2].replace(" ", "")
    return tuple(values)

def matching_families(owner: str, method: str, descriptor: str) -> dict[str, list[str]]:
    descriptor = descriptor.replace(" ", "")
    result = {}
    for family, rules in COMPILED_RULES.items():
        subtypes = {subtype for ro, rm, rd, subtype in rules if ro.fullmatch(owner) and rm.fullmatch(method) and rd.fullmatch(descriptor)}
        if subtypes:
            result[family] = sorted(subtypes)
    return result

def extract_api_families(analysis: Any, dex_method_ids: dict[int, str], features: dict[str, float]) -> dict:
    callsites = {family: set() for family in API_RULES}
    samples = {family: [] for family in API_RULES}
    total_xrefs, matched_unique = 0, set()
    subtype_counts, callee_subtypes = {}, {}
    for callee in analysis.get_methods():
        owner, method, descriptor = method_parts(callee)
        matches = matching_families(owner, method, descriptor)
        refs = list(callee.get_xref_from())
        total_xrefs += len(refs)
        if not matches or not refs:
            continue
        callee_signature = owner + "->" + method + descriptor
        for family, subtypes in matches.items():
            callee_subtypes[family, callee_signature] = subtypes
        for _, caller, offset in refs:
            raw_caller = _raw_method(caller)
            dex_name = dex_method_ids.get(id(raw_caller))
            if dex_name is None:
                raise ValueError("UNRESOLVED_CALLER_DEX")
            co, cm, cd = method_parts(raw_caller)
            caller_signature = co + "->" + cm + cd
            key = (dex_name, caller_signature, int(offset), callee_signature)
            matched_unique.add(key)
            for family, subtypes in matches.items():
                if key in callsites[family]:
                    continue
                callsites[family].add(key)
                for subtype in subtypes:
                    if subtype:
                        subtype_counts[subtype] = subtype_counts.get(subtype, 0) + 1
    for family in API_RULES:
        features["api_" + family] = float(bool(callsites[family]))
        features["api_" + family + "_count"] = math.log1p(len(callsites[family]))
        # Select canonical first N only after sorting, since Androguard xrefs
        # are sets whose iteration order can differ across Python processes.
        samples[family] = [{"dex": dex, "caller": caller, "offset_bytes": offset,
                            "callee": callee, "subtypes": callee_subtypes[family, callee]}
                           for dex, caller, offset, callee in sorted(callsites[family])[:MAX_EXAMPLE_CALLSITES]]
    return {"callsites_count": {f: len(callsites[f]) for f in API_RULES}, "callsites_examples": samples,
            "example_limit_per_family": MAX_EXAMPLE_CALLSITES, "example_lists_may_be_truncated": True,
            "total_xref_entries": total_xrefs, "matched_unique_callsites": len(matched_unique),
            "subtype_counts": subtype_counts,
            "scope": "All successfully parsed root classes*.dex; app and third-party library calls together. Strings/fields are not method evidence."}

def _record() -> dict:
    return {"status": "failed", "sha256": None, "package_name": None, "version_code": None,
            "schema_hash": SCHEMA_HASH, "feature_space_id": FEATURE_SPACE_ID, "features": None,
            "evidence": {}, "elapsed_seconds": 0.0, "error_code": None}

def preflight_apk(path: Path, max_mb: int = 200) -> dict:
    if path.suffix.lower() != ".apk":
        raise ValueError("UNSUPPORTED_FORMAT")
    if path.stat().st_size > max_mb * 1024 * 1024:
        raise ValueError("APK_SIZE_LIMIT")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 10000 or len({e.filename for e in entries}) != len(entries):
            raise ValueError("ZIP_ENTRY_LIMIT_OR_DUPLICATES")
        if sum(e.file_size for e in entries) > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("ZIP_UNCOMPRESSED_LIMIT")
        for entry in entries:
            if entry.flag_bits & 1:
                raise ValueError("ENCRYPTED_ZIP_UNSUPPORTED")
            if entry.file_size > 200 * 1024 * 1024 or (entry.file_size > 1024 * 1024 and entry.file_size / max(entry.compress_size, 1) > 1000):
                raise ValueError("ZIP_EXPANSION_LIMIT")
        names = {entry.filename for entry in entries}
        if "AndroidManifest.xml" not in names:
            raise ValueError("MISSING_MANIFEST")
        dex_names = sorted(n for n in names if DEX_PATTERN.fullmatch(n))
        return {"apk_size_bytes": path.stat().st_size, "zip_entries": len(entries), "dex_names": dex_names,
                "embedded_or_nonstandard_dex": sorted(n for n in names if n.lower().endswith(".dex") and n not in dex_names),
                "native_library_count": sum(n.startswith("lib/") and n.endswith(".so") for n in names)}

def _extract_in_process(path: str | Path) -> dict:
    """Worker only; callers should use extract_apk for resource limits."""
    started, result = time.perf_counter(), _record()
    phase = "manifest"
    try:
        from loguru import logger
        logger.disable("androguard")
        from androguard.core.apk import APK
        from androguard.core.dex import DEX
        from androguard.core.analysis.analysis import Analysis
        path = Path(path)
        result["sha256"] = sha256_file(path)
        result["evidence"]["archive"] = preflight_apk(path)
        apk = APK(str(path))
        if not apk.is_valid_APK():
            raise ValueError("INVALID_MANIFEST")
        root = apk.get_android_manifest_xml()
        root = root.getroot() if hasattr(root, "getroot") else root
        if root is None:
            raise ValueError("MISSING_PARSED_MANIFEST")
        result["package_name"] = apk.get_package() or None
        result["version_code"] = apk.get_androidversion_code()
        if root.get("split") or any(_local(e.tag) == "uses-split" for e in root):
            result.update(status="unsupported", error_code="SPLIT_APK_UNSUPPORTED")
            return result
        result["evidence"]["resolved_manifest_resources"] = resolve_manifest_resources(root, apk)
        features = empty_features()
        result["evidence"]["permissions"] = extract_permissions(root, features)
        result["evidence"]["manifest"] = extract_components_and_intents(root, features)
        result["evidence"]["manifest_features"] = {n: features[n] for g in ("P", "C", "I") for n in GROUPS[g] if n != "c_dex_count"}
        phase = "dex"
        dex_names = result["evidence"]["archive"]["dex_names"]
        if not dex_names:
            result.update(status="unsupported", error_code="NO_ROOT_DEX_UNSUPPORTED")
            return result
        api_by_dex = []
        with zipfile.ZipFile(path) as archive:
            for dex_name in dex_names:
                raw_dex = archive.read(dex_name)
                if not raw_dex.startswith(b"dex\n"):
                    raise ValueError("INVALID_DEX_HEADER: " + dex_name)
                dex = DEX(raw_dex)
                analysis, method_ids = Analysis(), {}
                # DEX.get_methods() returns MethodIdItem references in v4;
                # xref callers are the EncodedMethod objects from class bodies.
                for method in dex.get_encoded_methods():
                    method_ids[id(method)] = dex_name
                analysis.add(dex)
                analysis.create_xref()
                dex_features = empty_features()
                api_by_dex.append(extract_api_families(analysis, method_ids, dex_features))
                # Matchers use the owner+method+descriptor encoded in each call
                # reference, not cross-DEX class-hierarchy inference. The union
                # of independently scanned DEX callsites is therefore equivalent
                # for this schema and avoids holding every DEX analysis at once.
                del analysis, method_ids, dex, raw_dex, dex_features
                if "method" in locals():
                    del method
                gc.collect()
        features["c_dex_count"] = float(len(dex_names))
        merged = {"callsites_count": {}, "callsites_examples": {},
                  "example_limit_per_family": MAX_EXAMPLE_CALLSITES, "example_lists_may_be_truncated": True,
                  "total_xref_entries": sum(a["total_xref_entries"] for a in api_by_dex),
                  "matched_unique_callsites": sum(a["matched_unique_callsites"] for a in api_by_dex),
                  "subtype_counts": {}, "scope": api_by_dex[0]["scope"],
                  "dex_analysis_strategy": "Sequential per-DEX xrefs, union keyed by DEX+caller+offset+callee; no hierarchy inference",
                  "dex_scanned": dex_names}
        for family in API_RULES:
            count = sum(a["callsites_count"][family] for a in api_by_dex)
            merged["callsites_count"][family] = count
            examples = [e for a in api_by_dex for e in a["callsites_examples"][family]]
            merged["callsites_examples"][family] = sorted(examples, key=lambda e: (e["dex"], e["caller"], e["offset_bytes"], e["callee"]))[:MAX_EXAMPLE_CALLSITES]
            features["api_" + family], features["api_" + family + "_count"] = float(count > 0), math.log1p(count)
        for a in api_by_dex:
            for subtype, count in a["subtype_counts"].items():
                merged["subtype_counts"][subtype] = merged["subtype_counts"].get(subtype, 0) + count
        result["evidence"]["api"] = merged
        features.update(derive_group_b(features))
        validate_features(features)
        result.update(status="ok", features=features)
        result["evidence"]["analysis_complete"] = {"manifest": True, "root_dex": True, "native_code": False, "embedded_code": False}
        result["evidence"].pop("manifest_features", None)
    except Exception as exc:
        result.update(status="partial" if phase == "dex" else "failed", features=None,
                      error_code="DEX_ANALYSIS_FAILED" if phase == "dex" else "MANIFEST_ANALYSIS_FAILED")
        result["evidence"]["exception"] = {"type": type(exc).__name__, "message": str(exc)[:2000]}
    finally:
        result["elapsed_seconds"] = time.perf_counter() - started
    return result

def extract_apk(path: str | Path, timeout: float = 300, max_mb: int = 200) -> dict:
    started, result = time.perf_counter(), _record()
    path = Path(path).resolve()
    result["evidence"]["input_path"] = str(path)
    process = None
    try:
        if timeout <= 0 or max_mb <= 0:
            raise ValueError("INVALID_RESOURCE_LIMIT")
        if not path.is_file():
            raise ValueError("APK_NOT_FOUND")
        archive_info = preflight_apk(path, max_mb=max_mb)
        result["sha256"] = sha256_file(path)
        with tempfile.TemporaryDirectory(prefix="androidml_extract_") as temp:
            temp = Path(temp)
            output_path = temp / "result.json"
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
            env["PYTHONIOENCODING"] = "utf-8"
            with (temp / "stdout.log").open("w", encoding="utf-8") as stdout, (temp / "stderr.log").open("w", encoding="utf-8") as stderr:
                process = subprocess.Popen([sys.executable, "-m", "androidml.extraction_worker", str(path), str(output_path)],
                                           stdout=stdout, stderr=stderr, env=env,
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                memory_monitor = None
                try:
                    import psutil
                    memory_monitor = psutil.Process(process.pid)
                except ImportError:
                    pass
                peak_rss = 0
                while process.poll() is None:
                    if time.perf_counter() - started > timeout:
                        _kill_worker_tree(process)
                        process.wait(timeout=10)
                        result.update(status="timeout", error_code="EXTRACTION_TIMEOUT")
                        break
                    if memory_monitor is not None:
                        try:
                            # Windows venv redirector starts a Python child. RSS
                            # and termination must cover the entire process tree.
                            rss = sum(p.memory_info().rss for p in [memory_monitor, *memory_monitor.children(recursive=True)] if p.is_running())
                            peak_rss = max(peak_rss, rss)
                            if rss > MAX_WORKER_RSS_MB * 1024 * 1024:
                                _kill_worker_tree(process)
                                process.wait(timeout=10)
                                result.update(status="failed", error_code="WORKER_MEMORY_LIMIT")
                                break
                        except psutil.NoSuchProcess:
                            pass
                    time.sleep(0.10)
            if result["error_code"] is None:
                if process.returncode == 0 and output_path.is_file():
                    result = json.loads(output_path.read_text(encoding="utf-8"))
                    if result.get("sha256") != sha256_file(path):
                        result.update(status="failed", error_code="INPUT_CHANGED_DURING_EXTRACTION", features=None)
                    if result.get("status") == "ok":
                        validate_features(result["features"])
                else:
                    result.update(status="failed", error_code="WORKER_CRASH")
            result["evidence"]["resource_limits"] = {"timeout_seconds": timeout, "max_apk_mb": max_mb,
                "max_uncompressed_bytes": MAX_UNCOMPRESSED_BYTES, "worker_rss_limit_mb": MAX_WORKER_RSS_MB,
                "rss_monitor_active": memory_monitor is not None, "peak_observed_worker_rss_bytes": peak_rss,
                "rss_limit_kind": "sampled process-tree watchdog; not an OS-enforced hard memory ceiling"}
            if result["status"] != "ok":
                result["features"] = None
                result["evidence"]["worker_stderr_tail"] = (temp / "stderr.log").read_text(encoding="utf-8", errors="replace")[-2000:]
            result["evidence"].setdefault("archive", archive_info)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        code = str(exc) if isinstance(exc, ValueError) else type(exc).__name__.upper()
        result.update(status="unsupported" if code in {"UNSUPPORTED_FORMAT", "APK_SIZE_LIMIT", "ZIP_UNCOMPRESSED_LIMIT", "ZIP_EXPANSION_LIMIT", "ENCRYPTED_ZIP_UNSUPPORTED"} else "failed", features=None, error_code=code)
    finally:
        if process is not None and process.poll() is None:
            _kill_worker_tree(process)
            process.wait(timeout=10)
        result["elapsed_seconds"] = time.perf_counter() - started
    return result

def _kill_worker_tree(process: subprocess.Popen) -> None:
    """Terminate child parsers as well as the Windows virtualenv redirector."""
    try:
        import psutil
        parent = psutil.Process(process.pid)
        descendants = parent.children(recursive=True)
        for child in reversed(descendants):
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        try:
            parent.kill()
        except psutil.NoSuchProcess:
            pass
        psutil.wait_procs(descendants, timeout=5)
    except ImportError:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=15)
        else:
            process.kill()
