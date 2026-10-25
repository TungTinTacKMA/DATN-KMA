"""Locked, documented 163-dimensional static feature space; incompatible with v1.

The permission table is a checked-in Android 15 source snapshot. Classification
describes that reference release, not the device on which an APK would run.
"""
from __future__ import annotations

import hashlib
import json
import math
import numbers
import re
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "2.0.0"
FEATURE_SPACE_ID = "android-static-pcia-bcore-v2-android15"
REFERENCE_VERSION = "AOSP android-15.0.0_r1; API 35; Androguard 4.1.3"
REFERENCE_API = 35

PERMISSION_ALIASES = (
    "READ_CALENDAR WRITE_CALENDAR CAMERA READ_CONTACTS WRITE_CONTACTS GET_ACCOUNTS "
    "ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION ACCESS_BACKGROUND_LOCATION RECORD_AUDIO "
    "READ_PHONE_STATE READ_PHONE_NUMBERS CALL_PHONE ANSWER_PHONE_CALLS READ_CALL_LOG "
    "WRITE_CALL_LOG ADD_VOICEMAIL USE_SIP PROCESS_OUTGOING_CALLS BODY_SENSORS "
    "ACTIVITY_RECOGNITION SEND_SMS RECEIVE_SMS READ_SMS RECEIVE_WAP_PUSH RECEIVE_MMS "
    "READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE ACCESS_MEDIA_LOCATION READ_MEDIA_IMAGES "
    "READ_MEDIA_VIDEO READ_MEDIA_AUDIO POST_NOTIFICATIONS NEARBY_WIFI_DEVICES BLUETOOTH_SCAN "
    "BLUETOOTH_CONNECT BLUETOOTH_ADVERTISE SYSTEM_ALERT_WINDOW WRITE_SETTINGS "
    "REQUEST_INSTALL_PACKAGES INSTALL_PACKAGES DELETE_PACKAGES MANAGE_EXTERNAL_STORAGE "
    "QUERY_ALL_PACKAGES PACKAGE_USAGE_STATS BIND_ACCESSIBILITY_SERVICE "
    "BIND_NOTIFICATION_LISTENER_SERVICE BIND_DEVICE_ADMIN WRITE_SECURE_SETTINGS INTERNET "
    "ACCESS_NETWORK_STATE ACCESS_WIFI_STATE CHANGE_WIFI_STATE CHANGE_NETWORK_STATE "
    "RECEIVE_BOOT_COMPLETED WAKE_LOCK VIBRATE FOREGROUND_SERVICE DISABLE_KEYGUARD GET_TASKS "
    "KILL_BACKGROUND_PROCESSES RESTART_PACKAGES MOUNT_UNMOUNT_FILESYSTEMS WRITE_APN_SETTINGS "
    "READ_LOGS BLUETOOTH BLUETOOTH_ADMIN NFC SET_WALLPAPER EXPAND_STATUS_BAR BROADCAST_STICKY"
).split()
PERMISSION_SEED = {
    alias: ("com.android.voicemail.permission.ADD_VOICEMAIL" if alias == "ADD_VOICEMAIL"
            else "android.permission." + alias) for alias in PERMISSION_ALIASES
}
SENSITIVE_PERMISSIONS = {PERMISSION_SEED[x] for x in PERMISSION_ALIASES[37:49]}
P_COUNTS = ["p_total_count", "p_platform_count", "p_custom_count", "p_dangerous_count", "p_sensitive_count"]
C_FEATURES = [f"c_{kind}_{suffix}" for kind in ("activity", "service", "receiver", "provider")
              for suffix in ("count", "exported")] + ["c_total_exported", "c_protected_count", "c_dex_count"]
INTENT_SEED = (
    "android.intent.action.MAIN", "android.intent.action.VIEW", "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.USER_PRESENT", "android.intent.action.SCREEN_ON", "android.intent.action.SCREEN_OFF",
    "android.intent.action.PACKAGE_ADDED", "android.intent.action.PACKAGE_REMOVED", "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.MY_PACKAGE_REPLACED", "android.intent.action.NEW_OUTGOING_CALL", "android.intent.action.PHONE_STATE",
    "android.intent.action.SEND", "android.intent.action.SENDTO", "android.intent.action.DIAL", "android.intent.action.CALL",
    "android.intent.action.BATTERY_LOW", "android.intent.action.BATTERY_CHANGED", "android.intent.action.POWER_CONNECTED",
    "android.intent.action.POWER_DISCONNECTED", "android.intent.action.MEDIA_MOUNTED", "android.intent.action.TIME_SET",
    "android.intent.action.TIMEZONE_CHANGED", "android.intent.action.USER_INITIALIZE", "android.provider.Telephony.SMS_RECEIVED",
    "android.provider.Telephony.SMS_DELIVER", "android.provider.Telephony.WAP_PUSH_RECEIVED", "android.net.conn.CONNECTIVITY_CHANGE",
    "android.accessibilityservice.AccessibilityService", "android.service.notification.NotificationListenerService",
    "android.app.action.DEVICE_ADMIN_ENABLED", "android.intent.action.QUICKBOOT_POWERON",
)

def intent_feature_name(action: str) -> str:
    if action not in INTENT_SEED:
        raise KeyError(action)
    return "intent_" + action.rsplit(".", 1)[-1]

# Owner and method are full matches; descriptor is validated as a complete DEX
# method descriptor. Each rule deliberately accepts all overloads of its named
# methods. No free substring matching, field constant or string URI is a method.
DESCRIPTOR_PATTERN = r"\((?:\[*(?:[ZBSCIJFD]|L[^;()]+;))*\)(?:V|\[*(?:[ZBSCIJFD]|L[^;()]+;))"
def _rule(owner: str, method: str, subtype: str = "") -> dict:
    return {"owner": owner, "method": method, "descriptor": DESCRIPTOR_PATTERN, "subtype": subtype}

API_RULES = {
    "network": [
        _rule(r"Ljava/net/URL;", r"openConnection|openStream"),
        _rule(r"Ljava/net/(?:HttpURLConnection|URLConnection);", r"connect|getInputStream|getOutputStream"),
        _rule(r"Ljava/net/Socket;", r"<init>|connect|getInputStream|getOutputStream"),
        _rule(r"Ljava/net/InetAddress;", r"getByName|getAllByName"),
        _rule(r"Lokhttp3/(?:OkHttpClient|Call|RealCall);", r"newCall|execute|enqueue"),
        _rule(r"Lorg/apache/http/(?:client/HttpClient|impl/client/(?:DefaultHttpClient|AbstractHttpClient));", r"execute"),
        _rule(r"Landroid/webkit/WebView;", r"loadUrl|postUrl"),
    ],
    "sms": [
        _rule(r"Landroid/telephony/SmsManager;", r"sendTextMessage|sendMultipartTextMessage|sendDataMessage"),
        _rule(r"Landroid/telephony/SmsMessage;", r"createFromPdu"),
    ],
    "telephony": [_rule(r"Landroid/telephony/TelephonyManager;", r"getDeviceId|getImei|getMeid|getSubscriberId|getLine1Number|getSimSerialNumber|getNetworkOperator|getSimOperator|getCallState")],
    "device_info": [
        _rule(r"Landroid/provider/Settings\$Secure;", r"getString"),
        _rule(r"Landroid/net/wifi/WifiInfo;", r"getMacAddress"),
        _rule(r"Landroid/os/Build;", r"getSerial"),
        _rule(r"Landroid/app/ActivityManager;", r"getRunningAppProcesses"),
    ],
    "file_io": [
        _rule(r"Ljava/io/(?:FileOutputStream|FileInputStream|RandomAccessFile);", r"<init>|read|write"),
        _rule(r"Ljava/util/zip/ZipInputStream;", r"<init>|read|getNextEntry"),
        _rule(r"Landroid/os/Environment;", r"getExternalStorageDirectory|getExternalStoragePublicDirectory"),
        _rule(r"Landroid/content/(?:Context|ContextWrapper);", r"openFileOutput|openFileInput"),
    ],
    "persistence": [
        _rule(r"Landroid/app/AlarmManager;", r"set|setExact|setRepeating|setInexactRepeating|setAndAllowWhileIdle|setExactAndAllowWhileIdle|setAlarmClock"),
        _rule(r"Landroid/app/job/JobScheduler;", r"schedule|enqueue"),
        _rule(r"Landroid/content/(?:Context|ContextWrapper);", r"startService|startForegroundService"),
        _rule(r"Landroid/content/pm/PackageManager;", r"setComponentEnabledSetting"),
        _rule(r"Landroidx/work/WorkManager;", r"enqueue|enqueueUniqueWork|enqueueUniquePeriodicWork"),
    ],
    "dynamic_code": [
        _rule(r"Ldalvik/system/(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader);", r"<init>", "class_loader"),
        _rule(r"Ljava/lang/reflect/Method;", r"invoke", "reflection"),
        _rule(r"Ljava/lang/Class;", r"forName", "reflection"),
        _rule(r"Ljava/lang/(?:System|Runtime);", r"load|loadLibrary", "native_library"),
    ],
    "exec": [
        _rule(r"Ljava/lang/Runtime;", r"exec"),
        _rule(r"Ljava/lang/ProcessBuilder;", r"<init>|start"),
    ],
    "crypto": [
        _rule(r"Ljavax/crypto/Cipher;", r"doFinal"),
        _rule(r"Ljavax/crypto/spec/SecretKeySpec;", r"<init>"),
        _rule(r"Ljava/security/MessageDigest;", r"digest"),
        _rule(r"Landroid/util/Base64;", r"decode"),
    ],
    "accessibility": [
        _rule(r"Landroid/accessibilityservice/AccessibilityService;", r"performGlobalAction|getRootInActiveWindow|getWindows|dispatchGesture"),
        _rule(r"Landroid/view/accessibility/AccessibilityNodeInfo;", r"performAction|findAccessibilityNodeInfosByText|getText"),
    ],
    "overlay": [_rule(r"Landroid/view/WindowManager;", r"addView|updateViewLayout")],
    "package_query": [
        _rule(r"Landroid/content/pm/PackageManager;", r"getInstalledPackages|getInstalledApplications|getLaunchIntentForPackage|queryIntentActivities|getPackageInstaller"),
        _rule(r"Landroid/content/pm/PackageInstaller;", r"createSession|openSession|uninstall"),
        _rule(r"Landroid/content/pm/PackageInstaller\$Session;", r"commit|openWrite"),
    ],
}
API_FAMILIES = tuple(API_RULES)
B_FEATURES = ("b_network b_sms b_device_info b_file b_persistence b_dynamic_code b_exec b_crypto "
              "b_accessibility b_overlay b_package_mgmt b_notif_listen b_device_admin "
              "b_combo_sms_net b_combo_id_net b_combo_persist_net b_combo_overlay_acc").split()

B_DEPENDENCIES = {
    "b_network": ["perm_INTERNET", "api_network"],
    "b_sms": ["perm_SEND_SMS", "perm_RECEIVE_SMS", "perm_READ_SMS", "api_sms", "intent_SMS_RECEIVED"],
    "b_device_info": ["perm_READ_PHONE_STATE", "api_telephony", "api_device_info"],
    "b_file": ["perm_WRITE_EXTERNAL_STORAGE", "perm_READ_EXTERNAL_STORAGE", "perm_MANAGE_EXTERNAL_STORAGE", "api_file_io"],
    "b_persistence": ["intent_BOOT_COMPLETED", "perm_RECEIVE_BOOT_COMPLETED", "c_service_count", "api_persistence"],
    "b_dynamic_code": ["api_dynamic_code"], "b_exec": ["api_exec"], "b_crypto": ["api_crypto"],
    "b_accessibility": ["perm_BIND_ACCESSIBILITY_SERVICE", "intent_AccessibilityService", "api_accessibility"],
    "b_overlay": ["perm_SYSTEM_ALERT_WINDOW", "api_overlay"],
    "b_package_mgmt": ["perm_INSTALL_PACKAGES", "perm_REQUEST_INSTALL_PACKAGES", "perm_DELETE_PACKAGES", "perm_QUERY_ALL_PACKAGES", "api_package_query"],
    "b_notif_listen": ["perm_BIND_NOTIFICATION_LISTENER_SERVICE", "intent_NotificationListenerService"],
    "b_device_admin": ["perm_BIND_DEVICE_ADMIN", "intent_DEVICE_ADMIN_ENABLED"],
    "b_combo_sms_net": ["b_sms", "b_network"], "b_combo_id_net": ["b_device_info", "b_network"],
    "b_combo_persist_net": ["b_persistence", "b_network"], "b_combo_overlay_acc": ["b_overlay", "b_accessibility"],
}
GROUPS = {
    "P": ["perm_" + x for x in PERMISSION_ALIASES] + P_COUNTS,
    "C": C_FEATURES,
    "I": [intent_feature_name(x) for x in INTENT_SEED] + ["i_filter_count", "i_seed_action_count", "i_outside_seed_action_count"],
    "A": [x for f in API_FAMILIES for x in ("api_" + f, "api_" + f + "_count")],
    "B": B_FEATURES,
}
FEATURE_NAMES = [name for names in GROUPS.values() for name in names]
assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES)) == 163
BINARY_NAMES = {name for name in FEATURE_NAMES if name.startswith(("perm_", "intent_", "b_")) or
                name.startswith("api_") and not name.endswith("_count")}
INTEGER_NAMES = set(FEATURE_NAMES) - BINARY_NAMES - {"api_" + f + "_count" for f in API_FAMILIES}

def empty_features() -> dict[str, float]:
    """Internal builder; an all-zero builder is not evidence of successful parsing."""
    return dict.fromkeys(FEATURE_NAMES, 0.0)

def derive_group_b(features: Mapping[str, float]) -> dict[str, float]:
    result = {}
    for name, dependencies in B_DEPENDENCIES.items():
        on = lambda x: float(result.get(x, features.get(x, 0))) > 0
        if name == "b_persistence":
            value = on(dependencies[0]) or on(dependencies[1]) or (on(dependencies[2]) and on(dependencies[3]))
        elif name.startswith("b_combo_"):
            value = all(on(x) for x in dependencies)
        else:
            value = any(on(x) for x in dependencies)
        result[name] = float(value)
    return result

def validate_features(features: Mapping[str, float]) -> None:
    if not isinstance(features, Mapping) or set(features) != set(FEATURE_NAMES):
        raise ValueError("FEATURE_SCHEMA_KEYS: exactly 163 canonical names are required")
    for name in FEATURE_NAMES:
        value = features[name]
        if isinstance(value, (bool, str)) or not isinstance(value, numbers.Real) or not math.isfinite(float(value)) or value < 0:
            raise ValueError("FEATURE_VALUE: " + name)
        if name in BINARY_NAMES and value not in (0, 1):
            raise ValueError("FEATURE_BINARY: " + name)
        if name in INTEGER_NAMES and float(value) != int(value):
            raise ValueError("FEATURE_INTEGER: " + name)
    if any(features[x] != value for x, value in derive_group_b(features).items()):
        raise ValueError("FEATURE_B_CORE_INCONSISTENT")
    for family in API_FAMILIES:
        if bool(features["api_" + family]) != (features["api_" + family + "_count"] > 0):
            raise ValueError("FEATURE_API_INCONSISTENT: " + family)
    for kind in ("activity", "service", "receiver", "provider"):
        if features[f"c_{kind}_exported"] > features[f"c_{kind}_count"]:
            raise ValueError("FEATURE_COMPONENT_INCONSISTENT")
    if features["c_total_exported"] != sum(features[f"c_{k}_exported"] for k in ("activity", "service", "receiver", "provider")):
        raise ValueError("FEATURE_EXPORTED_TOTAL")
    if features["p_platform_count"] + features["p_custom_count"] > features["p_total_count"] or features["p_dangerous_count"] > features["p_platform_count"]:
        raise ValueError("FEATURE_PERMISSION_TOTAL")

def _dictionary_payload() -> dict:
    lookup_file = ROOT / "configs/platform_permissions_android15.json"
    lookup = json.loads(lookup_file.read_text(encoding="utf-8"))
    definitions = []
    for group, names in GROUPS.items():
        for name in names:
            source, deps = "AndroidManifest.xml", []
            description = name
            if name.startswith("perm_"):
                full = PERMISSION_SEED[name[5:]]
                rule = f"1 iff unique uses-permission (including sdk-23 variant) contains exact {full}; no component protection attributes"
                description = full
            elif name in P_COUNTS:
                rule = {
                    "p_total_count": "Number of distinct requested full permission names, including unclassified names",
                    "p_platform_count": "Number of requested permissions found in pinned Android platform manifest",
                    "p_custom_count": "Number of requested non-platform permissions also explicitly defined by this APK; others remain unknown in evidence",
                    "p_dangerous_count": "Number of requested platform permissions with dangerous base protectionLevel in pinned reference",
                    "p_sensitive_count": "Number of requested names in the locked 12-name research-sensitive list; NOT an Android special-permission class",
                }[name]
            elif group == "C":
                rule = ("Count declared entry points; activity count includes each activity-alias once and each activity once; "
                        "exported uses explicit/default semantics at API 35, provider default targetSdk<17; "
                        "protected counts any effective access permission (provider read OR write OR path-specific); "
                        "this does not imply every access path is protected. DEX count = parsed root classes*.dex")
                if name == "c_total_exported":
                    deps = [f"c_{k}_exported" for k in ("activity", "service", "receiver", "provider")]
            elif name.startswith("intent_"):
                action = next(a for a in INTENT_SEED if intent_feature_name(a) == name)
                rule = "1 iff a component intent-filter contains exact action " + action
                description = action
            elif group == "I":
                rule = {"i_filter_count": "Count component intent-filter elements",
                        "i_seed_action_count": "Count action occurrences whose complete name belongs to seed (duplicates included)",
                        "i_outside_seed_action_count": "Count action occurrences outside seed; not necessarily custom actions"}[name]
            elif group == "A":
                source = "All root DEX; Androguard method xrefs"
                rule = "Unique callsite = (DEX, caller full signature, offset, callee full signature); full structured rule match; " + ("log1p(number of unique callsites)" if name.endswith("_count") else "1 iff at least one matched callsite")
            else:
                source, deps = "Derived only from P/C/I/A (B_core)", B_DEPENDENCIES[name]
                rule = ("OR(first two) OR (third > 0 AND fourth > 0)" if name == "b_persistence" else
                        "AND(dependencies > 0)" if name.startswith("b_combo_") else "OR(dependencies > 0)")
            definitions.append({"name": name, "index": len(definitions), "group": group,
                                "dtype": "binary" if name in BINARY_NAMES else "uint_count" if name in INTEGER_NAMES else "float_log1p_count",
                                "source": source, "rule": rule, "dependencies": deps,
                                "description": description, "reference_version": REFERENCE_VERSION})
    return {"schema_version": SCHEMA_VERSION, "feature_space_id": FEATURE_SPACE_ID,
            "n_features": 163, "reference_api": REFERENCE_API, "platform_lookup_sha256": hashlib.sha256(lookup_file.read_bytes()).hexdigest(),
            "platform_source_sha256": lookup["source_sha256"], "definitions": definitions,
            "sensitive_permission_names": sorted(SENSITIVE_PERMISSIONS), "api_rules": API_RULES,
            "component_rule_version": "component-v2.2-api35-alias-own-permission-provider-read-write-path-resources-unanimous",
            "manifest_resource_resolution": "Resolve feature-relevant attributes only when every resource configuration resolves to the same scalar; conflicting or missing values are rejected",
            "limitations": ["Static indications are not executed behavior", "Native and encrypted embedded code is outside DEX coverage",
                            "API dictionary is a fixed subset; calls through unlisted owners/overrides may be missed",
                            "Platform permission classification is relative to Android 15 snapshot, not runtime target"]}

_PAYLOAD = _dictionary_payload()
SCHEMA_HASH = hashlib.sha256(json.dumps(_PAYLOAD, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def feature_dictionary() -> dict:
    return {**_PAYLOAD, "schema_hash": SCHEMA_HASH}

def write_feature_dictionary(path: str | Path) -> None:
    Path(path).write_text(json.dumps(feature_dictionary(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
