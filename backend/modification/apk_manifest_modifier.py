"""
apk_manifest_modifier.py — Safe, defensive manifest-only remediation.

Strategy
--------
An APK is a ZIP archive. AndroidManifest.xml inside it is stored in Android
Binary XML (AXML) format. Androguard already has a full AXML decoder and
exposes the parsed manifest as an lxml.etree.Element via get_android_manifest_xml().

We use lxml throughout to avoid namespace mangling. The modified manifest is
serialised back to plain-text XML and stored in a new APK zip.

Androguard reads both binary and plain-text XML manifests when parsing an APK,
so re-analysis via extract_static_features() works correctly on the modified file.

The resulting APK is suitable for re-analysis only, not for device installation
(which requires binary AXML and a valid signature). The UI discloses this.
"""

import os
import zipfile
from androguard.core.apk import APK
import lxml.etree as lxml_et


# Permissions that can be offered as remediation candidates
REMEDIABLE_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_PHONE_STATE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}

# Short-name → full permission name mapping
SHORT_TO_FULL = {p.split(".")[-1]: p for p in REMEDIABLE_PERMISSIONS}


def _normalise_permission(name: str) -> str:
    """Accept either 'READ_SMS' or 'android.permission.READ_SMS'."""
    if "." not in name:
        return SHORT_TO_FULL.get(name, name)
    return name


def get_remediable_permissions(apk_path: str) -> list:
    """
    Returns the subset of an APK's permissions that can be remediated.
    """
    apk = APK(apk_path)
    declared = set(apk.get_permissions())

    HIGH_RISK = {
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
    }
    DESCRIPTIONS = {
        "android.permission.READ_SMS":               "Can read all private text messages (SMS).",
        "android.permission.SEND_SMS":               "Can secretly send SMS messages.",
        "android.permission.RECEIVE_SMS":            "Can intercept incoming SMS (e.g. steal 2FA codes).",
        "android.permission.READ_CONTACTS":          "Can read all contacts and phone numbers.",
        "android.permission.WRITE_CONTACTS":         "Can modify or delete contacts.",
        "android.permission.READ_CALL_LOG":          "Can read incoming/outgoing call history.",
        "android.permission.WRITE_CALL_LOG":         "Can modify or delete call history.",
        "android.permission.ACCESS_FINE_LOCATION":   "Tracks precise GPS location.",
        "android.permission.ACCESS_COARSE_LOCATION": "Tracks approximate location.",
        "android.permission.RECORD_AUDIO":           "Can secretly turn on the microphone.",
        "android.permission.CAMERA":                 "Can secretly activate the camera.",
        "android.permission.READ_PHONE_STATE":       "Reads hardware IDs — used for device tracking.",
        "android.permission.GET_ACCOUNTS":           "Lists all accounts registered on the device.",
        "android.permission.SYSTEM_ALERT_WINDOW":    "Can draw overlays over other apps (overlay attack).",
        "android.permission.PROCESS_OUTGOING_CALLS": "Can intercept and redirect outgoing calls.",
        "android.permission.READ_EXTERNAL_STORAGE":  "Can read files from external storage.",
        "android.permission.WRITE_EXTERNAL_STORAGE": "Can write/delete files on external storage.",
    }

    results = []
    for perm in sorted(declared):
        if perm in HIGH_RISK:
            risk = "High"
        elif perm in DESCRIPTIONS:
            risk = "Medium"
        else:
            risk = "Low"
            
        results.append({
            "full_name":   perm,
            "short_name":  perm.split(".")[-1],
            "risk":        risk,
            "description": DESCRIPTIONS.get(perm, "Standard or custom Android permission."),
            "present":     True,
        })
        
    def risk_score(r):
        if r["risk"] == "High": return 0
        if r["risk"] == "Medium": return 1
        return 2
        
    results.sort(key=lambda x: (risk_score(x), x["short_name"]))
    return results


def apply_manifest_remediation(
    original_apk_path: str,
    output_apk_path: str,
    permissions_to_remove: list,
) -> dict:
    """
    Creates a modified APK with selected permissions stripped from the manifest.

    The original APK is never modified — output is a new file.

    Returns:
        dict with keys: success (bool), changes_applied (list), error (str|None)
    """
    ANDROID_NS = "http://schemas.android.com/apk/res/android"
    NAME_ATTR  = f"{{{ANDROID_NS}}}name"

    # Normalise all requested permissions to full names
    to_remove = {_normalise_permission(p) for p in permissions_to_remove}

    if not to_remove:
        return {"success": False, "changes_applied": [], "error": "No permissions selected for removal."}

    if not os.path.exists(original_apk_path):
        return {"success": False, "changes_applied": [], "error": "Original APK not found."}

    try:
        # ── Step 1: Parse the original APK with Androguard ───────────────────
        apk = APK(original_apk_path)

        # ── Step 2: Obtain the lxml manifest element ──────────────────────────
        # Androguard returns lxml.etree.Element from get_android_manifest_xml()
        root = apk.get_android_manifest_xml()
        if root is None:
            return {
                "success":         False,
                "changes_applied": [],
                "error":           "Could not parse AndroidManifest.xml from this APK.",
            }

        # ── Step 3: Find and remove selected <uses-permission> nodes ─────────
        # Uses .iter() to handle any nesting level, though permissions are
        # typically direct children of <manifest>.
        changes_applied = []
        nodes_to_remove = []

        for elem in root.iter():
            # In Androguard's lxml tree: tag names are plain strings (no ns prefix),
            # but attribute names use the full Clark notation {ns}name.
            tag = str(elem.tag)
            # Strip namespace if present (e.g. '{ns}uses-permission' → 'uses-permission')
            if "{" in tag:
                tag = tag.split("}", 1)[1]
            if tag == "uses-permission":
                perm_name = elem.get(NAME_ATTR) or elem.get("name", "")
                if perm_name in to_remove:
                    nodes_to_remove.append(elem)
                    changes_applied.append({
                        "type":        "permission_removal",
                        "target":      perm_name,
                        "short_name":  perm_name.split(".")[-1],
                        "description": f'Removed <uses-permission android:name="{perm_name}"/>',
                        "original":    "Present",
                        "modified":    "Removed",
                    })

        if not nodes_to_remove:
            return {
                "success":         False,
                "changes_applied": [],
                "error": (
                    "None of the selected permissions were found in the manifest. "
                    "They may already be absent or use a non-standard format."
                ),
            }

        for node in nodes_to_remove:
            root.remove(node)

        # ── Step 4: Serialise the modified lxml tree ──────────────────────────
        modified_xml_bytes = lxml_et.tostring(
            root,
            pretty_print=True,
            xml_declaration=True,
            encoding="utf-8",
        )

        # ── Step 5: Write a new APK — copy zip + replace manifest entry ───────
        with zipfile.ZipFile(original_apk_path, "r") as src_zip:
            with zipfile.ZipFile(output_apk_path, "w", zipfile.ZIP_DEFLATED) as dst_zip:
                for item in src_zip.infolist():
                    if item.filename == "AndroidManifest.xml":
                        dst_zip.writestr(item.filename, modified_xml_bytes)
                    else:
                        dst_zip.writestr(item, src_zip.read(item.filename))

        return {
            "success":         True,
            "changes_applied": changes_applied,
            "error":           None,
        }

    except Exception as e:
        # Clean up partial output if it was created
        if os.path.exists(output_apk_path):
            try:
                os.remove(output_apk_path)
            except Exception:
                pass
        return {
            "success":         False,
            "changes_applied": [],
            "error":           str(e),
        }
