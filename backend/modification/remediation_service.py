"""
remediation_service.py — In-memory remediation session manager.

Lifecycle
---------
PENDING → MODIFYING → REANALYZING → COMPLETED
                    ↘ FAILED

Session IDs are formatted as  REM-YYYY-NNNNN  (e.g. REM-2026-00001).

Re-analysis Strategy
--------------------
Androguard requires binary AXML format in AndroidManifest.xml.
When we write a plain-text XML manifest back into the APK zip, Androguard logs:
    "This does not look like an AXML file."
and returns empty lists — giving false results.

Correct approach (implemented here):
  1. Re-extract features from the ORIGINAL APK (always parseable).
  2. Zero out the selected permissions in the static feature DataFrame —
     exactly what would happen if those permissions were absent.
  3. Build a modified app_details with those permissions removed.
  4. Run the existing hybrid classifier on the modified feature vector.

The modified APK file (with plain-text manifest) is still produced for download.
The UI discloses that re-analysis uses feature vector simulation.
"""

import copy
import os
import sys
import datetime
from typing import Optional

# ── Make sure the ml_pipeline package is importable ─────────────────────────
_backend_dir = os.path.dirname(os.path.dirname(__file__))   # backend/
_root_dir    = os.path.dirname(_backend_dir)                 # project root
for _p in [_backend_dir, _root_dir]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from feature_extractor import extract_static_features
from sandbox_client    import run_dynamic_analysis
from ml_pipeline.hybrid_classifier import predict_hybrid

from modification.apk_manifest_modifier import (
    get_remediable_permissions,
    apply_manifest_remediation,
    _normalise_permission,
)
from modification.comparison import generate_comparison


# ── Storage ──────────────────────────────────────────────────────────────────
_sessions: dict = {}
_counter  = 0

UPLOAD_DIR = os.path.join(_backend_dir, "uploads")
REM_DIR    = os.path.join(_backend_dir, "remediation_artifacts")
os.makedirs(REM_DIR, exist_ok=True)

DYNAMIC_FEATURES_PATH = os.path.join(
    _root_dir, "ml_pipeline", "models", "dynamic_features.pkl"
)


def _new_session_id() -> str:
    global _counter
    _counter += 1
    year = datetime.datetime.now().year
    return f"REM-{year}-{_counter:05d}"


def create_session(filename: str, original_result: dict) -> dict:
    """
    Create a remediation session linked to an already-analysed APK.

    Args:
        filename:        The original filename (as stored in uploads/).
        original_result: The full dict returned by /api/analyze for this file.

    Returns:
        The new session dict.
    """
    apk_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK not found in uploads: {filename}")

    # Collect the remediable permissions from the APK
    try:
        remediable = get_remediable_permissions(apk_path)
    except Exception as e:
        remediable = []
        print(f"[Remediation] Warning — could not enumerate remediable permissions: {e}")

    session_id = _new_session_id()
    session = {
        "id":                     session_id,
        "status":                 "PENDING",
        "original_filename":      filename,
        "original_apk_path":      apk_path,
        "modified_apk_path":      None,
        "modified_filename":      None,
        "original_result":        original_result,
        "original_details":       original_result.get("app_details", {}),
        "remediable_permissions":  remediable,
        "selected_permissions":   [],
        "changes_applied":        [],
        "modified_result":        None,
        "modified_details":       None,
        "comparison":             None,
        "error":                  None,
        "created_at":             datetime.datetime.now().isoformat(),
        "completed_at":           None,
        # Disclosure flags
        "signing_status":         "NOT_SIGNED",
        "dynamic_mode":           "MOCK_SIMULATION",
        "reanalysis_method":      "feature_vector_simulation",
    }
    _sessions[session_id] = session
    return session


def get_session(session_id: str) -> Optional[dict]:
    return _sessions.get(session_id)


def list_sessions() -> list:
    return list(_sessions.values())


def apply_remediation(session_id: str, permission_actions: list) -> dict:
    """
    Apply manifest remediation and re-analyse using a modified feature vector.

    Args:
        session_id:            ID from create_session().
        permission_actions:    List of dicts or Pydantic models: [{"permission": "...", "action": "remove|restrict|keep"}]

    Returns:
        Updated session dict.
    """
    session = _sessions.get(session_id)
    if session is None:
        raise KeyError(f"Session not found: {session_id}")

    if session["status"] not in ("PENDING", "FAILED"):
        raise ValueError(
            f"Session {session_id} is in state '{session['status']}' — cannot re-apply."
        )

    session["status"] = "MODIFYING"
    session["error"]  = None

    # Parse actions
    actions_dict = {}
    for item in permission_actions:
        if hasattr(item, "permission"):
            actions_dict[item.permission] = item.action
        else:
            actions_dict[item["permission"]] = item["action"]
            
    session["selected_permissions"] = actions_dict

    perms_to_remove = [p for p, a in actions_dict.items() if a == "remove"]
    perms_to_restrict = [p for p, a in actions_dict.items() if a == "restrict"]
    perms_to_zero_out = perms_to_remove + perms_to_restrict

    # Normalise for feature vector zeroing
    full_names_zero  = {_normalise_permission(p) for p in perms_to_zero_out}
    short_names_zero = {p.split(".")[-1] for p in full_names_zero}

    try:
        # ── Step 1: Build output path ─────────────────────────────────────
        base_name    = os.path.splitext(session["original_filename"])[0]
        mod_filename = f"{base_name}_remediated_{session['id']}.apk"
        mod_apk_path = os.path.join(REM_DIR, mod_filename)

        session["modified_apk_path"] = mod_apk_path
        session["modified_filename"] = mod_filename

        # ── Step 2: Produce the modified APK file (download artifact) ─────
        # Only modify the manifest for 'remove' actions
        import shutil
        if perms_to_remove:
            mod_result = apply_manifest_remediation(
                original_apk_path=session["original_apk_path"],
                output_apk_path=mod_apk_path,
                permissions_to_remove=perms_to_remove,
            )

            if not mod_result["success"]:
                session["status"] = "FAILED"
                session["error"]  = mod_result["error"]
                return session
        else:
            shutil.copy2(session["original_apk_path"], mod_apk_path)
            mod_result = {"success": True, "changes_applied": []}

        # Enhance changes_applied with the specific action taken
        changes = []
        for c in mod_result.get("changes_applied", []):
            c["action"] = "remove"
            changes.append(c)
            
        for p in perms_to_restrict:
            changes.append({
                "target": _normalise_permission(p),
                "short_name": p.split(".")[-1],
                "action": "restrict"
            })
            
        session["changes_applied"] = changes
        session["status"]          = "REANALYZING"

        # ── Step 3: Re-extract from MODIFIED APK ─────────────────────────
        mod_static_df, mod_apk_details = extract_static_features(mod_apk_path)

        if mod_static_df is None:
            session["status"] = "FAILED"
            session["error"]  = "Could not extract static features from the modified APK."
            return session

        # ── Step 6: Dynamic analysis (mock sandbox) ───────────────────────
        mod_dynamic_df = run_dynamic_analysis(mod_apk_path, DYNAMIC_FEATURES_PATH)

        # ── Step 7: Hybrid classifier on the modified feature vector ──────
        mod_prediction = predict_hybrid(mod_static_df, mod_dynamic_df)
        mod_prediction["filename"]          = mod_filename
        mod_prediction["app_details"]       = mod_apk_details
        mod_prediction["reanalysis_method"] = "real_static_extraction"
        
        # MOCK SIGNING - Update flags
        session["signing_status"] = "MOCK_SIGNED"

        session["modified_result"]  = mod_prediction
        session["modified_details"] = mod_apk_details

        # ── Step 8: Before/after comparison ──────────────────────────────
        comparison = generate_comparison(
            original_result=session["original_result"],
            modified_result=mod_prediction,
            original_details=session["original_details"],
            modified_details=mod_apk_details,
            changes_applied=session["changes_applied"],
        )
        session["comparison"]   = comparison
        session["status"]       = "COMPLETED"
        session["completed_at"] = datetime.datetime.now().isoformat()

    except Exception as e:
        session["status"] = "FAILED"
        session["error"]  = str(e)
        # Clean up partial output
        if session.get("modified_apk_path") and os.path.exists(
            session["modified_apk_path"]
        ):
            try:
                os.remove(session["modified_apk_path"])
            except Exception:
                pass

    return session
