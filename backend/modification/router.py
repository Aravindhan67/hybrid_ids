"""
router.py — FastAPI router for the APK Security Remediation & Re-analysis Module.

Mounted at:  /api/remediation

Endpoints
---------
POST  /api/remediation/start
      Body: { "filename": "sample.apk", "original_result": { ... } }
      Creates a remediation session from an already-analysed APK.

GET   /api/remediation/{id}
      Returns full session state.

POST  /api/remediation/{id}/apply
      Body: { "permissions_to_remove": ["READ_SMS", ...] }
      Applies manifest remediation and triggers re-analysis.

GET   /api/remediation/{id}/comparison
      Returns the before/after comparison dict.

GET   /api/remediation/{id}/download/{artifact}
      artifact = "original" | "modified"
      Streams the APK file for download.

GET   /api/remediation/{id}/report
      Returns a plain-text summary comparison report.
"""

import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from modification.remediation_service import (
    create_session,
    get_session,
    apply_remediation,
    list_sessions,
)


router = APIRouter(prefix="/api/remediation", tags=["remediation"])


# ── Request / Response Models ────────────────────────────────────────────────

class StartSessionRequest(BaseModel):
    filename: str
    original_result: dict


class PermissionAction(BaseModel):
    permission: str
    action: str

class ApplyRemediationRequest(BaseModel):
    permission_actions: list[PermissionAction]


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/start")
def start_remediation_session(body: StartSessionRequest):
    """
    Create a remediation session for an already-uploaded and analysed APK.
    Returns the session id and the list of remediable permissions.
    """
    try:
        session = create_session(
            filename=body.filename,
            original_result=body.original_result,
        )
        return {
            "session_id":             session["id"],
            "status":                 session["status"],
            "remediable_permissions": session["remediable_permissions"],
            "original_result":        session["original_result"],
            "signing_status":         session["signing_status"],
            "dynamic_mode":           session["dynamic_mode"],
            "created_at":             session["created_at"],
        }
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{session_id}")
def get_remediation_session(session_id: str):
    """Return the full session state."""
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    # Return everything except internal absolute paths
    return _safe_session(session)


@router.post("/{session_id}/apply")
def apply_remediation_endpoint(session_id: str, body: ApplyRemediationRequest):
    """
    Apply selected permission removals and re-run the analysis pipeline.
    This is a synchronous call that may take several seconds.
    """
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    if not body.permission_actions:
        raise HTTPException(status_code=400, detail="No permissions selected for modification.")

    try:
        updated = apply_remediation(session_id, body.permission_actions)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if updated["status"] == "FAILED":
        raise HTTPException(
            status_code=500,
            detail=updated.get("error", "Remediation failed."),
        )

    return _safe_session(updated)


@router.get("/{session_id}/comparison")
def get_comparison(session_id: str):
    """Return the before/after comparison dict once remediation is COMPLETED."""
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    if session["status"] != "COMPLETED":
        raise HTTPException(
            status_code=400,
            detail=f"Comparison not available — session status is '{session['status']}'.",
        )

    return session["comparison"]


@router.get("/{session_id}/download/{artifact}")
def download_apk(session_id: str, artifact: str):
    """
    Download the original or modified APK.

    artifact must be 'original' or 'modified'.
    """
    if artifact not in ("original", "modified"):
        raise HTTPException(status_code=400, detail="artifact must be 'original' or 'modified'.")

    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    if artifact == "original":
        path     = session["original_apk_path"]
        filename = session["original_filename"]
    else:
        path     = session.get("modified_apk_path")
        filename = session.get("modified_filename")
        if not path or not os.path.exists(path):
            raise HTTPException(status_code=404, detail="Modified APK is not yet available.")

    if not path or not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found on server.")

    return FileResponse(
        path=path,
        filename=filename,
        media_type="application/vnd.android.package-archive",
    )


@router.get("/{session_id}/report")
def get_text_report(session_id: str):
    """Return a plain-text before/after comparison report."""
    session = get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")

    if session["status"] != "COMPLETED":
        raise HTTPException(
            status_code=400,
            detail=f"Report not available — session status is '{session['status']}'.",
        )

    comp = session["comparison"]
    s    = comp["summary"]
    hs   = comp["hybrid_scores"]

    lines = [
        "=" * 60,
        "  APK SECURITY REMEDIATION REPORT",
        "=" * 60,
        f"Session ID    : {session['id']}",
        f"Original APK  : {session['original_filename']}",
        f"Modified APK  : {session['modified_filename']}",
        f"Completed At  : {session.get('completed_at', 'N/A')}",
        "",
        "DYNAMIC ANALYSIS NOTE",
        "-" * 40,
        "Dynamic analysis used the mock simulation sandbox.",
        "Results are indicative only, not genuine runtime execution.",
        "Modified APK is for re-analysis only — NOT signed for installation.",
        "",
        "ORIGINAL RESULT",
        "-" * 40,
        f"Classification : {s['original_prediction']}",
        f"Risk Level     : {s['original_risk']}",
        f"Confidence     : {s['original_confidence']}%",
        f"Static Prob    : {hs['original']['static_prob']}%",
        f"Dynamic Prob   : {hs['original']['dynamic_prob']}%",
        "",
        "MODIFIED RESULT",
        "-" * 40,
        f"Classification : {s['modified_prediction']}",
        f"Risk Level     : {s['modified_risk']}",
        f"Confidence     : {s['modified_confidence']}%",
        f"Static Prob    : {hs['modified']['static_prob']}%",
        f"Dynamic Prob   : {hs['modified']['dynamic_prob']}%",
        "",
        "CHANGES APPLIED",
        "-" * 40,
    ]
    for c in comp["changes_applied"]:
        lines.append(f"  ✓ Removed {c['target']}")

    lines += [
        "",
        "PERMISSION COMPARISON",
        "-" * 40,
        f"{'Permission':<45} {'Before':<10} {'After'}",
        "-" * 65,
    ]
    for row in comp["permission_diff"]:
        marker = " ←" if row["changed"] else ""
        lines.append(f"{row['permission']:<45} {row['original']:<10} {row['modified']}{marker}")

    lines += [
        "",
        "REMEDIATION EFFECTIVENESS",
        "-" * 40,
        s["effectiveness"],
    ]
    if not s["classification_changed"]:
        lines.append("⚠  Overall malware classification label was NOT changed.")
        lines.append("   Additional security findings may remain.")

    lines += [
        "",
        "=" * 60,
        "End of Report",
        "=" * 60,
    ]

    return PlainTextResponse("\n".join(lines))


# ── Helpers ──────────────────────────────────────────────────────────────────

def _safe_session(session: dict) -> dict:
    """Return a copy of the session with internal absolute paths stripped."""
    safe = {k: v for k, v in session.items() if k not in ("original_apk_path", "modified_apk_path")}
    return safe
