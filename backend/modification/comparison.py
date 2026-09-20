"""
comparison.py — Generates before/after security comparison between original
and remediated APK analysis results.
"""

from typing import Optional


def generate_comparison(
    original_result: dict,
    modified_result: dict,
    original_details: dict,
    modified_details: dict,
    changes_applied: list[dict],
) -> dict:
    """
    Produces a structured before/after comparison dict.

    Args:
        original_result:  predict_hybrid() output for the original APK.
        modified_result:  predict_hybrid() output for the modified APK.
        original_details: apk_details dict from extract_static_features() — original.
        modified_details: apk_details dict from extract_static_features() — modified.
        changes_applied:  List of {"type", "target", "description"} dicts.

    Returns:
        dict: Comprehensive comparison ready for serialisation to JSON.
    """

    # ── Permission diff ──────────────────────────────────────────────────────
    orig_perms = set(original_details.get("permissions") or [])
    mod_perms  = set(modified_details.get("permissions") or [])

    removed_perms = sorted(orig_perms - mod_perms)
    retained_perms = sorted(orig_perms & mod_perms)
    added_perms = sorted(mod_perms - orig_perms)  # should always be empty

    permission_diff = []
    for p in sorted(orig_perms | mod_perms):
        in_orig = p in orig_perms
        in_mod  = p in mod_perms
        permission_diff.append({
            "permission": p,
            "original":   "Present" if in_orig else "Absent",
            "modified":   "Present" if in_mod  else "Removed",
            "changed":    in_orig != in_mod,
        })

    # ── SHAP feature diff ────────────────────────────────────────────────────
    orig_shap = {e["feature"]: e for e in (original_result.get("explanations") or [])}
    mod_shap  = {e["feature"]: e for e in (modified_result.get("explanations") or [])}

    all_features = sorted(set(orig_shap) | set(mod_shap))
    shap_diff = []
    for feat in all_features:
        o = orig_shap.get(feat)
        m = mod_shap.get(feat)
        shap_diff.append({
            "feature":        feat,
            "description":    (o or m or {}).get("description", ""),
            "original_impact": round(o["impact"], 4) if o else None,
            "modified_impact": round(m["impact"], 4) if m else None,
            "original_present": o["is_present"] if o else False,
            "modified_present": m["is_present"] if m else False,
            "status": (
                "Removed"  if o and not m else
                "Added"    if not o and m else
                "Changed"  if o and m and round(o["impact"], 4) != round(m["impact"], 4) else
                "Retained"
            ),
        })

    # ── Component counts diff ────────────────────────────────────────────────
    component_diff = {}
    for key in ("activities", "services", "receivers", "providers"):
        o_val = len(original_details.get(key) or [])
        m_val = len(modified_details.get(key) or [])
        component_diff[key] = {"original": o_val, "modified": m_val}

    # ── Risk level change assessment ─────────────────────────────────────────
    orig_conf   = original_result.get("confidence_score", 0)
    mod_conf    = modified_result.get("confidence_score", 0)
    conf_delta  = round(mod_conf - orig_conf, 2)

    orig_risk   = original_result.get("risk_level", "Unknown")
    mod_risk    = modified_result.get("risk_level", "Unknown")

    if conf_delta < -10:
        effectiveness = "Significant improvement"
    elif conf_delta < 0:
        effectiveness = "Marginal improvement"
    elif conf_delta == 0:
        effectiveness = "No change in risk score"
    else:
        effectiveness = "Risk score increased"

    # Honest assessment: was classification label actually changed?
    orig_pred = original_result.get("prediction", "Unknown")
    mod_pred  = modified_result.get("prediction", "Unknown")
    label_changed = orig_pred != mod_pred

    return {
        "summary": {
            "original_prediction":   orig_pred,
            "modified_prediction":   mod_pred,
            "classification_changed": label_changed,
            "original_risk":         orig_risk,
            "modified_risk":         mod_risk,
            "original_confidence":   orig_conf,
            "modified_confidence":   mod_conf,
            "confidence_delta":      conf_delta,
            "effectiveness":         effectiveness,
        },
        "changes_applied": changes_applied,
        "permissions_removed": removed_perms,
        "permissions_retained": retained_perms,
        "permissions_added": added_perms,
        "permission_diff": permission_diff,
        "hybrid_scores": {
            "original": {
                "static_prob":  original_result.get("static_malware_prob"),
                "dynamic_prob": original_result.get("dynamic_malware_prob"),
                "confidence":   orig_conf,
                "risk":         orig_risk,
            },
            "modified": {
                "static_prob":  modified_result.get("static_malware_prob"),
                "dynamic_prob": modified_result.get("dynamic_malware_prob"),
                "confidence":   mod_conf,
                "risk":         mod_risk,
            },
        },
        "shap_diff": shap_diff,
        "component_diff": component_diff,
        "app_info": {
            "original": {
                "package_name":  original_details.get("package_name"),
                "version_name":  original_details.get("version_name"),
                "target_sdk":    original_details.get("target_sdk"),
                "min_sdk":       original_details.get("min_sdk"),
            },
            "modified": {
                "package_name":  modified_details.get("package_name"),
                "version_name":  modified_details.get("version_name"),
                "target_sdk":    modified_details.get("target_sdk"),
                "min_sdk":       modified_details.get("min_sdk"),
            },
        },
    }
