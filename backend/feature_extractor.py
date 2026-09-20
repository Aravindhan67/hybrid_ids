from androguard.core.apk import APK
import joblib
import pandas as pd
import os

STATIC_FEATURES_PATH = os.path.join(os.path.dirname(__file__), '../ml_pipeline/models/static_features.pkl')

def extract_static_features(apk_path):
    """
    Parses an APK using Androguard and returns a tuple:
    - DataFrame matching the model's expected features.
    - Dictionary with basic APK details.
    """
    try:
        apk = APK(apk_path)
    except Exception as e:
        print(f"Error parsing APK: {e}")
        return None, None
        
    # Load the exact feature names used during training (Drebin features)
    if not os.path.exists(STATIC_FEATURES_PATH):
        raise FileNotFoundError(f"Feature columns not found at {STATIC_FEATURES_PATH}")
        
    model_columns = joblib.load(STATIC_FEATURES_PATH)
    
    # Initialize a zero-filled vector for all expected features
    feature_vector = {col: 0 for col in model_columns}
    
    # Extract general details
    # Note: Some fields (version_name, version_code) may be absent in
    # modified APKs whose manifests have been rewritten as plain-text XML.
    # We use .get_*() wrappers defensively to avoid KeyError.
    def _safe_get(fn):
        try:
            return fn()
        except (KeyError, AttributeError, TypeError):
            return None

    apk_details = {
        "package_name":  _safe_get(apk.get_package),
        "app_name":      _safe_get(apk.get_app_name),
        "version_name":  _safe_get(apk.get_androidversion_name),
        "version_code":  _safe_get(apk.get_androidversion_code),
        "target_sdk":    _safe_get(apk.get_target_sdk_version),
        "min_sdk":       _safe_get(apk.get_min_sdk_version),
        "permissions":   list(apk.get_permissions()),
        "activities":    list(apk.get_activities()),
        "services":      list(apk.get_services()),
        "receivers":     list(apk.get_receivers()),
        "providers":     list(apk.get_providers()),
    }
    
    # Extract Permissions
    for perm in apk.get_permissions():
        # Drebin formats permissions plainly or with the android.permission prefix.
        if perm in feature_vector:
            feature_vector[perm] = 1
        elif perm.split('.')[-1] in feature_vector:
            feature_vector[perm.split('.')[-1]] = 1

    # Extract Intents, Activities, Services if available in the model columns.
    # For a production system, we'd do exhaustive regex matching here based on Drebin's exact format.
    for activity in apk.get_activities():
        if activity in feature_vector:
            feature_vector[activity] = 1
            
    for service in apk.get_services():
        if service in feature_vector:
            feature_vector[service] = 1

    # Convert to DataFrame to match Scikit-Learn's expected input
    df = pd.DataFrame([feature_vector])
    return df, apk_details
