import joblib
import numpy as np
import os
import shap
import pandas as pd

FEATURE_DESCRIPTIONS = {
    "INTERNET": "Requires internet access to communicate with external servers.",
    "READ_PHONE_STATE": "Reads your phone's unique hardware ID and call status, often used for tracking.",
    "READ_SMS": "Can read all your private text messages (SMS).",
    "SEND_SMS": "Can secretly send text messages, which could cost you money.",
    "RECEIVE_SMS": "Can intercept incoming text messages, often used to steal 2FA codes.",
    "READ_CONTACTS": "Can read all your contacts and steal their phone numbers.",
    "WRITE_CONTACTS": "Can modify or add fake contacts to your phone.",
    "ACCESS_FINE_LOCATION": "Tracks your exact, precise GPS location.",
    "ACCESS_COARSE_LOCATION": "Tracks your approximate location (e.g. city or cell tower).",
    "CAMERA": "Can secretly turn on your camera and take photos/videos.",
    "RECORD_AUDIO": "Can secretly turn on your microphone and record your conversations.",
    "SYSTEM_ALERT_WINDOW": "Can draw invisible overlays over other apps to steal your passwords (Overlay Attack).",
    "GET_ACCOUNTS": "Can list all the accounts (Google, Facebook, etc.) registered on your phone.",
    "WAKE_LOCK": "Prevents your phone from sleeping, secretly running tasks in the background and draining battery.",
    "ACCESS_WIFI_STATE": "Can view information about Wi-Fi networks, often used for location tracking.",
    "android.telephony.SmsManager": "Uses the Android SMS manager directly to send or intercept texts secretly.",
    "Landroid/telephony/TelephonyManager;->getDeviceId": "Attempts to steal your device's unique IMEI hardware ID.",
    "Ljava/net/URL;->openConnection": "Opens a network connection, possibly to download a malicious payload or leak data.",
    "Landroid/content/Context;->getSystemService": "Accesses core Android system services, often used to check if the app is running in an emulator.",
    "Ljava/lang/Runtime;->exec": "Executes raw Linux commands on your phone's operating system.",
    "Landroid/app/ActivityManager;->getRunningAppProcesses": "Checks what other apps are currently running, often used to detect anti-virus apps."
}

STATIC_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models/static_rf_model.pkl')
DYNAMIC_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models/dynamic_rf_model.pkl')

# Lazy loading of models
_static_model = None
_dynamic_model = None

def load_models():
    global _static_model, _dynamic_model
    if _static_model is None:
        _static_model = joblib.load(STATIC_MODEL_PATH)
    if _dynamic_model is None:
        _dynamic_model = joblib.load(DYNAMIC_MODEL_PATH)
    return _static_model, _dynamic_model

def get_risk_level(confidence):
    """
    Returns risk level based on malware confidence score (0.0 to 1.0).
    """
    if confidence < 0.2:
        return "Safe"
    elif confidence < 0.5:
        return "Low Risk"
    elif confidence < 0.8:
        return "High Risk"
    else:
        return "Critical"

def predict_hybrid(static_features, dynamic_features, weight_static=0.5, weight_dynamic=0.5):
    """
    Predicts if an APK is benign or malware using the Hybrid Meta-Classifier.
    
    Args:
        static_features: 2D numpy array or DataFrame of static features.
        dynamic_features: 2D numpy array or DataFrame of dynamic features.
        
    Returns:
        dict: Final prediction, confidence score, and risk level.
    """
    static_model, dynamic_model = load_models()
    
    # Get probabilities (Class 1 is Malware)
    # Probabilities returned are [Prob_Benign, Prob_Malware]
    static_prob = static_model.predict_proba(static_features)[0][1]
    
    # If dynamic features are unavailable (e.g. failed to run in sandbox), we can rely solely on static
    if dynamic_features is not None:
        dynamic_prob = dynamic_model.predict_proba(dynamic_features)[0][1]
    else:
        dynamic_prob = static_prob
        weight_static = 1.0
        weight_dynamic = 0.0
        
    # Hybrid calculation
    final_confidence = (static_prob * weight_static) + (dynamic_prob * weight_dynamic)
    
    is_malware = bool(final_confidence >= 0.5)
    risk_level = get_risk_level(final_confidence)
    
    # Calculate SHAP explanations for static model
    top_explanations = []
    if isinstance(static_features, pd.DataFrame):
        try:
            explainer = shap.TreeExplainer(static_model)
            shap_values = explainer.shap_values(static_features)
            
            # Extract malware class SHAP values
            if isinstance(shap_values, list):
                malware_shap = shap_values[1][0]
            else:
                malware_shap = shap_values[0]
                if len(malware_shap.shape) > 1 and malware_shap.shape[1] == 2:
                     malware_shap = malware_shap[:, 1]
                     
            feature_names = static_features.columns.tolist()
            
            feature_impacts = []
            for i, name in enumerate(feature_names):
                impact = malware_shap[i]
                if impact != 0:
                    description = FEATURE_DESCRIPTIONS.get(name, "Accesses a sensitive Android component or API.")
                    feature_impacts.append({
                        "feature": name,
                        "description": description,
                        "impact": float(impact),
                        "is_present": bool(static_features.iloc[0, i])
                    })
                    
            # Sort by absolute impact to find the most influential features
            feature_impacts.sort(key=lambda x: abs(x["impact"]), reverse=True)
            top_explanations = feature_impacts[:10]  # Get top 10 features
        except Exception as e:
            print(f"SHAP error: {e}")
            
    return {
        "prediction": "Malware" if is_malware else "Benign",
        "confidence_score": round(final_confidence * 100, 2),
        "risk_level": risk_level,
        "static_malware_prob": round(static_prob * 100, 2),
        "dynamic_malware_prob": round(dynamic_prob * 100, 2),
        "explanations": top_explanations
    }

if __name__ == "__main__":
    print("Testing Hybrid Classifier...")
    # Mock some data (zeros array of correct shape)
    # Drebin has 215 features (since class was dropped from 216)
    mock_static = np.zeros((1, 215))
    # CICMalDroid has 139 features (since class was dropped from 140)
    mock_dynamic = np.zeros((1, 139))
    
    result = predict_hybrid(mock_static, mock_dynamic)
    print("Mock Prediction Result:")
    print(result)
