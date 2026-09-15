import requests
import time
import os
import pandas as pd

# Default configuration for a local Cuckoo Sandbox or generic REST Sandbox
SANDBOX_URL = os.getenv("SANDBOX_URL", "http://127.0.0.1:8090/tasks/create/file")
SANDBOX_REPORT_URL = os.getenv("SANDBOX_REPORT_URL", "http://127.0.0.1:8090/tasks/report")
SANDBOX_API_KEY = os.getenv("SANDBOX_API_KEY", "your_sandbox_api_key")

def submit_to_sandbox(apk_path):
    """
    Submits an APK to the dynamic analysis sandbox.
    Returns a task ID to poll for results.
    """
    print(f"[Sandbox] Submitting {apk_path} for dynamic analysis...")
    try:
        with open(apk_path, "rb") as sample:
            files = {"file": sample}
            headers = {"Authorization": f"Bearer {SANDBOX_API_KEY}"}
            response = requests.post(SANDBOX_URL, files=files, headers=headers, timeout=5)
            
        if response.status_code == 200:
            task_id = response.json().get("task_id")
            print(f"[Sandbox] Successfully submitted. Task ID: {task_id}")
            return task_id
        else:
            print(f"[Sandbox] Failed to submit. Status Code: {response.status_code}")
            return None
    except requests.exceptions.ConnectionError:
        print("[Sandbox] Connection Refused: Ensure your Sandbox (e.g. Cuckoo) is running on port 8090.")
        return None
    except Exception as e:
        print(f"[Sandbox] Error submitting: {e}")
        return None

def poll_sandbox_report(task_id, timeout_minutes=5):
    """
    Polls the sandbox for the analysis report.
    Real dynamic analysis takes 3-5 minutes as the app runs in the emulator.
    """
    print(f"[Sandbox] Polling report for Task ID: {task_id}...")
    headers = {"Authorization": f"Bearer {SANDBOX_API_KEY}"}
    
    start_time = time.time()
    while time.time() - start_time < (timeout_minutes * 60):
        try:
            response = requests.get(f"{SANDBOX_REPORT_URL}/{task_id}", headers=headers, timeout=5)
            if response.status_code == 200:
                report = response.json()
                status = report.get("status")
                
                if status == "reported":
                    print("[Sandbox] Analysis complete!")
                    return report
                elif status == "pending" or status == "running":
                    print("[Sandbox] Still analyzing... waiting 30 seconds.")
                    time.sleep(30)
                else:
                    print(f"[Sandbox] Unknown status: {status}")
                    return None
            else:
                print(f"[Sandbox] Polling failed. Status Code: {response.status_code}")
                return None
        except requests.exceptions.ConnectionError:
            print("[Sandbox] Connection Refused during polling.")
            return None
        except Exception as e:
            print(f"[Sandbox] Error polling: {e}")
            return None
            
    print("[Sandbox] Timeout reached while waiting for analysis.")
    return None

def extract_dynamic_features(sandbox_report, feature_columns_path):
    """
    Parses the sandbox JSON report, counts system calls, 
    and maps them to the 140 features expected by CICMalDroid dynamic model.
    """
    if sandbox_report is None:
        return None
        
    try:
        import joblib
        model_columns = joblib.load(feature_columns_path)
        feature_vector = {col: 0 for col in model_columns}
        
        # Example parsing: Cuckoo behavior logs
        behavior = sandbox_report.get("behavior", {})
        processes = behavior.get("processes", [])
        
        for proc in processes:
            calls = proc.get("calls", [])
            for call in calls:
                api_name = call.get("api")
                if api_name in feature_vector:
                    feature_vector[api_name] += 1
                    
        return pd.DataFrame([feature_vector])
    except Exception as e:
        print(f"[Sandbox] Error extracting features: {e}")
        return None

def run_dynamic_analysis(apk_path, feature_columns_path):
    """
    End-to-end flow: Submit -> Poll -> Extract Features.
    """
    task_id = submit_to_sandbox(apk_path)
    if not task_id:
        return None
        
    report = poll_sandbox_report(task_id)
    if not report:
        return None
        
    features = extract_dynamic_features(report, feature_columns_path)
    return features
