import json
import requests
import time

s_res = requests.post("http://127.0.0.1:8000/api/remediation/start", json={
    "filename":"MovieBox.apk",
    "original_result":{"prediction":"Malware","confidence_score":82.1,"risk_level":"High Risk","static_malware_prob":85.0,"dynamic_malware_prob":79.2,"explanations":[],"filename":"MovieBox.apk","app_details":{"package_name":"com.moviebox.pro","permissions":["android.permission.READ_EXTERNAL_STORAGE","android.permission.WRITE_EXTERNAL_STORAGE"],"activities":[],"services":[],"receivers":[],"providers":[]}}
})
sid = s_res.json()["session_id"]
print("Session:", sid)

time.sleep(1)

a_res = requests.post(f"http://127.0.0.1:8000/api/remediation/{sid}/apply", json={
    "permission_actions": [
        {"permission": "android.permission.READ_EXTERNAL_STORAGE", "action": "remove"}
    ]
})
print("Apply:", json.dumps(a_res.json(), indent=2))
