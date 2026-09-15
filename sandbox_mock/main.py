from fastapi import FastAPI, File, UploadFile
import uuid
import random

app = FastAPI()

# In-memory storage for mock tasks
tasks = {}

@app.post("/tasks/create/file")
async def create_task(file: UploadFile = File(...)):
    task_id = str(uuid.uuid4())
    # Start task as reported immediately for the mock
    tasks[task_id] = "reported"
    return {"task_id": task_id}

@app.get("/tasks/report/{task_id}")
async def get_report(task_id: str):
    if task_id not in tasks:
        return {"status": "error"}
        
    # Return a mock Cuckoo JSON report
    # We add some fake malicious-looking API calls that might trigger the model
    return {
        "status": tasks[task_id],
        "behavior": {
            "processes": [
                {
                    "calls": [
                        {"api": "Ljava/net/URL;->openConnection"},
                        {"api": "Landroid/telephony/TelephonyManager;->getDeviceId"},
                        {"api": "Landroid/content/Context;->getSystemService"},
                        {"api": "Ljava/lang/Runtime;->exec"},
                        {"api": "Landroid/app/ActivityManager;->getRunningAppProcesses"}
                    ]
                }
            ]
        }
    }
