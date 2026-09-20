import hashlib
import json
import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(env_path)

SIGNATURES_FILE = os.path.join(os.path.dirname(__file__), 'malware_signatures.json')
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

def load_signatures():
    if not os.path.exists(SIGNATURES_FILE):
        return {}
    with open(SIGNATURES_FILE, 'r') as f:
        return json.load(f)

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_virustotal(file_hash):
    """Queries VirusTotal for the given SHA-256 hash."""
    if not VIRUSTOTAL_API_KEY:
        return None
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})
            
            malicious = stats.get("malicious", 0)
            undetected = stats.get("undetected", 0)
            total = sum(stats.values())
            
            vendor_results = []
            for engine, details in results.items():
                vendor_results.append({
                    "vendor": engine,
                    "category": details.get("category", "undetected"),
                    "result": details.get("result", "")
                })
                
            vt_details = {
                "malicious": malicious,
                "total": total,
                "vendors": vendor_results
            }
            
            if malicious > 0:
                return {
                    "is_malware": True,
                    "hash": file_hash,
                    "description": f"Flagged by {malicious} security vendors on VirusTotal.",
                    "vt_details": vt_details
                }
            else:
                return {
                    "is_malware": False,
                    "hash": file_hash,
                    "description": "Safe according to VirusTotal.",
                    "vt_details": vt_details
                }
        elif response.status_code == 404:
            return {
                "is_malware": False,
                "hash": file_hash,
                "description": "Not found in VirusTotal database.",
                "vt_details": None
            }
        else:
            print(f"VirusTotal API Error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"VirusTotal Request Failed: {e}")
        return None

def check_signature(file_path):
    """
    Checks if the file at file_path matches any known malware signatures.
    Returns:
        dict: { "is_malware": bool, "hash": str, "description": str, "vt_details": dict }
    """
    file_hash = calculate_sha256(file_path)
    
    # Tier 1: Check Local Database First (Mock / Offline Cache)
    signatures = load_signatures()
    if file_hash in signatures:
        # Create a mock VT detail so the UI dashboard still works beautifully
        mock_vt_details = {
            "malicious": 1,
            "total": 1,
            "vendors": [
                {
                    "vendor": "Local-DB",
                    "category": "malicious",
                    "result": signatures[file_hash]
                }
            ]
        }
        return {
            "is_malware": True,
            "hash": file_hash,
            "description": f"Local DB Match: {signatures[file_hash]}",
            "vt_details": mock_vt_details
        }
    
    # Tier 2: Check VirusTotal if API Key is available
    if VIRUSTOTAL_API_KEY:
        vt_result = check_virustotal(file_hash)
        if vt_result:
            return vt_result

    # Default Safe Fallback
    return {
        "is_malware": False,
        "hash": file_hash,
        "description": "No known signature matched.",
        "vt_details": None
    }
