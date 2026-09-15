from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import shutil
import sys
import os

# Ensure ml_pipeline is in the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from feature_extractor import extract_static_features
from sandbox_client import run_dynamic_analysis
from ml_pipeline.hybrid_classifier import predict_hybrid

app = FastAPI(title="Hybrid IDS API", version="1.0.0")

# Allow CORS for the frontend Next.js app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/")
def read_root():
    return {"message": "Welcome to the Hybrid IDS API"}

@app.post("/api/analyze")
async def analyze_apk(file: UploadFile = File(...)):
    if not file.filename.endswith('.apk'):
        raise HTTPException(status_code=400, detail="Only .apk files are supported.")
        
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    
    # Save the uploaded file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    try:
        # 1. Extract static features and details from APK
        static_features_df, apk_details = extract_static_features(file_path)
        
        if static_features_df is None:
            raise HTTPException(status_code=500, detail="Failed to parse APK file.")
            
        # 2. Extract Dynamic Features via Sandbox
        # Path to the feature columns expected by the dynamic model
        dynamic_features_path = os.path.join(os.path.dirname(__file__), '../ml_pipeline/models/dynamic_features.pkl')
        dynamic_features_df = run_dynamic_analysis(file_path, dynamic_features_path)
        
        # 3. Make Prediction using Meta-Classifier
        result = predict_hybrid(static_features_df, dynamic_features_df)
        
        # Add metadata and extracted app details
        result["filename"] = file.filename
        result["app_details"] = apk_details
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
