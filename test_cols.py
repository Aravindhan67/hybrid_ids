import joblib
columns = joblib.load('c:/hybrid ids/ml_pipeline/models/static_features.pkl')
print(columns[:50])
print([c for c in columns if 'CAMERA' in c])
print([c for c in columns if 'LOCATION' in c])
