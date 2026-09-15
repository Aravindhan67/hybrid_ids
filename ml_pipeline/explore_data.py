import pandas as pd
import os

drebin_path = r"c:\hybrid ids\dataset\drebin.csv"
cic_static_path = r"c:\hybrid ids\dataset\CICMalDroid 2020\feature_vectors_static.csv"
cic_dynamic_path = r"c:\hybrid ids\dataset\CICMalDroid 2020\feature_vectors_syscalls_frequency_5_Cat.csv"

def inspect_dataset(name, path):
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return
    
    print(f"\n--- Inspecting {name} ---")
    try:
        # Read just a few rows first to avoid OOM for huge files, 
        # or read all to get full shape if manageable.
        df = pd.read_csv(path)
        print(f"Shape: {df.shape}")
        if 'class' in df.columns:
            print(f"Class distribution:\n{df['class'].value_counts()}")
        elif 'Class' in df.columns:
            print(f"Class distribution:\n{df['Class'].value_counts()}")
        elif 'Label' in df.columns:
            print(f"Class distribution:\n{df['Label'].value_counts()}")
        elif 'label' in df.columns:
            print(f"Class distribution:\n{df['label'].value_counts()}")
        else:
            print(f"Could not find class column. Columns preview: {list(df.columns[:5])} ... {list(df.columns[-5:])}")
    except Exception as e:
        print(f"Error reading {name}: {e}")

if __name__ == "__main__":
    inspect_dataset("Drebin Static", drebin_path)
    inspect_dataset("CICMalDroid Static", cic_static_path)
    inspect_dataset("CICMalDroid Dynamic", cic_dynamic_path)
