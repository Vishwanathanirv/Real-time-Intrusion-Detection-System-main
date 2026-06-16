import os
import pandas as pd
import glob

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "..", "datasets", "CICIDS2017.csv")
OUTPUT_FILE = os.path.join(BASE_DIR, "..", "datasets", "CICIDS2017_full.csv")

print("Combining CICIDS2017 CSV files...")

# Get all CSV files
csv_files = glob.glob(os.path.join(DATASET_DIR, "*.csv"))
print(f"Found {len(csv_files)} CSV files")

# Combine all CSV files
df_list = []
for file in csv_files:
    print(f"Reading: {os.path.basename(file)}")
    try:
        df = pd.read_csv(file, encoding='utf-8', encoding_errors='ignore')
        df_list.append(df)
        print(f"  ✅ Loaded {len(df)} rows")
    except Exception as e:
        print(f"  ❌ Error: {e}")

# Concatenate all dataframes
if df_list:
    combined_df = pd.concat(df_list, ignore_index=True)
    
    # Clean column names
    combined_df.columns = combined_df.columns.str.strip()
    
    # Save combined dataset
    combined_df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n✅ Combined dataset saved to: {OUTPUT_FILE}")
    print(f"   Total rows: {len(combined_df)}")
    print(f"   Total columns: {len(combined_df.columns)}")
    
    if 'Label' in combined_df.columns:
        print(f"\n   Label distribution:")
        print(combined_df['Label'].value_counts())
else:
    print("❌ No data loaded!")
