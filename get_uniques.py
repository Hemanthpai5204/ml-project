import pandas as pd

df = pd.read_csv('cybersecurity_intrusion_data.csv')
for col in ['protocol_type', 'encryption_used', 'browser_type']:
    print(f'{col}: {sorted(df[col].dropna().unique())}')
