import pickle
import pandas as pd
from sklearn.preprocessing import StandardScaler

df = pd.read_csv('cybersecurity_intrusion_data.csv')
df = df.drop('session_id', axis=1)
categorical = ['protocol_type', 'encryption_used', 'browser_type']
df = pd.get_dummies(df, columns=categorical, drop_first=True)
X = df.drop('attack_detected', axis=1)
scaler = StandardScaler()
scaler.fit(X)
with open('scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)
print('Scaler saved')

print('Feature names:', list(X.columns))
