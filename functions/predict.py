import json
import pickle
import pandas as pd
from sklearn.preprocessing import StandardScaler

# Load the model and scaler
with open('rf_model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

# Training features (from get_features.py output)
training_features = ['network_packet_size', 'login_attempts', 'session_duration', 'ip_reputation_score', 'failed_logins', 'unusual_time_access', 'protocol_type_TCP', 'protocol_type_UDP', 'encryption_used_DES', 'browser_type_Edge', 'browser_type_Firefox', 'browser_type_Safari', 'browser_type_Unknown']

def handler(event, context):
    if event['httpMethod'] != 'POST':
        return {
            'statusCode': 405,
            'body': json.dumps({'error': 'Method not allowed'})
        }

    try:
        # Parse form data
        body = event['body']
        if event.get('isBase64Encoded'):
            import base64
            body = base64.b64decode(body).decode('utf-8')

        # Parse form data (assuming application/x-www-form-urlencoded)
        from urllib.parse import parse_qs
        data = parse_qs(body)

        # Extract values
        network_packet_size = float(data['network_packet_size'][0])
        protocol_type = data['protocol_type'][0]
        login_attempts = int(data['login_attempts'][0])
        session_duration = float(data['session_duration'][0])
        encryption_used = data['encryption_used'][0]
        ip_reputation_score = float(data['ip_reputation_score'][0])
        failed_logins = int(data['failed_logins'][0])
        browser_type = data['browser_type'][0]
        unusual_time_access = int(data['unusual_time_access'][0])

        # Create input DataFrame
        input_data = pd.DataFrame({
            'network_packet_size': [network_packet_size],
            'protocol_type': [protocol_type],
            'login_attempts': [login_attempts],
            'session_duration': [session_duration],
            'encryption_used': [encryption_used],
            'ip_reputation_score': [ip_reputation_score],
            'failed_logins': [failed_logins],
            'browser_type': [browser_type],
            'unusual_time_access': [unusual_time_access]
        })

        # Preprocess: get_dummies
        categorical = ['protocol_type', 'encryption_used', 'browser_type']
        input_data = pd.get_dummies(input_data, columns=categorical, drop_first=True)

        # Align columns
        for col in training_features:
            if col not in input_data.columns:
                input_data[col] = 0
        input_data = input_data[training_features]

        # Scale
        input_scaled = scaler.transform(input_data)

        # Predict
        prediction = model.predict(input_scaled)[0]
        prob = model.predict_proba(input_scaled)[0][1]

        prediction_text = "Attack Detected" if prediction == 1 else "No Attack Detected"

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST, OPTIONS'
            },
            'body': json.dumps({
                'prediction': prediction_text,
                'probability': f"{prob:.2f}"
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def options_handler(event, context):
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Methods': 'POST, OPTIONS'
        },
        'body': ''
    }
