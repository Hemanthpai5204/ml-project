from flask import Flask, request, render_template
import pickle
import pandas as pd

app = Flask(__name__)

# Load the model and scaler
with open('rf_model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

# Training features (from get_features.py output)
training_features = ['network_packet_size', 'login_attempts', 'session_duration', 'ip_reputation_score', 'failed_logins', 'unusual_time_access', 'protocol_type_TCP', 'protocol_type_UDP', 'encryption_used_DES', 'browser_type_Edge', 'browser_type_Firefox', 'browser_type_Safari', 'browser_type_Unknown']

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    # Get form data
    network_packet_size = float(request.form['network_packet_size'])
    protocol_type = request.form['protocol_type']
    login_attempts = int(request.form['login_attempts'])
    session_duration = float(request.form['session_duration'])
    encryption_used = request.form['encryption_used']
    ip_reputation_score = float(request.form['ip_reputation_score'])
    failed_logins = int(request.form['failed_logins'])
    browser_type = request.form['browser_type']
    unusual_time_access = int(request.form['unusual_time_access'])

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

    return render_template('index.html', prediction=prediction_text, probability=f"{prob:.2f}")

if __name__ == '__main__':
    app.run(debug=True)
