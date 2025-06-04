import re
import time
import requests
import os
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Global variable to store messages
message_store = {}

def validate_credentials(email: str, password: str, refresh_token: str, client_id: str) -> bool:
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    if not password or not refresh_token or not client_id:
        return False, "Password, refresh_token, or client_id cannot be empty"
    return True, ""

def get_messages(email: str, password: str, refresh_token: str, client_id: str, timeout: int = 15):
    try:
        valid, msg = validate_credentials(email, password, refresh_token, client_id)
        if not valid:
            return {"status": "error", "message": msg}

        headers = {
            'accept': 'application/json',
            'content-type': 'application/json',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        response = requests.post(
            'https://tools.dongvanfb.net/api/get_messages_oauth2',
            headers=headers,
            json={
                'email': email,
                'pass': password,
                'refresh_token': refresh_token,
                'client_id': client_id,
            },
            timeout=timeout
        )

        if response.status_code == 429:
            return {"status": "error", "message": "Rate limit exceeded. Please try again later."}
        elif response.status_code != 200:
            return {"status": "error", "message": f"API request failed with status {response.status_code}"}

        data = response.json()
        messages = data.get('messages', [])
        
        # Store messages globally
        message_store[email] = messages
        
        return {"status": "success", "messages": messages}
        
    except Exception as e:
        return {"status": "error", "message": f"An error occurred: {str(e)}"}

def extract_otp(messages):
    for message in messages:
        sender = message.get('from', '').lower()
        if '@facebookmail.com' not in sender:
            continue

        subject = message.get('subject', '').strip()
        match = re.search(r'\b(\d{5,8})\b', subject, re.IGNORECASE)
        if match:
            return match.group(1)
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    input_data = request.form['credentials'].strip()
    
    # Auto-detect input format
    if '|' in input_data:
        parts = input_data.split('|')
        if len(parts) == 4:
            email, password, refresh_token, client_id = parts
        else:
            return render_template('index.html', error="Invalid input format. Expected: email|password|refresh_token|client_id")
    else:
        return render_template('index.html', error="Invalid input format. Use '|' separator")
    
    # Get messages from API
    result = get_messages(email, password, refresh_token, client_id)
    
    if result['status'] == 'error':
        return render_template('index.html', error=result['message'], email=email)
    
    messages = result['messages']
    otp_code = extract_otp(messages)
    
    return render_template(
        'index.html', 
        email=email,
        messages=messages,
        otp_code=otp_code,
        success=f"Successfully retrieved {len(messages)} messages"
    )

@app.route('/refresh', methods=['POST'])
def refresh():
    email = request.form['email']
    password = request.form['password']
    refresh_token = request.form['refresh_token']
    client_id = request.form['client_id']
    
    result = get_messages(email, password, refresh_token, client_id)
    
    if result['status'] == 'error':
        return render_template('index.html', error=result['message'], email=email)
    
    messages = result['messages']
    otp_code = extract_otp(messages)
    
    return render_template(
        'index.html', 
        email=email,
        password=password,
        refresh_token=refresh_token,
        client_id=client_id,
        messages=messages,
        otp_code=otp_code,
        success=f"Mailbox refreshed. {len(messages)} messages found"
    )

@app.route('/delete', methods=['POST'])
def delete():
    email = request.form['email']
    if email in message_store:
        del message_store[email]
    return render_template('index.html', success=f"Account data for {email} deleted")

if __name__ == '__main__':
    app.run(debug=True)