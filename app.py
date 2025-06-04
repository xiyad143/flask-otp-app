import re
import time
import requests
import os
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for
import bleach  # For sanitizing HTML content to prevent XSS

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Production-এ এটি পরিবর্তন করুন

# Global variable to store messages
message_store = {}

def validate_credentials(email: str, password: str, refresh_token: str, client_id: str) -> bool:
    """Credentials ভ্যালিডেশন ফাংশন"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    if not password or not refresh_token or not client_id:
        return False, "Password, refresh_token, or client_id cannot be empty"
    return True, ""

def get_messages(email: str, password: str, refresh_token: str, client_id: str, timeout: int = 15):
    """API থেকে মেসেজ ফেচ করার ফাংশন"""
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
        
        # মেসেজ বডি স্যানিটাইজ করুন (XSS প্রতিরোধ)
        for message in messages:
            body = (message.get('body', '') or 
                    message.get('text', '') or 
                    message.get('content', '') or 
                    'No Body Available')
            message['body'] = bleach.clean(body, tags=['p', 'br', 'strong', 'em'], strip=True)
        
        # মেসেজ গ্লোবালি স্টোর করুন
        message_store[email] = messages
        
        return {"status": "success", "messages": messages}
        
    except Exception as e:
        return {"status": "error", "message": f"An error occurred: {str(e)}"}

def extract_otp(messages):
    """মেসেজ থেকে OTP এক্সট্রাক্ট করার ফাংশন"""
    for message in messages:
        text = message.get('subject', '') + ' ' + message.get('body', '')
        match = re.search(r'\b(\d{4,8})\b', text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None

@app.route('/')
def index():
    """হোমপেজ রাউট"""
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    """ক্রেডেনশিয়াল প্রসেস করার রাউট"""
    input_data = request.form['credentials'].strip()
    
    if '|' in input_data:
        parts = input_data.split('|')
        if len(parts) == 4:
            email, password, refresh_token, client_id = [part.strip() for part in parts]
        else:
            return render_template('index.html', error="Invalid input format. Expected: email|password|refresh_token|client_id")
    else:
        return render_template('index.html', error="Invalid input format. Use '|' separator")
    
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
        success=f"Successfully retrieved {len(messages)} messages"
    )

@app.route('/refresh', methods=['POST'])
def refresh():
    """ইনবক্স রিফ্রেশ করার রাউট"""
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
    """অ্যাকাউন্ট ডেটা ডিলিট করার রাউট"""
    email = request.form['email']
    if email in message_store:
        del message_store[email]
    return render_template('index.html', email=email, success=f"Account data for {email} deleted")

@app.route('/delete_message', methods=['POST'])
def delete_message():
    """সিঙ্গেল মেসেজ ডিলিট করার API এন্ডপয়েন্ট"""
    data = request.get_json()
    email = data.get('email')
    message_id = data.get('message_id')
    if not email or not message_id:
        return jsonify({"status": "error", "message": "Email or message ID missing"})
    if email in message_store:
        message_store[email] = [msg for msg in message_store[email] if str(msg.get('id', '')) != str(message_id)]
        return jsonify({"status": "success", "message": "Message deleted"})
    return jsonify({"status": "error", "message": "Email not found in message store"})

if __name__ == '__main__':
    app.run(debug=True)  # Production-এ debug=False সেট করুন