#!/usr/bin/env python3
"""
Ghost Protocol Dashboard Server using Flask for proper file serving
"""

from flask import Flask, send_file, make_response, request
import os
from datetime import datetime

app = Flask(__name__, static_folder='/app', static_url_path='')

@app.route('/ghost_protocol.html')
def serve_html():
    """Serve ghost_protocol.html with no-cache headers"""
    response = make_response(send_file('/app/ghost_protocol.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def serve_root():
    """Redirect root to ghost_protocol.html"""
    return serve_html()

@app.before_request
def log_request():
    """Log incoming requests"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'[{timestamp}] {request.method} {request.path}')

if __name__ == '__main__':
    print(f"🚀 Ghost Protocol Dashboard Server running on port 8000")
    print(f"📂 Serving from: /app")
    print(f"🌐 Access at: http://localhost:8000/ghost_protocol.html")
    print(f"⚠️  All HTML served with no-cache headers")
    app.run(host='0.0.0.0', port=8000, debug=False)
