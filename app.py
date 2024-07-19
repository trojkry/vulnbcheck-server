from flask import Flask, request, jsonify
from components import check_vulnb
import os
import csv
import configparser
from functools import wraps
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
import logging
import secrets

app = Flask(__name__)

# Load configuration
config = configparser.ConfigParser()
config.read('config/config.ini')

app.config['UPLOAD_FOLDER'] = config["DEFAULT"]["UPLOAD_FOLDER"]
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

# Set the secret key for CSRF protection and other security features
app.config['SECRET_KEY'] = secrets.token_hex(16)  # or a static secret key

AUTHORIZED_IP = '10.0.2.2'  # IP adresa vašeho webového serveru

# CSRF protection
csrf = CSRFProtect()
csrf.init_app(app)

# Set up logging
logging.basicConfig(filename='app.log', level=logging.INFO)

@app.before_request
def log_request_info():
    logging.info('Headers: %s', request.headers)
    logging.info('Body: %s', request.get_data())

#def check_ip(f):
#    @wraps(f)
#    def decorated_function(*args, **kwargs):
#        if request.remote_addr != AUTHORIZED_IP:
#            return jsonify({"error": "Unauthorized IP address"}), 403
#        return f(*args, **kwargs)
#    return decorated_function

def load_threats_csv(threats_file):
    threats = []
    with open(threats_file, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=';')
        for row in reader:
            threats.append(row)
    return threats

@app.route("/vulnbcheck", methods=["POST"])
@check_ip
def vulnb_check():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    temp_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(temp_file)

    threats = load_threats_csv(temp_file)
    parent_dir = config["DEFAULT"]["PARENT_DIR"]
    matched_plugins_all = check_vulnb.checkvlnb(parent_dir, threats)

    response_data = {
        "matched_plugins": matched_plugins_all,
        "report_file": temp_file  # Optionally return the path to the generated report
    }
    return jsonify(response_data), 200

##@app.after_request
#def set_secure_headers(response):
 #   response.headers['Content-Security-Policy'] = "default-src 'self'"
  #  response.headers['X-Content-Type-Options'] = 'nosniff'
   # response.headers['X-Frame-Options'] = 'DENY'
    #response.headers['X-XSS-Protection'] = '1; mode=block'
    #return response

if __name__ == "__main__":
    context = ('cert.pem', 'key.pem')
    app.run(host="0.0.0.0", port=443, debug=True, ssl_context=context)
