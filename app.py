from flask import Flask, request, jsonify
from components import check_vulnb  
import tempfile
import csv
import os
import configparser
from flask_talisman import Talisman
from OpenSSL import SSL

app = Flask(__name__)
Talisman(app)

config = configparser.ConfigParser()
config.read('config/config.ini')

app.config['UPLOAD_FOLDER'] = config["DEFAULT"]["UPLOAD_FOLDER"]

def load_threats_csv(threats_file):
    threats = []
    with open(threats_file, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=';')
        for row in reader:
            threats.append(row)
    return threats

@app.route("/vulnbcheck", methods=["POST"])
def vulnb_check():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    temp_file = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(temp_file)

    threats = load_threats_csv(temp_file)
    parent_dir = config["DEFAULT"]["PARENT_DIR"]
    matched_plugins_all = check_vulnb.checkvlnb(parent_dir, threats)

    return jsonify({"matched_plugins": matched_plugins_all}), 200

if __name__ == "__main__":
    # Načtení certifikátu a klíče pro HTTPS
    cert = 'cert.pem'
    key = 'key.pem'

    # Spuštění aplikace s HTTPS
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.use_privatekey_file(key)
    context.use_certificate_file(cert)

    app.run(host="0.0.0.0", port=443, debug=True, ssl_context=context)
