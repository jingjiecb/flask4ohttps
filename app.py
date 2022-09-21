import logging

from flask import Flask
from flask import request, abort
from hashlib import md5
import json
import os

app = Flask(__name__)
ok_json = {
    "success": True
}
config = {}
with open("config.json", "r", encoding='utf-8') as config_file:
    config_raw = json.loads(config_file.read())
    for domain in config_raw["domains"]:
        config[domain["domain"]] = domain


@app.route('/')
def hello_world():  # put application's code here
    return 'Hello World!'


@app.route('/hook', methods=['POST'])
def hook():
    if not request.is_json:
        abort(400)

    json_data = request.get_json()
    domains = json_data["payload"]["certificateDomains"]
    cert_key = json_data["payload"]["certificateCertKey"]
    cert = json_data["payload"]["certificateFullchainCerts"]
    timestamp = json_data["timestamp"]
    sign = json_data["sign"]

    for domain in domains:
        try:
            domain_config = config[domain]
        except:
            logging.warning(f'{domain} is not configured, ignoring...')
            continue
        token = domain_config["token"]
        sign_expected = md5(f'{timestamp}:{token}'.encode("utf-8")).hexdigest()
        if sign == sign_expected:
            deploy_certificate(cert_key, cert, domain_config["path"])
        else:
            logging.warning(f'{domains} request sign is invalid, ignoring...')
            continue
    os.system("nginx -s reload")
    return ok_json


def deploy_certificate(key, cer, path):
    os.makedirs(path, exist_ok=True)
    with open(f'{path}/cert.key', 'w', encoding='utf-8') as key_file, open(f'{path}/fullchain.cer','w',encoding='utf-8') as cer_file:
        key_file.write(key)
        cer_file.write(cer)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
