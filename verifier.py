import json
from jwcrypto import jwk
from flask import Flask, jsonify, request
import requests
from sd_jwt.verifier import SDJWTVerifier

app = Flask(__name__)

def get_issuer_key(issuer, header):
    response = requests.get("http://localhost:5000/issuer_key")
    if response.status_code == 200:
        return jwk.JWK(**response.json())
    else:
        raise Exception("Failed to retrieve issuer key")

@app.route("/verify_sd-jwt", methods=["POST"])
def verify_sd_jwt():
    data = request.get_json()
    sd_jwt_presentation = data.get("sd_jwt_presentation")
    
    if not sd_jwt_presentation:
        return jsonify({"error": "Missing 'sd_jwt_presentation' in request body"}), 400
    
    verifier = SDJWTVerifier(sd_jwt_presentation, cb_get_issuer_key=get_issuer_key)
    verified = verifier.get_verified_payload()

    print(verified)
    
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=True, port=5001)
