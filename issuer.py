import json
from flask import Flask, jsonify, request
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.utils.demo_utils import get_jwk
from sd_jwt.common import SDObj

app = Flask(__name__)

user_claims = {
    "name": "Fran",
    "last_name": "Kramberger",
    SDObj("nationality"): "Croatia",
    "is_over_18": True,
}

params = {"key_size": 256, "kty": "EC"}

keys = get_jwk(jwk_kwargs=params)
issuer_key = keys["issuer_key"]

issuer = SDJWTIssuer(user_claims, issuer_key, sign_alg="ES256")
issuance = issuer.sd_jwt_issuance

@app.route("/issue_sd-jwt", methods=["POST"])
def issue_sd_jwt():
    return jsonify({"sd_jwt": issuance})

@app.route("/issuer_key", methods=["GET"])
def get_issuer_key():
    return jsonify(issuer_key)

if __name__ == "__main__":
    app.run(debug=True)