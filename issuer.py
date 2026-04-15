import time
import ssl
import json
from pathlib import Path
from flask import Flask, jsonify, request
from jwcrypto.jwk import JWK
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.utils.demo_utils import get_jwk
from sd_jwt.common import SDObj

app = Flask(__name__)

# korisnici ako dataset datoteka nije dostupna
DEFAULT_USERS = {
    "fran": {
        "name": "Fran",
        "last_name": "Kramberger",
        "nationality": "Croatia",
        "is_over_18": True,
    },
    "ana": {
        "name": "Ana",
        "last_name": "Horvat",
        "nationality": "Croatia",
        "is_over_18": False,
    },
}

params = {"key_size": 256, "kty": "EC"}

keys = get_jwk(jwk_kwargs=params)
issuer_key = keys["issuer_key"]
issuer_public_key = keys["issuer_public_key"]
BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"
DATASET_USERS_PATH = BASE_DIR / "data" / "users.json"
ISSUER_PUBLIC_KEY_PATH = BASE_DIR / "issuer_public_key.jwk.json"


def load_users_dataset():
    if DATASET_USERS_PATH.exists():
        with open(DATASET_USERS_PATH, "r", encoding="utf-8") as f:
            users = json.load(f)
        if isinstance(users, dict) and users:
            return users
    return DEFAULT_USERS


USERS = load_users_dataset()


# zapisi javni kljuc u datoteku
def persist_issuer_public_key():
    public_jwk = issuer_public_key.export_public(as_dict=True)
    with open(ISSUER_PUBLIC_KEY_PATH, "w", encoding="utf-8") as f:
        json.dump(public_jwk, f, indent=2)


persist_issuer_public_key()


# napravi set claimova za issue
def build_claims(user_id):
    user = USERS[user_id]
    now = int(time.time())
    return {
        "iss": "https://localhost:5000",
        "iat": now,
        "exp": now + 3600,
        "sub": user_id,
        "name": user["name"],
        "last_name": user["last_name"],
        SDObj("nationality"): user["nationality"],
        SDObj("is_over_18"): user["is_over_18"],
    }

@app.route("/issue_sd-jwt", methods=["POST"])
def issue_sd_jwt():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id", "fran")
    holder_public_key = data.get("holder_public_key")
    holder_public_keys = data.get("holder_public_keys")

    if user_id not in USERS:
        return jsonify({"error": f"Unknown user_id '{user_id}'"}), 400

    # podrzava izdavanje jednog ili vise tokena
    if holder_public_keys is None:
        holder_public_keys = [holder_public_key] if holder_public_key else []

    if not holder_public_keys:
        return jsonify({"error": "Missing 'holder_public_key' or 'holder_public_keys' in request body"}), 400

    if not isinstance(holder_public_keys, list):
        return jsonify({"error": "'holder_public_keys' must be a list of JWK objects"}), 400

    issued_sd_jwts = []
    for public_key in holder_public_keys:
        try:
            holder_key = JWK.from_json(json.dumps(public_key))
        except Exception:
            return jsonify({"error": "Invalid holder public key JWK format in batch"}), 400

        # svaki izdani token povezi s holderovim kljucem
        user_claims = build_claims(user_id)
        issuance = SDJWTIssuer(
            user_claims,
            issuer_key,
            holder_key=holder_key,
            sign_alg="ES256",
        ).sd_jwt_issuance
        issued_sd_jwts.append(issuance)

    return jsonify(
        {
            "sd_jwts": issued_sd_jwts,
            "sd_jwt": issued_sd_jwts[0],
            "issued_count": len(issued_sd_jwts),
            "user_id": user_id,
        }
    )


@app.route("/users", methods=["GET"])
def list_users():
    return jsonify({"users": list(USERS.keys())})


# implementacija mTLSa 
def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        certfile=str(CERTS_DIR / "issuer.crt"),
        keyfile=str(CERTS_DIR / "issuer.key"),
    )
    context.load_verify_locations(cafile=str(CERTS_DIR / "ca.crt"))
    context.verify_mode = ssl.CERT_REQUIRED
    return context

if __name__ == "__main__":
    app.run(debug=True, ssl_context=create_ssl_context())