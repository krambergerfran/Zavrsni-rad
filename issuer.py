import time
import ssl
import json
import base64
from pathlib import Path
from flask import Flask, jsonify, request
from jwcrypto.jwk import JWK
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.common import SDObj
from pybulletproofs import zkrp_prove

app = Flask(__name__)

# korisnici ako dataset datoteka nije dostupna
DEFAULT_USERS = {
    "fran": {
        "name": "Fran",
        "last_name": "Kramberger",
        "nationality": "Croatia",
        "age": 22,
    },
    "ana": {
        "name": "Ana",
        "last_name": "Horvat",
        "nationality": "Croatia",
        "age": 16,
    },
}
BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"
DATASET_USERS_PATH = BASE_DIR / "data" / "users.json"
ISSUER_PRIVATE_KEY_PATH = BASE_DIR / "issuer_private_key.jwk.json"
ISSUER_PUBLIC_KEY_PATH = BASE_DIR / "issuer_public_key.jwk.json"

# stvori ili ucitaj issuer kljuceve
def load_or_create_issuer_keys():
    if ISSUER_PRIVATE_KEY_PATH.exists():
        with open(ISSUER_PRIVATE_KEY_PATH, "r", encoding="utf-8") as f:
            private_jwk = json.load(f)
        issuer_key_obj = JWK(**private_jwk)
    else:
        issuer_key_obj = JWK.generate(kty="EC", crv="P-256")
        with open(ISSUER_PRIVATE_KEY_PATH, "w", encoding="utf-8") as f:
            json.dump(issuer_key_obj.export_private(as_dict=True), f, indent=2)

    issuer_public_key_obj = JWK.from_json(issuer_key_obj.export_public())
    with open(ISSUER_PUBLIC_KEY_PATH, "w", encoding="utf-8") as f:
        json.dump(issuer_public_key_obj.export_public(as_dict=True), f, indent=2)
    return issuer_key_obj, issuer_public_key_obj


def load_users_dataset():
    if DATASET_USERS_PATH.exists():
        with open(DATASET_USERS_PATH, "r", encoding="utf-8") as f:
            users = json.load(f)
        if isinstance(users, dict) and users:
            return users
    return DEFAULT_USERS


USERS = load_users_dataset()

issuer_key, issuer_public_key = load_or_create_issuer_keys()


# funkcija za pretvorbu godina u bulletproofs oblik
# - issuer generira proof i commitment zajedno
def make_commitment_for_age(user_id):
    user = USERS[user_id]
    user_age = user["age"]
    if user_age < 18:
        # maloljetni korisnik nema valjan 18+ proof
        return None, None

    age_minus_threshold = user_age - 18
    result = zkrp_prove(age_minus_threshold, 32)
    # zkrp_prove vraća (proof, commitment, blinding_factor)
    if len(result) >= 2:
        proof, commitment = result[0], result[1]
    else:
        raise ValueError(f"zkrp_prove returned unexpected format: {result}")
    
    proof_bytes = bytes(proof)
    commitment_bytes = bytes(commitment)
    
    encoded_proof = base64.b64encode(proof_bytes).decode('utf-8')
    encoded_commitment = base64.b64encode(commitment_bytes).decode('utf-8')
    return encoded_proof, encoded_commitment

# napravi set claimova za issue
def build_claims(user_id, age_proof=None, age_commitment=None):
    user = USERS[user_id]
    now = int(time.time())
    claims = {
        "iss": "https://localhost:5000",
        "iat": now,
        "exp": now + 3600,
        "sub": user_id,
        "name": user["name"],
        "last_name": user["last_name"],
        SDObj("nationality"): user["nationality"],
    }
    # proof nije sd
    if age_proof is not None:
        claims["age_proof"] = age_proof
    # commitment je sd
    if age_commitment is not None:
        claims[SDObj("age")] = age_commitment
    return claims

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

        # napravi commitment godina za usera (bulletproofs dio)
        encoded_proof, encoded_commitment = make_commitment_for_age(user_id)
        user_claims = build_claims(user_id, age_proof=encoded_proof, age_commitment=encoded_commitment)

        # svaki izdani token povezi s holderovim kljucem
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