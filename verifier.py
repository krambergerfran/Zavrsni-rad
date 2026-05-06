import os
import json
import ssl
import secrets
import time
from pathlib import Path
from jwcrypto import jwk
from flask import Flask, jsonify, request
import requests
from sd_jwt.verifier import SDJWTVerifier

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"
ISSUER_PUBLIC_KEY_PATH = Path(
    os.getenv("ISSUER_PUBLIC_KEY_PATH", str(BASE_DIR / "issuer_public_key.jwk.json"))
)
VERIFIER_BASE_URL = "https://localhost:5001"
VERIFIER_POLICIES = {
    "age": {"required_claims": ["is_over_18"]},
    "basic": {"required_claims": ["name", "last_name", "is_over_18"]},
    "strict": {"required_claims": ["name", "last_name", "is_over_18", "nationality"]},
}
# spremnik nonce-a za povezivanje prezentacije i verifiera
ACTIVE_CHALLENGES = {}

# bolje odrzavanje sustava - ako se presretne nonce ne moze se zauvijek koristiti, cisti memoriju
CHALLENGE_TTL_SECONDS = 60

# izbrisi challenge holdera (nonceve) kojima je istekao TTL
def cleanup_expired_challenges(now=None):
    now = now or time.time()
    expired_nonces = [
        nonce
        for nonce, challenge in ACTIVE_CHALLENGES.items()
        if challenge["expires_at"] < now
    ]
    for nonce in expired_nonces:
        ACTIVE_CHALLENGES.pop(nonce, None)

# ucitaj javni kljuc issuera
def load_issuer_public_key():
    if not ISSUER_PUBLIC_KEY_PATH.exists():
        raise RuntimeError(
            f"Issuer public key file not found: {ISSUER_PUBLIC_KEY_PATH}. "
            "-- Prvo treba pokrenuti issuer.py da se kljuc generira --"
        )
    with open(ISSUER_PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
        key_payload = json.load(f)
    return jwk.JWK(**key_payload)


ISSUER_PUBLIC_KEY = load_issuer_public_key()


# dohvati kljuc issuera bez pristupanja njemu
def get_issuer_key(issuer, header):
    return ISSUER_PUBLIC_KEY

def verify_kb_and_presentation(sd_jwt_presentation, verifier_id, nonce):
    # ocitsti challenge
    cleanup_expired_challenges()

    # provjera postojanosti verifiera
    if verifier_id not in VERIFIER_POLICIES:
        return jsonify({"error": f"Unknown verifier profile '{verifier_id}'"}), 400

    # dohvati podatak o prezentaciji na temelju noncea koji pruza i potrosi nonce
    challenge = ACTIVE_CHALLENGES.pop(nonce, None)
    if not challenge:
        return jsonify({"status": "failed", "reason": "invalid_or_used_nonce"}), 400

    # provjeri je li nonce istekao
    if challenge["expires_at"] < time.time():
        return jsonify({"status": "failed", "reason": "expired_nonce"}), 400

    # ako nonce ne odgovara verifieru koji ga je izdao
    if challenge["verifier_profile"] != verifier_id:
        return jsonify({"status": "failed", "reason": "nonce_profile_mismatch"}), 400

    verifier = SDJWTVerifier(
        sd_jwt_presentation,
        cb_get_issuer_key=get_issuer_key,
        expected_aud=challenge["aud"],
        expected_nonce=nonce,
    )

    try:
        verified = verifier.get_verified_payload()
    except Exception as exc:
        return jsonify({"status": "failed", "error": str(exc)}), 400

    # provjeri jesu li zadovoljeni svi nuzni claimovi
    required_claims = VERIFIER_POLICIES[verifier_id]["required_claims"]
    missing_claims = [claim for claim in required_claims if claim not in verified]

    # ako nedostaje neki nuzni claim
    if missing_claims:
        return (
            jsonify(
                {
                    "status": "failed",
                    "reason": "missing_required_claims",
                    "missing_claims": missing_claims,
                    "verifier_profile": verifier_id,
                }
            ),
            400,
        )

    if verifier_id == "age" and verified.get("is_over_18") is not True:
        return (
            jsonify(
                {
                    "status": "failed",
                    "reason": "invalid_claim_value",
                    "claim": "is_over_18",
                    "expected": True,
                    "actual": verified.get("is_over_18"),
                    "verifier_profile": verifier_id,
                }
            ),
            400,
        )

    # sve je zadovoljeno
    return jsonify(
        {
            "status": "ok",
            "verifier_profile": verifier_id,
            "verified_claims": list(verified.keys()),
            "key_binding": "verified",
        }
    )


# napravi nonce i audience za verifiera da se poveze s prezentacijom
@app.route("/challenge/<verifier_id>", methods=["GET"])
def issue_challenge(verifier_id):
    # ocisti challenge
    cleanup_expired_challenges()

    if verifier_id not in VERIFIER_POLICIES:
        return jsonify({"error": f"Unknown verifier profile '{verifier_id}'"}), 400

    # stvori nonce i aud, upisi u listu holder challengea, daj mu TTL
    nonce = secrets.token_urlsafe(18)
    aud = f"{VERIFIER_BASE_URL}/verify_sd-jwt/{verifier_id}"
    ACTIVE_CHALLENGES[nonce] = {
        "verifier_profile": verifier_id,
        "aud": aud,
        "expires_at": time.time() + CHALLENGE_TTL_SECONDS,
    }

    return jsonify({"nonce": nonce, "aud": aud, "verifier_profile": verifier_id})

# preusmjeravanje na verifikaciju s basic verifierom
@app.route("/verify_sd-jwt", methods=["POST"])
def verify_sd_jwt_default():
    data = request.get_json()
    sd_jwt_presentation = data.get("sd_jwt_presentation")
    nonce = data.get("nonce")

    if not sd_jwt_presentation:
        return jsonify({"error": "Missing 'sd_jwt_presentation' in request body"}), 400
    if not nonce:
        return jsonify({"error": "Missing 'nonce' in request body"}), 400

    return verify_kb_and_presentation(sd_jwt_presentation, "basic", nonce)

# preusmjeravanje na verifikaciju sa zadanim verifierom
@app.route("/verify_sd-jwt/<verifier_id>", methods=["POST"])
def verify_sd_jwt(verifier_id):
    data = request.get_json()
    sd_jwt_presentation = data.get("sd_jwt_presentation")
    nonce = data.get("nonce")

    if not sd_jwt_presentation:
        return jsonify({"error": "Missing 'sd_jwt_presentation' in request body"}), 400
    if not nonce:
        return jsonify({"error": "Missing 'nonce' in request body"}), 400

    return verify_kb_and_presentation(sd_jwt_presentation, verifier_id, nonce)

# implementacija mTLSa 
def create_ssl_context():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        certfile=str(CERTS_DIR / "verifier.crt"),
        keyfile=str(CERTS_DIR / "verifier.key"),
    )
    context.load_verify_locations(cafile=str(CERTS_DIR / "ca.crt"))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


if __name__ == "__main__":
    app.run(debug=True, port=5001, ssl_context=create_ssl_context())
