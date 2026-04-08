import requests
import hashlib
import json
from pathlib import Path
from jwcrypto.jwk import JWK
from sd_jwt.holder import SDJWTHolder

ISSUER_URL = "https://localhost:5000"
VERIFIER_URL = "https://localhost:5001"
BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"
TLS_VERIFY = str(CERTS_DIR / "ca.crt")
CLIENT_CERT = (str(CERTS_DIR / "holder.crt"), str(CERTS_DIR / "holder.key"))


def issue_tokens(user_id="fran", count=1):  # default vrijednosti
	# za svaki token holder generira zaseban par kljuceva
	holder_signing_keys = []
	holder_public_keys = []

	for i in range(count):
		signing_key = JWK.generate(kty="EC", crv="P-256")
		holder_signing_keys.append(signing_key)
		holder_public_keys.append(signing_key.export_public(as_dict=True))

	# batch issuance - issuer veze svaki token na odgovarajuci javni kljuc
	response = requests.post(
		f"{ISSUER_URL}/issue_sd-jwt",
		json={
			"user_id": user_id,
			"holder_public_keys": holder_public_keys,
		},
		timeout=5,
		verify=TLS_VERIFY,
		cert=CLIENT_CERT,
	)
	# provjera je li uspjelo - ako server javi gresku, baci exception
	response.raise_for_status()
	sd_jwts = response.json().get("sd_jwts", [])

	# broj izdanih tokena mora odgovarati broju kljuceva
	if len(sd_jwts) != len(holder_signing_keys):
		raise ValueError("Issuer returned unexpected token count")

	result = []
	for sd_jwt, holder_key in zip(sd_jwts, holder_signing_keys):
		result.append({"sd_jwt": sd_jwt, "holder_key": holder_key})
	return result

# skraceni dokaz o jedinstvenosti tokena
# hashirani sd-jwt i holderov kljuc se pretvaraju u "fingerprint"
def credential_fingerprint(sd_jwt, holder_key):
	token_fp = hashlib.sha256(sd_jwt.encode("utf-8")).hexdigest()[:12]
	holder_pub = holder_key.export_public(as_dict=True)
	key_fp = hashlib.sha256(json.dumps(holder_pub, sort_keys=True).encode("utf-8")).hexdigest()[:12]
	return token_fp, key_fp


def get_verifier_challenge(verifier_id):
	# verifier daje nonce i audience za key-binding provjeru
	response = requests.get(
		f"{VERIFIER_URL}/challenge/{verifier_id}",
		timeout=5,
		verify=TLS_VERIFY,
		cert=CLIENT_CERT,
	)
	# provjera je li uspjelo - ako server javi gresku, baci exception
	response.raise_for_status()
	return response.json()


def verify_presentation(sd_jwt_presentation, verifier_id, nonce):
	request_data = {"sd_jwt_presentation": sd_jwt_presentation, "nonce": nonce}
	response = requests.post(
		f"{VERIFIER_URL}/verify_sd-jwt/{verifier_id}",
		json=request_data,
		timeout=5,
		verify=TLS_VERIFY,
		cert=CLIENT_CERT,
	)
	return response.status_code, response.json()

# demonstracija prezentacija
def run_demo(user_id="fran"):

    # lista prezentacija i podataka koje otkrivaju
	presentations = {
		"without nationality": {
			"name": True,
			"last_name": True,
			"is_over_18": True,
		},
		"with nationality": {
			"name": True,
			"last_name": True,
			"is_over_18": True,
			"nationality": True,
		},
	}

	verifier_profiles = ["basic", "strict"]
	# trazi onoliko tokena koliko radis prezentacija
	required_token_count = len(presentations) * len(verifier_profiles)
	token_pool = issue_tokens(user_id, required_token_count)

	print(f"Prepared {len(token_pool)} one-time credentials for user={user_id}")
	previous_token_fp = None
	previous_key_fp = None

	for label, disclosure_map in presentations.items():
		print(f"\nPresentation: {label}")

		for verifier_id in verifier_profiles:
			if not token_pool:
				token_pool.extend(issue_tokens(user_id, 2))

            # dohvati token
			credential = token_pool.pop(0)
			holder = SDJWTHolder(credential["sd_jwt"])
			holder_signing_key = credential["holder_key"]

            # izvadi "fingerprint" tokena
			token_fp, key_fp = credential_fingerprint(
				credential["sd_jwt"], holder_signing_key
			)
			
            # zastavica za indikator novosti tokena
			token_changed = token_fp != previous_token_fp
			key_changed = key_fp != previous_key_fp


			challenge = get_verifier_challenge(verifier_id)
			nonce = challenge["nonce"]
			aud = challenge["aud"]

			holder.create_presentation(
				disclosure_map,
				nonce=nonce,
				aud=aud,
				holder_key=holder_signing_key,
				sign_alg="ES256",
			)
			output = holder.sd_jwt_presentation

			status_code, payload = verify_presentation(output, verifier_id, nonce)

            # ispis podataka o prezentaciji
			print(f"  verifier = {verifier_id}")
			print(f"  token_fp = {token_fp} (new = {token_changed})")
			print(f"  key_fp   = {key_fp} (new = {key_changed})")
			print(f"  status code = {status_code}")
			print(f"  response = {payload}")
			print("")

			previous_token_fp = token_fp
			previous_key_fp = key_fp


if __name__ == "__main__":
	run_demo("fran")
