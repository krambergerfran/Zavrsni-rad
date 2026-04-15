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
TEST_CASES_PATH = BASE_DIR / "data" / "test_cases.json"
TLS_VERIFY = str(CERTS_DIR / "ca.crt")
CLIENT_CERT = (str(CERTS_DIR / "holder.crt"), str(CERTS_DIR / "holder.key"))


def issue_tokens(user_id="fran", count=1):
    # za svaki token holder generira zaseban par kljuceva.
    holder_signing_keys = []
    holder_public_keys = []

    for _ in range(count):
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
    sd_jwts = response.json().get("sd_jwts", [])

	# broj izdanih tokena mora odgovarati broju kljuceva
    if len(sd_jwts) != len(holder_signing_keys):
        raise ValueError("Issuer returned unexpected token count")

    return [
        {"sd_jwt": sd_jwt, "holder_key": holder_key}
        for sd_jwt, holder_key in zip(sd_jwts, holder_signing_keys)
    ]

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

# vrati ocekivani status za verifiera
def expected_for_verifier(expected_status, verifier_id):
	# ako je status broj, samo je jedan verifier
	if isinstance(expected_status, int):
		return expected_status
	# status je dict za vise verifiera
	if isinstance(expected_status, dict):
		return expected_status.get(verifier_id)
	

# pokretanje jednog test casea
def run_single_case(case):
	# dohvacanje podataka za taj test case
	case_name = case.get("name", "unnamed_case")
	user_id = case.get("user_id", "fran")
	disclosure_map = case.get("disclosure_map")
	verifier_profiles = case.get("verifier_profiles", ["basic", "strict"])
	expected_status = case.get("expected_status") # izlazni status (200 ili 400)

	# ucitaj tokene za usera
	token_pool = issue_tokens(user_id, len(verifier_profiles))

	print("\nCase: " + case_name)

	for verifier_id in verifier_profiles:
		# dohvati credential i napravi holdera s njim
		credential = token_pool.pop(0)
		holder = SDJWTHolder(credential["sd_jwt"])
		holder_signing_key = credential["holder_key"]

		# dohvati sazeti zapis jedinstvenosti tokena
		token_fp, key_fp = credential_fingerprint(credential["sd_jwt"], holder_signing_key)

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

		# status i rezultat verifikacije
		status_code, payload = verify_presentation(output, verifier_id, nonce)

		# dohvati ocekivan status testa
		expected = expected_for_verifier(expected_status, verifier_id)

		if status_code == expected:
			match = True
		else:
			match = False


		# ispis podataka o testu
		print("  verifier = " + verifier_id)
		print("  token_fp = " + token_fp)
		print("  key_fp  = " + key_fp)
		print("  expected status = " + str(expected))
		print("  status code = " + str(status_code))
		print("  response = " + str(payload))
		print("")


# pokusaj ucitati test caseve
def load_test_cases():
	if not TEST_CASES_PATH.exists():
		return []

	with open(TEST_CASES_PATH, "r", encoding="utf-8") as f:
		cases = json.load(f)

	return cases

# pokretanje svih test caseva iz zadane datoteke
def run_test_cases(cases):
	print("Running " + str(len(cases)) + " test case(s) from " + str(TEST_CASES_PATH))
	for case in cases:
		run_single_case(case)


# default demonstracija - ako ne postoje test casevi
def run_demo(user_id="fran"):
	default_cases = [
		{
			"name": "demo_without_nationality",
			"user_id": user_id,
			"disclosure_map": {
				"name": True,
				"last_name": True,
				"is_over_18": True,
			},
			"verifier_profiles": ["basic", "strict"],
		},
		{
			"name": "demo_with_nationality",
			"user_id": user_id,
			"disclosure_map": {
				"name": True,
				"last_name": True,
				"is_over_18": True,
				"nationality": True,
			},
			"verifier_profiles": ["basic", "strict"],
		},
	]
	run_test_cases(default_cases)


if __name__ == "__main__":
	cases = load_test_cases()
	if cases:
		run_test_cases(cases)
	else:
		run_demo("fran")
