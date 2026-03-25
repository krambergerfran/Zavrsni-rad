import json
import base64
from flask import Flask, jsonify, request
import requests
from sd_jwt.holder import SDJWTHolder


app = Flask(__name__)

resp = requests.post("http://localhost:5000/issue_sd-jwt")
sd_jwt = resp.json()["sd_jwt"]
holder = SDJWTHolder(sd_jwt)

holder.create_presentation({"name": True, "last_name": True, "is_over_18": True})

output = holder.sd_jwt_presentation

print(" sd-jwt presentation 1: ")
print(output)

request_data = {"sd_jwt_presentation": output}
verification_response = requests.post("http://localhost:5001/verify_sd-jwt", json=request_data)

print("\n verification response: ")
print(verification_response.json()["status"])

print("\n ---------")

holder.create_presentation({"name": True, "last_name": True, "is_over_18": True, "nationality": True})
output = holder.sd_jwt_presentation

print("\n sd-jwt presentation 2: ")
print(output)

request_data = {"sd_jwt_presentation": output}
verification_response = requests.post("http://localhost:5001/verify_sd-jwt", json=request_data)

print(" verification response: ")
print(verification_response.json()["status"])
