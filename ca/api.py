from flask import Flask, request, jsonify, make_response
from ca import CA
import base64 
ca = CA()

app = Flask(__name__)


@app.route("/ica/verify_signature", methods=["POST"])
def verify_signature_ica():
    if valid_request():
        req = request.json()
        response = jsonify(
            {"verified": ca.verifySignature(certificate=req["certificate"])}
        )
        return make_response(response, 200)
    else:
        response = jsonify({"message": "Bad request"})
        response.status_code = 400
        return response


@app.route("/eca/verify_signature", methods=["POST"])
def verify_signature_eca():
    if valid_request():
        request.form
        challenge = request.form.get("challenge")
        signature = request.form.get("signature")
        serial = request.form.get("serial")
        response = jsonify(
            {"verified": ca.verifySignature(challenge, signature, serial)}
        )
        return make_response(response, 200)
    else:
        response = jsonify({"message": "Bad request"})
        response.status_code = 400
        return response


@app.route("/get_certificates_by_serial_numbers", methods=["POST"])
def get_certificates_by_serial_numbers():
    if valid_request():
        numbers = request.form.getlist("numbers")
        if not numbers:
            response = jsonify({"certificates": None})
            response.status_code = 200
            return response
        response = jsonify(
            {"certificates": ca.getCertificatesBySerialNumbers(numbers=numbers)}
        )
        return make_response(response, 200)
    else:
        response = jsonify({"message": "Bad request"})
        response.status_code = 400
        return response


@app.route("/create_certificate", methods=["POST"])
def create_certificate():
    if valid_request():
        req = request.form
        data, serial = ca.create_certificate(
            firstName=req["firstName"],
            lastName=req["lastName"],
            email=req["email"],
            uid=req["uid"],
        )
        response = jsonify({"status": {"data": data.hex(), "serial": serial}})
        return make_response(response, 200)
    else:
        response = jsonify({"message": "Bad request"})
        response.status_code = 400
        return response


@app.route("/revoke_certificate", methods=["POST"])
def revoke_cert():
    if valid_request():
        serial = request.form.get("serialNumber")
        response = jsonify(
            {"status": ca.revoke_certificate(serial)}
        )
        return make_response(response, 200)
    else:
        response = jsonify({"message": "Bad request"})
        response.status_code = 400
        return response


@app.route("/adminInfo", methods=["POST"])
def admin_info():
    if valid_request():
        response = jsonify({"status": ca.adminInfo()})
        return make_response(response, 200)
    else:
        response = jsonify({"message": "Bad request"})
        response.status_code = 400
        return response


def valid_request() -> bool:
    return True


@app.errorhandler(404)
def request_not_found(e):
    response = jsonify({"status": f"Resource {e} not found"})
    response.status_code = 400
    return response


if __name__ == "__main__":
    app.run(host="10.0.99.50")
