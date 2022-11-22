from flask import Flask, request, jsonify, make_response
from ca import RootCA, InterCA

root = RootCA("root")
ica = InterCA(root, "ica")
eca = InterCA(root, "eca")

app = Flask(__name__)

@app.route('ica/verify_signature', methods=['GET'])
def verify_signature():
    if valid_request():
        req = request.json()
        response = jsonify({
            'verified': ica.verifySignature(
                certificate=req['certificate']
            )
        })
        return make_response(response, 200)
    else:
        response = jsonify({
            'message': "Bad request"
        })
        response.status_code = 400
        return response

@app.route('eca/verify_signature', methods=['GET'])
def verify_signature():
    if valid_request():
        req = request.json()
        response = jsonify({
            'verified': eca.verifySignature(
                certificate=req['certificate']
            )
        })
        return make_response(response, 200)
    else:
        response = jsonify({
            'message': "Bad request"
        })
        response.status_code = 400
        return response

@app.route('get_certificates_by_serial_numbers', methods=['GET'])
def get_certificates_by_serial_numbers():
    if valid_request():
        req = request.json()
        response = jsonify({
            'certificates': eca.getCertificatesBySerialNumbers(
                numbers=req['numbers']
            )
        })
        return make_response(response, 200)
    else:
        response = jsonify({
            'message': "Bad request"
        })
        response.status_code = 400
        return response

@app.route('create_certificate', method=['POST'])
def create_certificate():
    if valid_request():
        req = request.json()
        response = jsonify({
            'status': eca.createCertificate(
                firstName=req['firstName'],
                lastName=req['lastName'],
                email=req['email'],
                uid=req['uid']
            )
        })
        return make_response(response, 200)
    else:
        response = jsonify({
            'message': "Bad request"
        })
        response.status_code = 400
        return response

@app.route('revoke_certificate', method=['POST'])
def revoke_cert():
    if valid_request():
        req = request.json()
        response = jsonify({
            'status': eca.revokeCertificate(
                serialNumber=req['serialNumber']
            )
        })
        return make_response(response, 200)
    else:
        response = jsonify({
            'message': "Bad request"
        })
        response.status_code = 400
        return response

@app.route('adminInfo', method=['GET'])
def admin_info():
    if valid_request():
        req = request.json()
        response = jsonify({
            'status': eca.currentState()
        })
        return make_response(response, 200)
    else:
        response = jsonify({
            'message': "Bad request"
        })
        response.status_code = 400
        return response

def valid_request() -> bool:
    if request.json:
        if 'uid' in request.json:
            return True
    return False

@app.errorhandler(404)
def request_not_found(e):
    response = jsonify({
        'status': f"Resource {e} not found"
    })
    response.status_code = 400
    return response