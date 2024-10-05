from flask import Blueprint, request, jsonify
from app.services.traffic_service import TrafficService
from app.utils.encryption import Encryption

bp = Blueprint('traffic', __name__)
traffic_service = TrafficService()
encryption = Encryption()

@bp.route("/analyze_traffic", methods=["POST"])
def analyze():
    encrypted_data = request.get_json()['data']
    decrypted_data = encryption.decrypt_message(encrypted_data)
    result = traffic_service.analyze_traffic(decrypted_data)
    encrypted_result = encryption.encrypt_message(str(result))
    return jsonify({"result": encrypted_result})