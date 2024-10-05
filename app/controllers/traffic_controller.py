from flask import Blueprint, request, jsonify
from app.services.traffic_service import TrafficService
from app.utils.encryption import Encryption

bp = Blueprint('traffic', __name__)

encryption = Encryption("your_secret_key_here")  # Passe a chave correta
traffic_service = TrafficService()

@bp.route("/analyze_traffic", methods=["POST"])
def analyze():
    data = request.get_json()
    result = traffic_service.analyze_traffic(data)
    return jsonify(result)
