from flask import Blueprint, request, jsonify, render_template, send_file
from app.services.traffic_service import TrafficService
from app.utils.encryption import Encryption
import logging
import json
import io

bp = Blueprint('traffic', __name__)

encryption = Encryption("your_secret_key_here")
traffic_service = TrafficService()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@bp.route("/upload_page", methods=["GET"])
def upload_page():
    return render_template('upload.html')

@bp.route("/analyze_traffic", methods=["POST"])
def analyze():
    data = request.get_json()
    result = traffic_service.analyze_traffic(data)
    report = generate_report(result)
    return jsonify(result)

@bp.route("/upload_traffic", methods=["POST"])
def upload_traffic():
    logger.info("Recebendo arquivo para análise de tráfego")
    if 'file' not in request.files:
        logger.error("Nenhum arquivo encontrado na requisição")
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        logger.error("Nenhum arquivo selecionado")
        return jsonify({"error": "No selected file"}), 400
    if not file.filename.endswith(('.csv', '.json')):
        logger.error("Tipo de arquivo inválido")
        return jsonify({"error": "Invalid file type. Only CSV and JSON are allowed."}), 400
    file_content = file.read()
    try:
        result = traffic_service.analyze_traffic(file_content)
        logger.info("Resultado da análise: %s", result)
        report = generate_report(result)
        return jsonify(result), report
    except ValueError as e:
        logger.error("Erro ao processar o arquivo: %s", str(e))
        return jsonify({"error": str(e)}), 400

def generate_report(result):
    report = {
        "analysis": result,
        "details": "Análise completa dos dados enviados."
    }
    return json.dumps(report, indent=4)
