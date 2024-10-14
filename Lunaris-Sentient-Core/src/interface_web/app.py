import os
import sys
from flask import Flask, request, render_template, Response, stream_with_context, send_from_directory
from werkzeug.utils import secure_filename
import json
from keras.models import load_model

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from malware_analysis.analyzer import analyze_malware

app = Flask(__name__, template_folder='templates')

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create the uploads directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        def generate():
            yield json.dumps({"type": "progress", "percentage": 0, "message": "Starting analysis..."}) + '\n'
            
            for progress in analyze_malware(file_path):
                if isinstance(progress, tuple):
                    percentage, message = progress
                    yield json.dumps({"type": "progress", "percentage": percentage, "message": message}) + '\n'
                else:
                    yield json.dumps({"type": "result", "message": progress}) + '\n'
            
            yield json.dumps({"type": "progress", "percentage": 100, "message": "Analysis completed"}) + '\n'
        
        return Response(stream_with_context(generate()), content_type='application/json')

@app.route('/templates/<path:filename>')
def serve_template_files(filename):
    return send_from_directory(app.template_folder, filename)

if __name__ == '__main__':
    app.run(debug=True)