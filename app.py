from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
import os
import google.generativeai as genai
import PyPDF2
from bson import ObjectId
from database.db_connection import users_collection, records_collection
from datetime import datetime
from werkzeug.utils import secure_filename

 
app = Flask(__name__)

CORS(app, supports_credentials=True)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_secret_key")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False

UPLOAD_FOLDER = os.path.join('static', 'profile_images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


from routes.user_routes import user_bp


load_dotenv()


app.register_blueprint(user_bp, url_prefix="/api/user")


API_KEY = os.getenv("GOOGLE_API_KEY")
if not API_KEY:
    raise RuntimeError("GOOGLE_API_KEY not found. Add it to .env file.")

genai.configure(api_key=API_KEY)
MODEL_NAME = "models/gemini-flash-latest"

def get_model():
    return genai.GenerativeModel(MODEL_NAME)


def predict_fake_or_real_email_content(text):
    prompt = f"""
You are an expert in identifying scam messages in text, email, or attachments. 

Task:
1. If the text contains URLs, analyze each one for malicious intent 
   (phishing, fraud, suspicious domains, security-check lookalikes).
2. Classify the whole content as:
   - Real/Legitimate (Authentic, safe message)
   - Scam/Fake (Phishing, fraud, or suspicious message)

Text to analyze:
{text}

Return a clear classification message:
- If scam/fake → explain briefly why (e.g., phishing URL, suspicious domain, fraudulent language).
- If real → state that it is legitimate.
"""
    try:
        model = get_model()
        response = model.generate_content(prompt)
        return response.text.strip() if response and getattr(response, "text", None) else "Classification failed or empty response."
    except Exception as e:
        return f"Error during classification: {str(e)}"

#Url detection prompt
def url_detection(url):
    prompt = f"""
You are an advanced AI model specializing in URL security classification. Classify the given URL as one of:
secure, phishing, malware, defacement

Input URL: {url}

Return only one word in lowercase: secure, phishing, malware, or defacement.
"""
    try:
        model = get_model()
        response = model.generate_content(prompt)
        return response.text.strip().lower() if response and getattr(response, "text", None) else "detection_failed"
    except Exception as e:
        return f"error: {str(e)}"

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/dashboard')
def dashboard():
    
    if "user_id" not in session:
        return render_template("login.html", message="Please log in first.")
    return render_template("dashboard.html")

@app.route('/profile')
def profile():
    if "user_id" not in session:
        return render_template("login.html", message="Please log in first.")

    user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
    if not user:
        return render_template("dashboard.html", message="User not found.")


    records = list(records_collection.find({"user_id": session["user_id"]}))
    total_checks = len(records)
    secure_count = sum(1 for r in records if "secure" in str(r.get("result", "")).lower())
    phishing_count = total_checks - secure_count

    return render_template(
        "profile.html",
        user=user,
        records=records,
        total_checks=total_checks,
        secure_count=secure_count,
        phishing_count=phishing_count
    )
    
@app.route('/scam/', methods=['POST']) 
def detect_scam():
    if 'file' not in request.files:
        return render_template("dashboard.html", message="No file uploaded.")

    file = request.files['file']
    if file.filename == "":
        return render_template("dashboard.html", message="No file selected.")

    filename = file.filename.lower()
    extracted_text = ""

    try:
        if filename.endswith(".pdf"):
            pdf_reader = PyPDF2.PdfReader(file)
            extracted_text = " ".join([page.extract_text() or "" for page in pdf_reader.pages])
        elif filename.endswith(".txt"):
            extracted_text = file.read().decode("utf-8", errors="ignore")
        else:
            return render_template("dashboard.html", message="Invalid file type. Please upload a PDF or TXT file.")
    except Exception as e:
        return render_template("dashboard.html", message=f"Failed to read file: {str(e)}")

    if not extracted_text.strip():
        return render_template("dashboard.html", message="File is empty or text could not be extracted.")


    message = predict_fake_or_real_email_content(extracted_text)

    if "user_id" in session:
        record = {
            "user_id": session["user_id"],
            "type": "file",
            "filename": file.filename,
            "status": message.capitalize() if isinstance(message, str) else "Unknown",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        records_collection.insert_one(record)

    return render_template("dashboard.html", message=message)

@app.route("/predict", methods=["POST"])
def predict_url():
    url = request.form.get("url", "").strip()

    if not url:
        return render_template("dashboard.html", message="Please enter a URL.")

    if not url.startswith(("http://", "https://")):
        return render_template("dashboard.html", message="Invalid URL format. Include http:// or https://", input_url=url)

    classification_result = url_detection(url)
    classification = classification_result.get("result", "Unknown") if isinstance(classification_result, dict) else classification_result

    if "user_id" in session:
        record = {
            "user_id": session["user_id"],
            "type": "url",
            "input": url,
            "status": classification.capitalize() if isinstance(classification, str) else "Unknown",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        records_collection.insert_one(record)

    return render_template("dashboard.html", input_url=url, predicted_class=classification)


if __name__ == '__main__':
    app.run(debug=True)
