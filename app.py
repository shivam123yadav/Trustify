from flask import Flask, render_template, request, jsonify, session
import importlib
from dotenv import load_dotenv
import os
import secrets
import hmac
import google.generativeai as genai
from google.api_core import exceptions as google_exceptions
import PyPDF2
from bson import ObjectId
from database.db_connection import users_collection, records_collection, rate_limits_collection
from datetime import datetime, timezone
import time
from pymongo import ReturnDocument
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException

# Ensure environment variables are loaded prior to configuration
load_dotenv()

flask_cors_spec = importlib.util.find_spec("flask_cors")
if flask_cors_spec is not None:
    flask_cors = importlib.import_module("flask_cors")
    CORS = flask_cors.CORS
else:
    def CORS(app, supports_credentials=False):
        return None

 
app = Flask(__name__)

# Determine deployment environment
is_production = os.getenv("FLASK_ENV", "").lower() == "production" or os.getenv("ENV", "").lower() == "production"

# Enforce production debug settings during app initialization before WSGI serves requests
if is_production:
    app.debug = False
    app.config["DEBUG"] = False
else:
    dev_debug = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    app.debug = dev_debug
    app.config["DEBUG"] = dev_debug

# Secret Key Configuration: Enforce strong secret in production
flask_secret_key = os.getenv("FLASK_SECRET_KEY")
if is_production:
    if not flask_secret_key or flask_secret_key == "dev_secret_key":
        raise RuntimeError("FLASK_SECRET_KEY must be set to a secure, random value in production mode.")
    app.secret_key = flask_secret_key
else:
    app.secret_key = flask_secret_key or "dev_secret_key"

# Session Cookie Security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True if is_production else (os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true")

# Maximum upload limit: 10 MB
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

CORS(app, supports_credentials=True)

UPLOAD_FOLDER = os.path.join('static', 'profile_images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ----------------- Rate Limiting (Multi-worker & In-Memory Fallback) -----------------
def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

_in_memory_rate_limits = {}

def check_rate_limit(identifier, limit=10, window_seconds=60):
    """
    Multi-worker rate limiter backed by MongoDB atomic increment.
    Falls back gracefully to an in-memory sliding window if MongoDB is unavailable.
    Returns True if allowed, False if exceeded.
    """
    window = int(time.time() // window_seconds)
    doc_id = f"{identifier}:{window}"

    if rate_limits_collection is not None:
        try:
            res = rate_limits_collection.find_one_and_update(
                {"_id": doc_id},
                {
                    "$inc": {"count": 1},
                    "$setOnInsert": {"created_at": datetime.now(timezone.utc)}
                },
                upsert=True,
                return_document=ReturnDocument.AFTER
            )
            if res and res.get("count", 1) > limit:
                return False
            return True
        except Exception:
            pass  # Fall back to in-memory tracking

    # In-memory fallback
    now = time.time()
    cutoff = now - window_seconds
    timestamps = _in_memory_rate_limits.setdefault(identifier, [])
    _in_memory_rate_limits[identifier] = [t for t in timestamps if t > cutoff]
    if len(_in_memory_rate_limits[identifier]) >= limit:
        return False
    _in_memory_rate_limits[identifier].append(now)
    return True

# ----------------- CSRF Protection -----------------
def get_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=get_csrf_token)

@app.after_request
def set_csrf_cookie(response):
    if "_csrf_token" in session:
        response.set_cookie(
            "XSRF-TOKEN",
            session["_csrf_token"],
            samesite="Lax",
            secure=app.config.get("SESSION_COOKIE_SECURE", False),
            httponly=False
        )
    return response

@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        token = request.form.get("csrf_token")
        if not token:
            token = (
                request.headers.get("X-CSRFToken")
                or request.headers.get("X-CSRF-Token")
                or request.headers.get("X-XSRF-TOKEN")
            )
        if not token and request.is_json:
            json_data = request.get_json(silent=True)
            if isinstance(json_data, dict):
                token = json_data.get("csrf_token")

        expected = session.get("_csrf_token")
        if not expected or not token or not hmac.compare_digest(str(token), str(expected)):
            if request.path.startswith("/api/"):
                return jsonify({"error": "CSRF validation failed. Token missing or invalid."}), 400
            return render_template(
                "dashboard.html",
                message="CSRF validation failed. Please refresh the page and try again.",
                url_error="CSRF validation failed. Please refresh the page and try again."
            ), 400

@app.errorhandler(413)
def request_entity_too_large(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Uploaded file exceeds the maximum allowed limit of 10 MB."}), 413
    return render_template(
        "dashboard.html",
        message="Uploaded file is too large. The maximum allowed limit is 10 MB."
    ), 413

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/") or request.is_json:
        return jsonify({"error": "Resource not found."}), 404
    return render_template("dashboard.html", message="Page not found."), 404

@app.errorhandler(405)
def method_not_allowed(error):
    if request.path.startswith("/api/") or request.is_json:
        return jsonify({"error": "Method not allowed."}), 405
    return render_template("dashboard.html", message="Method not allowed."), 405

@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error(f"Internal server error (500) on {request.path}: {error}")
    if request.path.startswith("/api/") or request.is_json:
        return jsonify({"error": "Internal server error. Please try again later."}), 500
    return render_template(
        "dashboard.html",
        message="An unexpected server error occurred. Please try again later."
    ), 500

@app.errorhandler(Exception)
def handle_unexpected_exception(e):
    if isinstance(e, HTTPException):
        if request.path.startswith("/api/") or request.is_json:
            return jsonify({"error": e.description}), e.code
        return e
    app.logger.error(f"Unhandled exception on {request.path}: {e}", exc_info=True)
    if request.path.startswith("/api/") or request.is_json:
        return jsonify({"error": "Internal server error. Please try again later."}), 500
    return render_template(
        "dashboard.html",
        message="An unexpected server error occurred. Please try again later."
    ), 500

from routes.user_routes import user_bp
app.register_blueprint(user_bp, url_prefix="/api/user")


API_KEY = os.getenv("GOOGLE_API_KEY")
if not API_KEY:
    raise RuntimeError("GOOGLE_API_KEY not found. Add it to .env file.")

genai.configure(api_key=API_KEY)
MODEL_NAME = os.getenv("GEMINI_MODEL", "models/gemini-flash-latest")

def get_model():
    model_name = os.getenv("GEMINI_MODEL", MODEL_NAME)
    return genai.GenerativeModel(model_name)


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
        response = model.generate_content(
            prompt,
            request_options={"retry": None, "timeout": 20}
        )
        if not response or not getattr(response, "text", None):
            return {
                "error": "empty_response",
                "message": "Classification failed or empty response from AI model."
            }
        return {"result": response.text.strip()}
    except (google_exceptions.ResourceExhausted, google_exceptions.TooManyRequests):
        return {
            "error": "quota_exceeded",
            "message": "Classification is temporarily unavailable because the AI quota is exhausted. Please try again later."
        }
    except google_exceptions.DeadlineExceeded:
        return {
            "error": "timeout",
            "message": "Classification request timed out. Please try again."
        }
    except Exception as e:
        err_msg = str(e).lower()
        if "429" in err_msg or "quota" in err_msg or "resource_exhausted" in err_msg or "resource has been exhausted" in err_msg:
            return {
                "error": "quota_exceeded",
                "message": "Classification is temporarily unavailable because the AI quota is exhausted. Please try again later."
            }
        return {
            "error": "api_error",
            "message": f"Error during classification: {str(e)}"
        }

# Url detection prompt
def url_detection(url):
    prompt = f"""
You are an advanced AI model specializing in URL security classification. Classify the given URL as one of:
secure, phishing, malware, defacement

Input URL: {url}

Return only one word in lowercase: secure, phishing, malware, or defacement.
"""
    try:
        model = get_model()
        # Disable automatic retry loop and set 15s timeout to avoid hanging indefinitely
        response = model.generate_content(
            prompt,
            request_options={"retry": None, "timeout": 15}
        )
        if not response or not getattr(response, "text", None):
            return {"error": "empty_response", "message": "Classification failed or empty response from AI model."}

        raw_text = response.text.strip().lower()
        valid_classes = ["secure", "phishing", "malware", "defacement"]
        for cls in valid_classes:
            if cls in raw_text:
                return {"result": cls}

        return {"result": "unknown"}

    except (google_exceptions.ResourceExhausted, google_exceptions.TooManyRequests):
        return {
            "error": "quota_exceeded",
            "message": "Classification is temporarily unavailable because the AI quota is exhausted. Please try again later."
        }
    except google_exceptions.DeadlineExceeded:
        return {
            "error": "timeout",
            "message": "Classification request timed out. Please try again."
        }
    except Exception as e:
        err_msg = str(e).lower()
        if "429" in err_msg or "quota" in err_msg or "resource_exhausted" in err_msg or "resource has been exhausted" in err_msg:
            return {
                "error": "quota_exceeded",
                "message": "Classification is temporarily unavailable because the AI quota is exhausted. Please try again later."
            }
        return {
            "error": "api_error",
            "message": f"Classification error: {str(e)}"
        }

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
    if "user_id" not in session:
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({"error": "Login required"}), 401
        return render_template("login.html", message="Please log in first to use threat detection.")

    # Rate limiting (per-user: 10/min, per-IP: 15/min)
    user_id = session["user_id"]
    client_ip = get_client_ip()
    if not check_rate_limit(f"user:{user_id}", limit=10) or not check_rate_limit(f"ip:{client_ip}", limit=15):
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({"error": "Rate limit exceeded. Please wait a moment before trying again."}), 429
        return render_template("dashboard.html", message="Rate limit exceeded. You can perform up to 10 scans per minute. Please try again shortly."), 429

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


    classification_result = predict_fake_or_real_email_content(extracted_text)

    # Check if classification returned a handled error (such as quota exceeded, timeout, AI error)
    if isinstance(classification_result, dict) and "error" in classification_result:
        error_message = classification_result.get("message", "Classification failed.")
        return render_template("dashboard.html", message=error_message)

    message = classification_result.get("result", "") if isinstance(classification_result, dict) else str(classification_result).strip()

    # Reject unexpected or empty classification without creating scan-history record
    if not message or message.lower() in ("unknown", "classification failed or empty response.", ""):
        return render_template("dashboard.html", message="Could not determine threat classification for this file.")

    record = {
        "user_id": session["user_id"],
        "type": "file",
        "filename": file.filename,
        "status": message.capitalize(),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    records_collection.insert_one(record)

    return render_template("dashboard.html", message=message)

@app.route("/predict", methods=["POST"])
def predict_url():
    if "user_id" not in session:
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({"error": "Login required"}), 401
        return render_template("login.html", message="Please log in first to use threat detection.")

    url = request.form.get("url", "").strip()

    # Rate limiting (per-user: 10/min, per-IP: 15/min)
    user_id = session["user_id"]
    client_ip = get_client_ip()
    if not check_rate_limit(f"user:{user_id}", limit=10) or not check_rate_limit(f"ip:{client_ip}", limit=15):
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({"error": "Rate limit exceeded. Please wait a moment before trying again."}), 429
        return render_template(
            "dashboard.html",
            url_error="Rate limit exceeded. You can perform up to 10 scans per minute. Please try again shortly.",
            input_url=url
        ), 429

    if not url:
        return render_template("dashboard.html", url_error="Please enter a URL.", input_url="")

    if not url.startswith(("http://", "https://")):
        return render_template("dashboard.html", url_error="Invalid URL format. Include http:// or https://", input_url=url)

    classification_result = url_detection(url)

    # Check if classification returned a handled error (such as quota exceeded)
    if isinstance(classification_result, dict) and "error" in classification_result:
        error_message = classification_result.get("message", "Classification failed.")
        return render_template(
            "dashboard.html",
            input_url=url,
            url_error=error_message
        )

    classification = classification_result.get("result", "unknown") if isinstance(classification_result, dict) else str(classification_result).strip().lower()

    # Reject unexpected or empty classification without creating scan-history record
    if classification in ("unknown", ""):
        return render_template(
            "dashboard.html",
            input_url=url,
            url_error="Could not determine threat classification for this URL."
        )

    record = {
        "user_id": session["user_id"],
        "type": "url",
        "input": url,
        "status": classification.capitalize(),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    records_collection.insert_one(record)

    return render_template("dashboard.html", input_url=url, predicted_class=classification)


if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "127.0.0.1" if app.debug else "0.0.0.0")
    app.run(host=host, port=port, debug=app.debug)
