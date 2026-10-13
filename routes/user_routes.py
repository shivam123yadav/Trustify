from flask import Blueprint, request, jsonify, session, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database.db_connection import db
from bson import ObjectId
from datetime import datetime
import os
import secrets

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

user_bp = Blueprint("user_bp", __name__)

users_collection = db["users"]
records_collection = db["records"]

@user_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "No data provided"}), 400

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    contact = data.get("contact", "")

    if not all([name, email, password]):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        if users_collection.find_one({"email": email}):
            return jsonify({"error": "Email already exists"}), 400

        hashed_password = generate_password_hash(password)
        new_user = {"name": name, "email": email, "password": hashed_password, "contact": contact}
        users_collection.insert_one(new_user)
    except Exception as e:
        current_app.logger.error(f"Database error during registration: {e}")
        return jsonify({"error": "Database service unavailable. Please try again later."}), 503

    return jsonify({"message": "User registered successfully"}), 201


@user_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "No data provided"}), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Invalid email or password"}), 401

    try:
        user = users_collection.find_one({"email": email})
    except Exception as e:
        current_app.logger.error(f"Database error during login: {e}")
        return jsonify({"error": "Database service unavailable. Please try again later."}), 503

    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    if not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid email or password"}), 401

    session.clear()
    session["user_id"] = str(user["_id"])
    session["user_email"] = user["email"]
    session["_csrf_token"] = secrets.token_hex(32)

    return jsonify({"message": "Login successful"}), 200



@user_bp.route("/profile_data", methods=["GET"])
def profile_data():
    if "user_id" not in session:
        return jsonify({"error": "Login required"}), 401

    try:
        user = users_collection.find_one({"_id": ObjectId(session["user_id"])})
        if not user:
            return jsonify({"error": "User not found"}), 404

        raw_records = list(records_collection.find({"user_id": session["user_id"]}))
    except Exception as e:
        current_app.logger.error(f"Database error during profile fetch: {e}")
        return jsonify({"error": "Database service unavailable. Please try again later."}), 503

    history = []
    for r in raw_records:
        status = None
        if isinstance(r.get("status"), str) and r.get("status").strip():
            status = r.get("status")
        elif isinstance(r.get("result"), str) and r.get("result").strip():
            status = r.get("result")
        else:
            text = " ".join(str(v) for v in (r.get("input"), r.get("filename"), r.get("result")) if v)
            t = text.lower()
            if "secure" in t:
                status = "Secure"
            elif "phish" in t or "phishing" in t:
                status = "Phishing"
            else:
                status = "Unknown"

        created_at = None
        if "created_at" in r and isinstance(r["created_at"], datetime):
            created_at = r["created_at"].isoformat()
        else:
            if isinstance(r.get("_id"), ObjectId):
                created_at = r["_id"].generation_time.isoformat()
            else:
                created_at = None

        input_val = r.get("input") or r.get("filename") or r.get("url") or "-"

        history.append({
            "_id": str(r.get("_id")),
            "type": r.get("type", "-"),
            "input": input_val,
            "status": status,
            "created_at": created_at
        })

    return jsonify({
        "user": {
            "name": user.get("name"),
            "email": user.get("email"),
            "photo": user.get("photo") or "/static/user_images/default-avatar.png"
        },
        "history": history
    }), 200


@user_bp.route("/upload_profile", methods=["POST"])
def upload_profile():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    if "profileImage" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["profileImage"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    ext = file.filename.rsplit('.', 1)[1].lower()
    # Prevent collisions, overwrites across users, and path traversal
    safe_filename = f"{session['user_id']}_{secrets.token_hex(8)}.{ext}"
    upload_folder = current_app.config.get("UPLOAD_FOLDER", os.path.join("static", "profile_images"))
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder, exist_ok=True)

    save_path = os.path.join(upload_folder, safe_filename)
    try:
        file.save(save_path)
    except Exception as e:
        return jsonify({"error": f"Failed to save file: {str(e)}"}), 500

    image_url = f"/static/profile_images/{safe_filename}"

    try:
        users_collection.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": {"photo": image_url}}
        )
    except Exception as e:
        current_app.logger.error(f"Database error during profile photo update: {e}")
        return jsonify({"error": "Saved file but DB update failed: database unavailable"}), 500

    return jsonify({"message": "Profile image uploaded successfully", "image_url": image_url}), 200




@user_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    session["_csrf_token"] = secrets.token_hex(32)
    return jsonify({"message": "Logged out successfully"}), 200

@user_bp.route("/check_session", methods=["GET"])
def check_session():
    if "user_id" in session:
        return jsonify({"logged_in": True, "email": session["user_email"]}), 200
    return jsonify({"logged_in": False}), 200
