
from database.db_connection import db
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

users_col = db["users"]

def register_user(name, email, password):
    """Register a new user"""
    if users_col.find_one({"email": email}):
        return {"error": "Email already exists"}
    hashed_pw = generate_password_hash(password)
    users_col.insert_one({"name": name, "email": email, "password": hashed_pw})
    return {"success": True}

def login_user(email, password):
    """Verify user credentials"""
    user = users_col.find_one({"email": email})
    if not user:
        return {"error": "Invalid email or password"}
    if not check_password_hash(user["password"], password):
        return {"error": "Invalid email or password"}
    return {"success": True, "user": {"id": str(user["_id"]), "name": user["name"], "email": user["email"]}}

def get_all_users():
    """Return all registered users"""
    return list(users_col.find())
