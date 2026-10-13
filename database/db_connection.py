from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

# Prioritize MONGODB_URI, falling back to MONGO_URI, then localhost default
mongo_uri = (
    os.getenv("MONGODB_URI")
    or os.getenv("MONGO_URI")
    or "mongodb://localhost:27017/"
)

# Initialize MongoClient with a 5-second server selection timeout
client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)

# Explicitly select the trustify database
db = client["trustify"]

users_collection = db["users"]
records_collection = db["records"]
rate_limits_collection = db["rate_limits"]
